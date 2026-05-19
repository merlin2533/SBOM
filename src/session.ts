import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import pino from 'pino';
import type { Response } from 'express';
import type {
  ServerConfig,
  Session,
  Job,
  SessionSnapshot,
  JobSnapshot,
  SessionState,
} from './types';
import { detectPhase } from './step-detector';
import { shredUnlink } from './shred';

async function rmrf(dir: string): Promise<void> {
  if (!dir) return;
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (_) {
    // best-effort
  }
}

export class SessionManager {
  private sessions = new Map<string, Session>();
  private config: ServerConfig;
  private logger: pino.Logger;

  constructor(config: ServerConfig, logger: pino.Logger) {
    this.config = config;
    this.logger = logger;
  }

  // --------------------------------------------------------------------------
  // Lifecycle
  // --------------------------------------------------------------------------

  create(): Session {
    const sid = crypto.randomBytes(16).toString('hex');
    const dir = path.join(this.config.scratchDir, sid);
    fs.mkdirSync(path.join(dir, 'upload'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(dir, 'jobs'), { recursive: true, mode: 0o700 });

    const sess: Session = {
      sid,
      dir,
      jobs: [],
      currentJobIdx: null,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      sseClients: new Set<Response>(),
      outputWatcher: null,
      pendingUploadId: null,
      pendingUploadPath: null,
      pendingUploadName: null,
      pendingUploadSize: null,
    };
    this.sessions.set(sid, sess);
    this.logger.debug({ sid }, 'session created');
    return sess;
  }

  get(sid?: string): Session | undefined {
    if (!sid) return undefined;
    return this.sessions.get(sid);
  }

  async destroy(sid: string): Promise<void> {
    const sess = this.sessions.get(sid);
    if (!sess) return;
    this.sessions.delete(sid);

    // Notify SSE subscribers that this session is gone.
    for (const client of sess.sseClients) {
      try {
        client.write('event: closed\ndata: {}\n\n');
        client.end();
      } catch (_) {
        // client may already be gone
      }
    }
    sess.sseClients.clear();

    // Kill running job child process.
    const runningJob = this.runningJob(sess);
    if (runningJob?.child && runningJob.state === 'running') {
      try {
        runningJob.child.kill('SIGTERM');
      } catch (_) {}
    }

    // Close file watcher.
    if (sess.outputWatcher) {
      try {
        sess.outputWatcher.close();
      } catch (_) {}
      sess.outputWatcher = null;
    }

    // Shred password files for all jobs.
    for (const job of sess.jobs) {
      if (job.passwordFile) {
        await shredUnlink(job.passwordFile);
        job.passwordFile = null;
      }
    }

    await rmrf(sess.dir);
    this.logger.debug({ sid }, 'session destroyed');
  }

  // --------------------------------------------------------------------------
  // Snapshot
  // --------------------------------------------------------------------------

  snapshot(sess: Session): SessionSnapshot {
    let state: SessionState = 'idle';
    const currentJob =
      sess.currentJobIdx !== null ? sess.jobs[sess.currentJobIdx] : undefined;
    if (currentJob) {
      state = currentJob.state;
    }

    const pendingUpload =
      sess.pendingUploadId && sess.pendingUploadName && sess.pendingUploadSize != null
        ? {
            id: sess.pendingUploadId,
            name: sess.pendingUploadName,
            size: sess.pendingUploadSize,
          }
        : null;

    const jobs: JobSnapshot[] = sess.jobs.map((j) => ({
      id: j.id,
      state: j.state,
      command: j.command,
      args: j.argsDisplay,
      pid: j.pid,
      inputName: j.inputName,
      inputSize: j.inputSize,
      passwordCount: j.passwordCount,
      passwordTransport: j.passwordTransport,
      createdAt: j.createdAt,
      startedAt: j.startedAt,
      finishedAt: j.finishedAt,
      exitCode: j.exitCode,
      signal: j.signal,
      error: j.error,
      outputs: j.outputs,
      phase: j.phase,
      progress: j.progress,
      sandbox: j.sandbox,
    }));

    return {
      sessionId: sess.sid,
      sessionStartedAt: sess.createdAt,
      state,
      currentJobId: currentJob?.id ?? null,
      pendingUpload,
      jobs,
    };
  }

  // --------------------------------------------------------------------------
  // SSE / messaging
  // --------------------------------------------------------------------------

  broadcast(sess: Session, event: string, data: unknown): void {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sess.sseClients) {
      try {
        client.write(payload);
      } catch (_) {
        // client disconnected
      }
    }
  }

  pushLog(
    sess: Session,
    job: Job,
    stream: 'stdout' | 'stderr',
    line: string
  ): void {
    const entry = { t: Date.now(), stream, line };
    job.log.push(entry);
    // Ring-buffer: trim oldest entries when over the cap.
    if (job.log.length > this.config.maxLogLines) {
      job.log.splice(0, job.log.length - this.config.maxLogLines);
    }
    this.broadcast(sess, 'log', { jobId: job.id, entry });

    // Phase detection — only upgrade, never downgrade.
    const hit = detectPhase(line, job.progress);
    if (hit !== null) {
      job.phase = hit.phase;
      job.progress = hit.progress;
      this.broadcast(sess, 'phase', {
        jobId: job.id,
        phase: job.phase,
        progress: job.progress,
      });
    }
  }

  async refreshOutputs(sess: Session, job: Job): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(job.outDir, { withFileTypes: true });
    } catch {
      return;
    }
    const files: { name: string; size: number; mtime: number }[] = [];
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      try {
        const st = await fsp.stat(path.join(job.outDir, ent.name));
        files.push({ name: ent.name, size: st.size, mtime: st.mtimeMs });
      } catch (_) {}
    }
    files.sort((a, b) => a.name.localeCompare(b.name));
    if (JSON.stringify(job.outputs) !== JSON.stringify(files)) {
      job.outputs = files;
      this.broadcast(sess, 'outputs', { jobId: job.id, files });
    }
  }

  touch(sess: Session): void {
    sess.lastActivity = Date.now();
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  runningJob(sess: Session): Job | undefined {
    if (sess.currentJobIdx === null) return undefined;
    return sess.jobs[sess.currentJobIdx];
  }

  /** Iterate all sessions — returns a snapshot-safe array copy. */
  iterate(): Session[] {
    return [...this.sessions.values()];
  }

  /**
   * Start the idle-session garbage collector. Returns a teardown function.
   * Sessions with no active job and no live SSE subscribers are destroyed
   * after `idleMs` milliseconds of inactivity.
   */
  startIdleGc(idleMs: number): () => void {
    const timer = setInterval(() => {
      const now = Date.now();
      for (const sess of this.sessions.values()) {
        const running = this.runningJob(sess);
        if (running && running.state === 'running') continue;
        if (sess.sseClients.size > 0) continue;
        if (now - sess.lastActivity > idleMs) {
          this.destroy(sess.sid).catch(() => {});
        }
      }
    }, 60_000);
    timer.unref();
    return () => clearInterval(timer);
  }
}
