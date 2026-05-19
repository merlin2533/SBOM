import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import pino from 'pino';
import type { ServerConfig, Session, Job, SandboxKind } from './types';
import { SessionManager } from './session';
import { wrapCommand } from './sandbox';
import { shredUnlink } from './shred';

export interface EnqueueOpts {
  uploadPath: string;
  uploadName: string;
  uploadSize: number;
  passwords: string[];
}

export class JobRunner {
  constructor(
    private sessions: SessionManager,
    private config: ServerConfig,
    private logger: pino.Logger,
    private sandboxKind: SandboxKind
  ) {}

  enqueue(sess: Session, opts: EnqueueOpts): Job {
    const id = crypto.randomBytes(12).toString('hex');
    const outDir = path.join(sess.dir, 'jobs', id, 'out');
    fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

    const job: Job = {
      id,
      state: 'queued',
      command: this.config.extractSbomBin,
      args: [],
      argsDisplay: [],
      child: null,
      pid: null,
      exitCode: null,
      signal: null,
      error: null,
      startedAt: null,
      finishedAt: null,
      createdAt: Date.now(),
      inputName: opts.uploadName,
      inputSize: opts.uploadSize,
      uploadPath: opts.uploadPath,
      passwordCount: opts.passwords.length,
      passwordTransport: 'none',
      passwordFile: null,
      outDir,
      outputs: [],
      log: [],
      phase: null,
      progress: null,
      sandbox: this.sandboxKind,
    };

    // Stash plaintext passwords temporarily until the job is launched;
    // they are erased in preparePasswords().
    (job as JobWithPending)._pendingPasswords = opts.passwords;

    sess.jobs.push(job);

    this.logger.debug({ sid: sess.sid, jobId: id }, 'job enqueued');

    // Kick off the queue if nothing is currently running.
    const running = this.sessions.runningJob(sess);
    if (!running || running.state !== 'running') {
      this.runNext(sess);
    }

    return job;
  }

  // --------------------------------------------------------------------------
  // Private: job execution
  // --------------------------------------------------------------------------

  private async runNext(sess: Session): Promise<void> {
    const nextJob = sess.jobs.find((j) => j.state === 'queued');
    if (!nextJob) return;

    // Update currentJobIdx to point at the new active job.
    sess.currentJobIdx = sess.jobs.indexOf(nextJob);

    await this.launchJob(sess, nextJob);
  }

  private async launchJob(sess: Session, job: Job): Promise<void> {
    const { passwords } = await this.preparePasswords(sess, job);

    // Build args list.
    const args: string[] = ['--output-dir', job.outDir, ...this.config.extraArgs];
    if (job.passwordFile) {
      args.push('--password-file', job.passwordFile);
    }
    args.push(job.uploadPath);

    // Display args: replace scratch-dir prefix with basename so the client
    // never sees internal server paths.
    const argsDisplay = args.map((a) =>
      a.startsWith(sess.dir + path.sep) ? path.basename(a) : a
    );

    job.args = args;
    job.argsDisplay = argsDisplay;

    // Wrap for sandbox.
    // rw paths = session dir (contains upload, jobs subdir, password file).
    const wrapped = wrapCommand(this.sandboxKind, {
      command: job.command,
      args,
      rwPaths: [sess.dir],
    });

    // Build child process environment.
    const childEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) childEnv[k] = v;
    }
    if (passwords.length > 0 && job.passwordTransport === 'env') {
      childEnv['EXTRACT_SBOM_PASSWORDS'] = passwords.join(',');
    }

    let child;
    try {
      child = spawn(wrapped.command, wrapped.args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: childEnv,
      });
    } catch (e: unknown) {
      await shredUnlink(job.passwordFile);
      job.passwordFile = null;
      job.state = 'failed';
      job.error = e instanceof Error ? e.message : String(e);
      job.finishedAt = Date.now();
      this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));
      this.logger.error({ sid: sess.sid, jobId: job.id, err: e }, 'failed to spawn');
      return;
    }

    job.child = child;
    job.pid = child.pid ?? null;
    job.state = 'running';
    job.startedAt = Date.now();

    this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));
    this.logger.info(
      { sid: sess.sid, jobId: job.id, pid: job.pid, sandbox: this.sandboxKind },
      'job started'
    );

    // Wire stdout/stderr to the log ring buffer.
    readline
      .createInterface({ input: child.stdout! })
      .on('line', (line) => this.sessions.pushLog(sess, job, 'stdout', line));
    readline
      .createInterface({ input: child.stderr! })
      .on('line', (line) => this.sessions.pushLog(sess, job, 'stderr', line));

    // Watch output directory for new files.
    try {
      sess.outputWatcher = fs.watch(job.outDir, { persistent: false }, () => {
        this.sessions.refreshOutputs(sess, job).catch(() => {});
      });
    } catch (_) {
      // fs.watch may not be supported on all platforms — not fatal.
    }

    child.on('error', (e) => {
      job.error = e.message;
      this.sessions.pushLog(sess, job, 'stderr', `[spawn error] ${e.message}`);
      this.logger.error({ sid: sess.sid, jobId: job.id }, e.message);
    });

    child.on('close', async (code, signal) => {
      job.exitCode = code;
      job.signal = signal as NodeJS.Signals | null;
      job.finishedAt = Date.now();
      job.state = code === 0 ? 'done' : signal ? 'cancelled' : 'failed';

      if (sess.outputWatcher) {
        try {
          sess.outputWatcher.close();
        } catch (_) {}
        sess.outputWatcher = null;
      }

      // Shred password file and remove the upload artifact immediately.
      await shredUnlink(job.passwordFile);
      job.passwordFile = null;
      try {
        await fsp.unlink(job.uploadPath);
      } catch (_) {}

      await this.sessions.refreshOutputs(sess, job);
      this.sessions.touch(sess);
      this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));

      this.logger.info(
        { sid: sess.sid, jobId: job.id, code, signal, state: job.state },
        'job finished'
      );

      // Process next queued job, if any.
      this.runNext(sess);
    });
  }

  private async preparePasswords(
    sess: Session,
    job: Job
  ): Promise<{ passwords: string[] }> {
    // Passwords were already parsed into an array before enqueue; we stored
    // them temporarily on the job via a private trick — see enqueue().
    // Because Job doesn't carry the plaintext array past enqueue, we re-derive
    // from job.passwordCount to avoid storing them. BUT since we do need them
    // for transport selection we use the internal holder.
    // The actual passwords array is plumbed in via _pendingPasswords below.
    const passwords: string[] = (job as JobWithPending)._pendingPasswords ?? [];

    if (passwords.length === 0) {
      job.passwordTransport = 'none';
      return { passwords };
    }

    const hasComma = passwords.some((p) => p.includes(','));
    if (!hasComma) {
      job.passwordTransport = 'env';
    } else {
      const pwFile = path.join(sess.dir, `passwords-${job.id}.txt`);
      await fsp.writeFile(pwFile, passwords.join('\n') + '\n', { mode: 0o600 });
      job.passwordFile = pwFile;
      job.passwordTransport = 'file';
    }

    // Erase the in-memory plaintext copy as soon as it's no longer needed.
    delete (job as JobWithPending)._pendingPasswords;
    return { passwords };
  }

  // --------------------------------------------------------------------------
  // Cancel
  // --------------------------------------------------------------------------

  cancel(sess: Session): void {
    const job = this.sessions.runningJob(sess);
    if (!job || job.state !== 'running' || !job.child) return;
    try {
      job.child.kill('SIGTERM');
    } catch (_) {}
    const child = job.child;
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (_) {}
    }, 5000);
    // Don't keep Node alive just for the escalation timeout.
    if (t.unref) t.unref();
  }
}

// Internal helper type: jobs carry their plaintext password array only until
// the job is launched, at which point the field is deleted.
type JobWithPending = Job & { _pendingPasswords?: string[] };

