import path from 'path';
import fsp from 'fs/promises';
import fs from 'fs';
import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import pino from 'pino';
import type { ServerConfig, SandboxKind } from './types';
import { SessionManager } from './session';
import { JobRunner } from './job';
import { createLogger, createHttpLogger } from './logger';
import { detectSandbox } from './sandbox';
import {
  securityHeaders,
  basicAuth,
  sameOriginOnly,
  rateLimitUpload,
} from './security';
import { createTusHandler } from './tus-handler';

async function rmrf(dir: string): Promise<void> {
  if (!dir) return;
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (_) {}
}

export interface AppResult {
  app: express.Application;
  sessions: SessionManager;
  jobs: JobRunner;
  logger: pino.Logger;
  sandboxKind: SandboxKind;
  drain: () => Promise<void>;
}

export function createApp(config: ServerConfig): AppResult {
  // ------------------------------------------------------------------
  // Infrastructure
  // ------------------------------------------------------------------

  const logger = createLogger(config);
  const sandboxKind = detectSandbox(config.sandboxMode, {
    warn: (msg) => logger.warn(msg),
  });
  logger.info({ sandbox: sandboxKind }, 'sandbox mode');

  const sessions = new SessionManager(config, logger);
  const jobs = new JobRunner(sessions, config, logger, sandboxKind);

  // Start idle session garbage collection.
  sessions.startIdleGc(config.sessionIdleMs);

  // ------------------------------------------------------------------
  // App + middleware
  // ------------------------------------------------------------------

  const app = express();
  if (config.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(createHttpLogger(config, logger));
  app.use(securityHeaders);
  app.use(cookieParser());

  if (config.authUser) {
    app.use(basicAuth(config));
  }

  // Static assets — served without body parsers, index: false so GET /
  // hits our route handler.
  app.use(
    express.static(path.join(__dirname, '..', 'public'), {
      index: false,
      setHeaders(res) {
        res.setHeader('Cache-Control', 'no-store, private');
      },
    })
  );

  // ------------------------------------------------------------------
  // Session helper used by route handlers and tus handler
  // ------------------------------------------------------------------

  function requireSession(req: Request, res: Response) {
    const sid = req.cookies?.['sid'] as string | undefined;
    const sess = sessions.get(sid);
    if (!sess) {
      res.status(440).json({ error: 'Session expired. Reload the page.' });
      return null;
    }
    sessions.touch(sess);
    return sess;
  }

  // ------------------------------------------------------------------
  // TUS resumable upload handler
  // ------------------------------------------------------------------

  const rateLimit = rateLimitUpload(config);

  const { middleware: tusMiddleware } = createTusHandler({
    scratchDir: config.scratchDir,
    maxUploadBytes: config.maxUploadBytes,
    getSession: (req: Request) => {
      const sid = req.cookies?.['sid'] as string | undefined;
      return sessions.get(sid);
    },
    onUploadFinished(sess, info) {
      // Store the pending upload info on the session so POST /api/jobs can
      // pick it up.
      sess.pendingUploadId = info.id;
      sess.pendingUploadPath = info.filePath;
      sess.pendingUploadName = info.name;
      sess.pendingUploadSize = info.size;
      sessions.touch(sess);
    },
    logger,
  });

  // Rate-limit only the POST (creation) — not HEAD/PATCH/DELETE.
  app.post('/api/tus', sameOriginOnly, rateLimit, tusMiddleware);
  app.use('/api/tus', tusMiddleware);

  // ------------------------------------------------------------------
  // JSON body parser — only for JSON endpoints, NOT tus paths
  // ------------------------------------------------------------------

  const jsonParser = express.json({ limit: '1mb' });

  // ------------------------------------------------------------------
  // Routes
  // ------------------------------------------------------------------

  // --- GET / — wipe previous session, create new, serve SPA -----------
  app.get('/', async (req: Request, res: Response) => {
    const prev = req.cookies?.['sid'] as string | undefined;
    if (prev) {
      await sessions.destroy(prev);
    }
    const sess = sessions.create();
    res.cookie('sid', sess.sid, {
      httpOnly: true,
      sameSite: 'strict',
      secure: !!req.secure,
      path: '/',
    });
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  });

  // --- GET /api/state --------------------------------------------------
  app.get('/api/state', sameOriginOnly, (req: Request, res: Response) => {
    const sess = requireSession(req, res);
    if (!sess) return;
    res.json(sessions.snapshot(sess));
  });

  // --- GET /api/events (SSE) ------------------------------------------
  app.get('/api/events', sameOriginOnly, (req: Request, res: Response) => {
    const sess = requireSession(req, res);
    if (!sess) return;

    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-store, private',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders();

    sess.sseClients.add(res);

    // Send current state snapshot immediately on connect.
    res.write(`event: state\ndata: ${JSON.stringify(sessions.snapshot(sess))}\n\n`);

    // If there is an active job with logs, replay them.
    const currentJob =
      sess.currentJobIdx !== null ? sess.jobs[sess.currentJobIdx] : undefined;
    if (currentJob && currentJob.log.length > 0) {
      res.write(
        `event: log-replay\ndata: ${JSON.stringify({ jobId: currentJob.id, log: currentJob.log })}\n\n`
      );
    }

    // Heartbeat every 15 seconds to keep the connection alive through proxies.
    const beat = setInterval(() => {
      try {
        res.write(': beat\n\n');
      } catch (_) {}
    }, 15_000);

    req.on('close', () => {
      clearInterval(beat);
      sess.sseClients.delete(res);
      sessions.touch(sess);
    });
  });

  // --- POST /api/jobs — start a new job from a pending upload ----------
  app.post(
    '/api/jobs',
    sameOriginOnly,
    jsonParser,
    async (req: Request, res: Response) => {
      if (draining) {
        res.status(503).json({ error: 'Server is shutting down.' });
        return;
      }
      const sess = requireSession(req, res);
      if (!sess) return;

      if (!sess.pendingUploadPath || !sess.pendingUploadName || sess.pendingUploadSize == null) {
        res.status(409).json({ error: 'No pending upload. Upload a file first.' });
        return;
      }

      // Parse passwords from request body.
      const rawPasswords: string = req.body?.passwords ?? '';
      const passwords = rawPasswords
        .split(/\r?\n/)
        .map((s: string) => s.replace(/\s+$/, ''))
        .filter((s: string) => s.length > 0 && !s.startsWith('#'));

      const uploadPath = sess.pendingUploadPath;
      const uploadName = sess.pendingUploadName;
      const uploadSize = sess.pendingUploadSize;

      // Clear pending upload fields before enqueue (enqueue may throw).
      sess.pendingUploadId = null;
      sess.pendingUploadPath = null;
      sess.pendingUploadName = null;
      sess.pendingUploadSize = null;

      const job = jobs.enqueue(sess, {
        uploadPath,
        uploadName,
        uploadSize,
        passwords,
      });

      res.json({ ok: true, jobId: job.id, snapshot: sessions.snapshot(sess) });
    }
  );

  // --- POST /api/cancel -----------------------------------------------
  app.post('/api/cancel', sameOriginOnly, jsonParser, (req: Request, res: Response) => {
    const sess = requireSession(req, res);
    if (!sess) return;
    const running = sessions.runningJob(sess);
    if (!running || running.state !== 'running') {
      res.status(409).json({ error: 'No job is running.' });
      return;
    }
    jobs.cancel(sess);
    res.json({ ok: true });
  });

  // --- GET /api/download/:jobId/:name ----------------------------------
  app.get(
    '/api/download/:jobId/:name',
    sameOriginOnly,
    async (req: Request, res: Response) => {
      const sess = requireSession(req, res);
      if (!sess) return;

      const jobId = req.params['jobId'];
      const job = sess.jobs.find((j) => j.id === jobId);
      if (!job) {
        res.status(404).json({ error: 'Job not found.' });
        return;
      }
      if (job.state !== 'done' && job.state !== 'failed') {
        res.status(409).json({ error: 'Job not finished.' });
        return;
      }

      const name = path.basename(req.params['name'] ?? '');
      const full = path.resolve(job.outDir, name);
      // Ensure the resolved path is inside the output directory.
      if (!full.startsWith(job.outDir + path.sep) && full !== job.outDir) {
        res.status(400).send('Bad path.');
        return;
      }
      try {
        await fsp.access(full, fs.constants.R_OK);
      } catch {
        res.status(404).send('Not found.');
        return;
      }
      res.setHeader('Cache-Control', 'no-store, private');
      res.download(full, name);
    }
  );

  // --- POST /api/reset ------------------------------------------------
  app.post(
    '/api/reset',
    sameOriginOnly,
    jsonParser,
    async (req: Request, res: Response) => {
      const sid = req.cookies?.['sid'] as string | undefined;
      if (sid) await sessions.destroy(sid);
      res.clearCookie('sid', { path: '/' });
      res.json({ ok: true });
    }
  );

  // --- GET /api/health ------------------------------------------------
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      sessions: sessions.iterate().length,
      sandbox: sandboxKind,
      bin: config.extractSbomBin,
    });
  });

  // ------------------------------------------------------------------
  // Graceful drain
  // ------------------------------------------------------------------

  let draining = false;

  async function drain(): Promise<void> {
    draining = true;
    logger.info('drain: waiting for in-flight jobs');

    // Collect all running child processes.
    const running = sessions
      .iterate()
      .map((sess) => sessions.runningJob(sess))
      .filter((j): j is NonNullable<typeof j> => j !== undefined && j.state === 'running');

    if (running.length > 0) {
      logger.info({ count: running.length }, 'drain: waiting for jobs to finish');
      const done = Promise.all(
        running.map(
          (job) =>
            new Promise<void>((resolve) => {
              if (!job.child) {
                resolve();
                return;
              }
              job.child.once('exit', () => resolve());
            })
        )
      );
      const timeout = new Promise<void>((resolve) =>
        setTimeout(resolve, config.shutdownGraceMs)
      );
      await Promise.race([done, timeout]);

      // Kill any processes that didn't exit within the grace period.
      for (const job of running) {
        if (job.state === 'running' && job.child) {
          logger.warn({ jobId: job.id }, 'drain: SIGKILL after timeout');
          try {
            job.child.kill('SIGKILL');
          } catch (_) {}
        }
      }
    }

    // Destroy all sessions (shreds passwords, cleans up dirs).
    const allSessions = sessions.iterate();
    await Promise.all(allSessions.map((s) => sessions.destroy(s.sid)));

    // Remove the entire scratch dir.
    await rmrf(config.scratchDir);

    logger.info('drain: complete');
  }

  return { app, sessions, jobs, logger, sandboxKind, drain };
}
