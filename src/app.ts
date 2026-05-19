import path from 'path';
import fsp from 'fs/promises';
import fs from 'fs';
import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import pino from 'pino';
import { marked } from 'marked';
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

// Markdown renderer: GitHub-flavoured, line breaks honoured, no smartypants
// surprises. marked.parse is synchronous in default mode.
marked.setOptions({ gfm: true, breaks: false });

// Escape user-provided strings for safe inclusion in HTML.
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]!
  );
}

// Standalone HTML viewer for SBOM/report files. Inlines our colour palette
// so it renders nicely even when opened in a fresh tab.
function renderViewerPage(opts: {
  title: string;
  bodyHtml: string;
  downloadUrl: string;
  rawName: string;
}): string {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(opts.title)} — SBOM-Extraktor</title>
<style>
:root{color-scheme:light dark;
--bg:#f6f7fb;--card:#fff;--fg:#0e1320;--muted:#6a7184;--border:#e3e7f1;
--accent:#002b7f;--accent-2:#1a4fb0;--accent-soft:#e6ecf6;
--code-bg:#0a0c14;--code-fg:#d4dbe6;}
@media (prefers-color-scheme:dark){:root{
--bg:#07090f;--card:#10131c;--fg:#ecf0f6;--muted:#8a93a8;--border:#232a3a;
--accent:#6c8dd9;--accent-2:#8aa9ea;--accent-soft:#0e1a35;}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem 4rem;background:var(--bg);color:var(--fg);
font-family:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
line-height:1.6;font-size:15px;-webkit-font-smoothing:antialiased}
main{max-width:980px;margin:0 auto;background:var(--card);border:1px solid var(--border);
border-radius:16px;padding:2rem 2.2rem;box-shadow:0 6px 24px rgba(0,43,127,.08)}
header.viewer{display:flex;justify-content:space-between;align-items:center;gap:1rem;
padding-bottom:1rem;margin-bottom:1.4rem;border-bottom:1px solid var(--border);flex-wrap:wrap}
.viewer-title{font-size:.78rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:.5rem}
.viewer-title::before{content:"";width:4px;height:14px;border-radius:2px;background:linear-gradient(180deg,var(--accent),var(--accent-2))}
.viewer-name{font-family:ui-monospace,Menlo,monospace;font-size:.9rem;color:var(--fg)}
.viewer-actions{display:flex;gap:.5rem;flex-wrap:wrap}
.viewer-actions a{text-decoration:none;font-weight:600;padding:.5rem .85rem;border-radius:8px;font-size:.85rem;
border:1px solid var(--border);color:var(--accent);background:var(--card);transition:all .15s}
.viewer-actions a:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.viewer-actions a.secondary{color:var(--muted)}
.viewer-actions a.secondary:hover{background:var(--accent-soft);color:var(--accent);border-color:var(--accent)}
h1,h2,h3,h4{letter-spacing:-.01em;line-height:1.25;margin-top:1.6em}
h1{font-size:1.7rem;margin-top:0;color:var(--accent)}
h2{font-size:1.3rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}
h3{font-size:1.1rem}
p,ul,ol{margin:.7em 0}
a{color:var(--accent)}
ul,ol{padding-left:1.4rem}
li{margin:.2em 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em;background:var(--accent-soft);padding:.06em .35em;border-radius:4px;color:var(--accent)}
pre{background:var(--code-bg);color:var(--code-fg);padding:1rem 1.1rem;border-radius:10px;overflow:auto;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;line-height:1.55;border:1px solid var(--border)}
pre code{background:transparent;color:inherit;padding:0;font-size:inherit}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:.92em}
th,td{padding:.5rem .7rem;border:1px solid var(--border);text-align:left}
th{background:var(--accent-soft);color:var(--accent);font-weight:600}
tr:nth-child(even) td{background:rgba(0,43,127,.03)}
blockquote{border-left:3px solid var(--accent);padding-left:1rem;color:var(--muted);margin:.7em 0}
hr{border:none;border-top:1px solid var(--border);margin:2rem 0}
.json-pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.json-pre .k{color:#7aa9ff}.json-pre .s{color:#9be7a3}.json-pre .n{color:#f0c674}.json-pre .b{color:#f08080}
</style>
</head>
<body>
<main>
  <header class="viewer">
    <div>
      <div class="viewer-title">Bericht</div>
      <div class="viewer-name">${escapeHtml(opts.rawName)}</div>
    </div>
    <div class="viewer-actions">
      <a href="${opts.downloadUrl}" download="${escapeHtml(opts.rawName)}">Herunterladen</a>
      <a href="javascript:history.back()" class="secondary">Zurück</a>
    </div>
  </header>
  ${opts.bodyHtml}
</main>
</body>
</html>`;
}

// Syntax-highlight a JSON document. Tiny regex-based highlighter so we don't
// pull in another dependency just for one viewer page.
function highlightJson(json: string): string {
  return escapeHtml(json).replace(
    /("([^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d+)?([eE][+-]?\d+)?/g,
    (m, _str, _u, colon, bool) => {
      if (colon) return `<span class="k">${m}</span>`;
      if (bool) return `<span class="b">${m}</span>`;
      if (m.startsWith('"')) return `<span class="s">${m}</span>`;
      return `<span class="n">${m}</span>`;
    }
  );
}

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

  // --- GET /api/view/:jobId/:name ------------------------------------
  // Render Markdown / JSON / text output files as a styled HTML page so
  // the browser can display them without forcing a download. Anything we
  // don't recognise falls back to the download endpoint via 302.
  app.get(
    '/api/view/:jobId/:name',
    sameOriginOnly,
    async (req: Request, res: Response) => {
      const sess = requireSession(req, res);
      if (!sess) return;

      const jobId = req.params['jobId'];
      const job = sess.jobs.find((j) => j.id === jobId);
      if (!job) { res.status(404).send('Job not found.'); return; }
      if (job.state !== 'done' && job.state !== 'failed') {
        res.status(409).send('Job not finished.'); return;
      }

      const name = path.basename(req.params['name'] ?? '');
      const full = path.resolve(job.outDir, name);
      if (!full.startsWith(job.outDir + path.sep) && full !== job.outDir) {
        res.status(400).send('Bad path.'); return;
      }
      let buf: Buffer;
      try { buf = await fsp.readFile(full); }
      catch { res.status(404).send('Not found.'); return; }

      const downloadUrl = `/api/download/${encodeURIComponent(jobId!)}/${encodeURIComponent(name)}`;
      const lower = name.toLowerCase();
      let bodyHtml: string;

      if (lower.endsWith('.md') || lower.endsWith('.markdown')) {
        // Trusted source: extract-sbom's own audit report. marked renders to HTML.
        bodyHtml = marked.parse(buf.toString('utf8'), { async: false }) as string;
      } else if (lower.endsWith('.json')) {
        let text = buf.toString('utf8');
        try {
          text = JSON.stringify(JSON.parse(text), null, 2);
        } catch { /* leave as-is if it isn't valid JSON */ }
        bodyHtml = `<pre class="json-pre"><code>${highlightJson(text)}</code></pre>`;
      } else if (lower.endsWith('.txt') || lower.endsWith('.log')) {
        bodyHtml = `<pre><code>${escapeHtml(buf.toString('utf8'))}</code></pre>`;
      } else {
        // Binary or unknown: send the user to the download endpoint.
        res.redirect(302, downloadUrl);
        return;
      }

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store, private');
      res.send(renderViewerPage({
        title: name,
        bodyHtml,
        downloadUrl,
        rawName: name,
      }));
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
