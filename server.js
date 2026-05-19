const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || String(5 * 1024 * 1024 * 1024), 10);
const EXTRACT_SBOM_BIN = process.env.EXTRACT_SBOM_BIN || 'extract-sbom';
const EXTRA_ARGS = (process.env.EXTRACT_SBOM_ARGS || '').split(/\s+/).filter(Boolean);
const MAX_LOG_LINES = parseInt(process.env.MAX_LOG_LINES || '2000', 10);
const SESSION_IDLE_MS = parseInt(process.env.SESSION_IDLE_MS || String(30 * 60 * 1000), 10);
const UPLOAD_RATE_PER_MIN = parseInt(process.env.UPLOAD_RATE_PER_MIN || '5', 10);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const AUTH_USER = process.env.AUTH_USER || '';
const AUTH_PASS = process.env.AUTH_PASS || '';

// Default to system tmpdir, but allow a tmpfs path (e.g. /dev/shm) so the
// uploaded artifact + extracted contents never touch real storage.
const ROOT_TMP = process.env.SCRATCH_DIR || path.join(os.tmpdir(), 'sbom-upload-app');

// Wipe any leftovers from a previous crashed process before we start using
// the scratch root. The 0700 mode keeps other local users out.
try { fs.rmSync(ROOT_TMP, { recursive: true, force: true }); } catch (_) {}
fs.mkdirSync(ROOT_TMP, { recursive: true, mode: 0o700 });
try { fs.chmodSync(ROOT_TMP, 0o700); } catch (_) {}

const sessions = new Map();
const uploadBuckets = new Map(); // ip -> { count, resetAt }

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

async function rmrf(dir) {
  if (!dir) return;
  try { await fsp.rm(dir, { recursive: true, force: true }); }
  catch (err) { console.warn(`cleanup failed for ${dir}:`, err.message); }
}

// Overwrite a file with random bytes before unlinking. Not a real shred on
// CoW/SSD filesystems but cheap and meaningful on tmpfs where the bytes do
// live in RAM. Belt-and-braces; the file is 0600 already.
async function shredUnlink(file) {
  if (!file) return;
  try {
    const st = await fsp.stat(file);
    if (st.size > 0) {
      const fd = await fsp.open(file, 'r+');
      try {
        const chunk = Math.min(64 * 1024, st.size);
        const buf = crypto.randomBytes(chunk);
        let written = 0;
        while (written < st.size) {
          const n = Math.min(buf.length, st.size - written);
          await fd.write(buf, 0, n, written);
          written += n;
        }
        try { await fd.sync(); } catch (_) {}
      } finally { await fd.close(); }
    }
  } catch (_) {}
  try { await fsp.unlink(file); } catch (_) {}
}

function snapshot(sess) {
  const j = sess.job;
  return {
    sessionId: sess.sid,
    sessionStartedAt: sess.createdAt,
    state: j ? j.state : 'idle',
    job: j && {
      pid: j.pid,
      command: j.command,
      // Don't leak the absolute path of internal scratch files to the client.
      // Show only the basenames the user actually cares about.
      args: j.argsDisplay,
      inputName: j.inputName,
      inputSize: j.inputSize,
      passwordCount: j.passwordCount,
      passwordTransport: j.passwordTransport,
      startedAt: j.startedAt,
      finishedAt: j.finishedAt,
      exitCode: j.exitCode,
      signal: j.signal,
      error: j.error,
      state: j.state,
      outputs: j.outputs,
    },
  };
}

function broadcast(sess, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sess.sseClients) {
    try { client.write(payload); } catch (_) {}
  }
}

function pushLog(sess, stream, line) {
  if (!sess.job) return;
  const entry = { t: Date.now(), stream, line };
  sess.job.log.push(entry);
  if (sess.job.log.length > MAX_LOG_LINES) {
    sess.job.log.splice(0, sess.job.log.length - MAX_LOG_LINES);
  }
  broadcast(sess, 'log', entry);
}

async function refreshOutputs(sess) {
  if (!sess.job) return;
  let entries;
  try { entries = await fsp.readdir(sess.job.outDir, { withFileTypes: true }); }
  catch { return; }
  const files = [];
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    try {
      const st = await fsp.stat(path.join(sess.job.outDir, ent.name));
      files.push({ name: ent.name, size: st.size, mtime: st.mtimeMs });
    } catch (_) {}
  }
  files.sort((a, b) => a.name.localeCompare(b.name));
  if (JSON.stringify(sess.job.outputs) !== JSON.stringify(files)) {
    sess.job.outputs = files;
    broadcast(sess, 'outputs', files);
  }
}

function touch(sess) {
  if (sess) sess.lastActivity = Date.now();
}

async function destroySession(sid) {
  const sess = sessions.get(sid);
  if (!sess) return;
  sessions.delete(sid);
  for (const client of sess.sseClients) {
    try { client.write('event: closed\ndata: {}\n\n'); client.end(); } catch (_) {}
  }
  sess.sseClients.clear();
  if (sess.job && sess.job.child && !sess.job.finished) {
    try { sess.job.child.kill('SIGTERM'); } catch (_) {}
  }
  if (sess.watcher) {
    try { sess.watcher.close(); } catch (_) {}
  }
  // Shred the password file if it's still around (job killed mid-flight).
  if (sess.job && sess.job.passwordFile) {
    await shredUnlink(sess.job.passwordFile);
    sess.job.passwordFile = null;
  }
  await rmrf(sess.dir);
}

function newSession() {
  const sid = crypto.randomBytes(16).toString('hex');
  const dir = path.join(ROOT_TMP, sid);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(dir, 'upload'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(dir, 'out'), { recursive: true, mode: 0o700 });
  const sess = {
    sid, dir,
    job: null,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    sseClients: new Set(),
    watcher: null,
  };
  sessions.set(sid, sess);
  return sess;
}

// ----------------------------------------------------------------------------
// Express setup
// ----------------------------------------------------------------------------

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

// --- security headers (apply to everything) ---------------------------------
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=(), browsing-topics=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join('; ')
  );
  // API responses must never end up in shared caches or browser back/forward.
  if (req.path === '/' || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
});

// --- optional HTTP basic auth -----------------------------------------------
function timingEqual(a, b) {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  const len = Math.max(ab.length, bb.length, 1);
  const aPad = Buffer.concat([ab, Buffer.alloc(len - ab.length)]);
  const bPad = Buffer.concat([bb, Buffer.alloc(len - bb.length)]);
  return crypto.timingSafeEqual(aPad, bPad) && ab.length === bb.length;
}

if (AUTH_USER) {
  app.use((req, res, next) => {
    const h = req.get('Authorization') || '';
    if (h.startsWith('Basic ')) {
      let cred = '';
      try { cred = Buffer.from(h.slice(6), 'base64').toString('utf8'); } catch (_) {}
      const i = cred.indexOf(':');
      const u = i >= 0 ? cred.slice(0, i) : cred;
      const p = i >= 0 ? cred.slice(i + 1) : '';
      if (timingEqual(u, AUTH_USER) && timingEqual(p, AUTH_PASS)) return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="SBOM Extractor", charset="UTF-8"');
    res.status(401).send('Authentication required.');
  });
}

// --- CSRF guard for state-changing API endpoints -----------------------------
// Browsers send Sec-Fetch-Site on Fetch/XHR. Reject anything that didn't
// originate from the same origin. (SameSite=Lax already blocks the cookie
// from cross-site POSTs, but defense in depth.)
function sameOriginOnly(req, res, next) {
  const sfs = req.get('Sec-Fetch-Site');
  if (sfs && sfs !== 'same-origin' && sfs !== 'none') {
    return res.status(403).json({ error: 'Cross-origin request rejected.' });
  }
  next();
}

// --- per-IP rate limit on uploads --------------------------------------------
function rateLimitUpload(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let b = uploadBuckets.get(ip);
  if (!b || b.resetAt < now) {
    b = { count: 0, resetAt: now + 60_000 };
    uploadBuckets.set(ip, b);
  }
  b.count++;
  res.setHeader('X-RateLimit-Limit', String(UPLOAD_RATE_PER_MIN));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, UPLOAD_RATE_PER_MIN - b.count)));
  if (b.count > UPLOAD_RATE_PER_MIN) {
    const retry = Math.ceil((b.resetAt - now) / 1000);
    res.setHeader('Retry-After', String(retry));
    return res.status(429).json({ error: 'Too many uploads. Try again later.' });
  }
  next();
}

// --- static files (no index so GET / hits our handler) -----------------------
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  setHeaders(res, file) {
    if (file.endsWith('.js') || file.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-store, private');
    }
  },
}));

// ----------------------------------------------------------------------------
// Routes
// ----------------------------------------------------------------------------

app.get('/', async (req, res) => {
  const prev = req.cookies.sid;
  if (prev) await destroySession(prev);
  const sess = newSession();
  res.cookie('sid', sess.sid, {
    httpOnly: true,
    sameSite: 'strict',
    secure: !!req.secure,
    path: '/',
  });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function requireSession(req, res) {
  const sid = req.cookies.sid;
  const sess = sid && sessions.get(sid);
  if (!sess) {
    res.status(440).json({ error: 'Session expired. Reload the page.' });
    return null;
  }
  touch(sess);
  return sess;
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => {
      const sess = sessions.get(req.cookies.sid);
      if (!sess) return cb(new Error('no session'));
      cb(null, path.join(sess.dir, 'upload'));
    },
    filename: (_req, file, cb) => {
      const safe = path.basename(file.originalname).replace(/[^\w.\-]+/g, '_');
      cb(null, safe || 'artifact.bin');
    },
  }),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 4, parts: 6 },
});

app.get('/api/state', sameOriginOnly, (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  res.json(snapshot(sess));
});

app.get('/api/events', sameOriginOnly, (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-store, private',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  sess.sseClients.add(res);
  res.write(`event: state\ndata: ${JSON.stringify(snapshot(sess))}\n\n`);
  if (sess.job && sess.job.log.length) {
    res.write(`event: log-replay\ndata: ${JSON.stringify(sess.job.log)}\n\n`);
  }
  const beat = setInterval(() => {
    try { res.write(': beat\n\n'); } catch (_) {}
  }, 15000);
  req.on('close', () => {
    clearInterval(beat);
    sess.sseClients.delete(res);
    touch(sess);
  });
});

app.post('/api/upload', sameOriginOnly, rateLimitUpload, (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (sess.job && !sess.job.finished) {
    return res.status(409).json({ error: 'A job is already running in this session.' });
  }

  upload.single('artifact')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? `File exceeds the ${MAX_UPLOAD_BYTES} byte limit.`
        : err.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) return res.status(400).json({ error: 'No artifact uploaded.' });

    // Strip comments + blank lines. Keep order — extract-sbom tries them in
    // sequence and a "no password" attempt is always tried first anyway.
    const passwords = (req.body.passwords || '')
      .split(/\r?\n/)
      .map((s) => s.replace(/\s+$/, ''))
      .filter((s) => s.length > 0 && !s.startsWith('#'));

    // Prefer the EXTRACT_SBOM_PASSWORDS env var so secrets never touch disk.
    // Env vars are still readable by same-user processes via /proc/<pid>/environ,
    // but that's the same threat model as a 0600 file under our scratch dir.
    // The env var format is comma-separated; fall back to a tmpfs file if any
    // password contains a comma.
    let passwordFile = null;
    let passwordTransport = 'none';
    const childEnv = { ...process.env };
    if (passwords.length > 0) {
      const hasComma = passwords.some((p) => p.includes(','));
      if (!hasComma) {
        childEnv.EXTRACT_SBOM_PASSWORDS = passwords.join(',');
        passwordTransport = 'env';
      } else {
        passwordFile = path.join(sess.dir, 'passwords.txt');
        await fsp.writeFile(passwordFile, passwords.join('\n') + '\n', { mode: 0o600 });
        passwordTransport = 'file';
      }
    }

    const outDir = path.join(sess.dir, 'out');
    const args = ['--output-dir', outDir, ...EXTRA_ARGS];
    if (passwordFile) args.push('--password-file', passwordFile);
    args.push(req.file.path);

    // Display-only args: replace full scratch paths with basenames so the UI
    // doesn't show the server-side internal directory layout.
    const argsDisplay = args.map((a) =>
      a.startsWith(sess.dir + path.sep) ? path.basename(a) : a
    );

    let child;
    try {
      child = spawn(EXTRACT_SBOM_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'], env: childEnv });
    } catch (e) {
      await shredUnlink(passwordFile);
      return res.status(500).json({ error: `Failed to spawn ${EXTRACT_SBOM_BIN}: ${e.message}` });
    }

    const job = {
      child,
      pid: child.pid,
      command: EXTRACT_SBOM_BIN,
      args, argsDisplay,
      state: 'running',
      finished: false,
      exitCode: null,
      signal: null,
      error: null,
      startedAt: Date.now(),
      finishedAt: null,
      inputName: req.file.filename,
      inputSize: req.file.size,
      uploadPath: req.file.path,
      passwordCount: passwords.length,
      passwordTransport,
      passwordFile,
      outDir,
      outputs: [],
      log: [],
    };
    sess.job = job;

    readline.createInterface({ input: child.stdout }).on('line', (l) => pushLog(sess, 'stdout', l));
    readline.createInterface({ input: child.stderr }).on('line', (l) => pushLog(sess, 'stderr', l));

    try {
      sess.watcher = fs.watch(outDir, { persistent: false }, () => {
        refreshOutputs(sess).catch(() => {});
      });
    } catch (_) { /* fs.watch not supported on this platform */ }

    broadcast(sess, 'state', snapshot(sess));

    child.on('error', (e) => {
      job.error = e.message;
      pushLog(sess, 'stderr', `[spawn error] ${e.message}`);
    });

    child.on('close', async (code, signal) => {
      job.finished = true;
      job.exitCode = code;
      job.signal = signal;
      job.finishedAt = Date.now();
      job.state = code === 0 ? 'done' : (signal ? 'cancelled' : 'failed');
      if (sess.watcher) {
        try { sess.watcher.close(); } catch (_) {}
        sess.watcher = null;
      }
      // Shred + unlink the password file the instant the child has exited.
      // The uploaded artifact goes too; only the SBOM/report remain.
      await shredUnlink(job.passwordFile);
      job.passwordFile = null;
      try { await fsp.unlink(job.uploadPath); } catch (_) {}
      await refreshOutputs(sess);
      touch(sess);
      broadcast(sess, 'state', snapshot(sess));
    });

    res.json({ ok: true, snapshot: snapshot(sess) });
  });
});

app.post('/api/cancel', sameOriginOnly, (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (!sess.job || sess.job.finished) {
    return res.status(409).json({ error: 'No job is running.' });
  }
  try { sess.job.child.kill('SIGTERM'); } catch (_) {}
  const child = sess.job.child;
  setTimeout(() => {
    if (!child.killed) {
      try { child.kill('SIGKILL'); } catch (_) {}
    }
  }, 5000).unref();
  res.json({ ok: true });
});

app.get('/api/download/:name', sameOriginOnly, async (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (!sess.job || !sess.job.finished) return res.status(409).send('Not ready.');
  const name = path.basename(req.params.name);
  const full = path.join(sess.job.outDir, name);
  if (!full.startsWith(sess.job.outDir + path.sep)) return res.status(400).send('Bad path.');
  try { await fsp.access(full, fs.constants.R_OK); }
  catch { return res.status(404).send('Not found.'); }
  res.setHeader('Cache-Control', 'no-store, private');
  res.download(full, name);
});

app.post('/api/reset', sameOriginOnly, async (req, res) => {
  const sid = req.cookies.sid;
  if (sid) await destroySession(sid);
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, sessions: sessions.size });
});

// ----------------------------------------------------------------------------
// Background GC: drop sessions that have no active job and no live SSE
// subscriber after the idle window. Catches users who close the tab without
// the sendBeacon making it through.
// ----------------------------------------------------------------------------

setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of sessions) {
    if (sess.job && !sess.job.finished) continue;
    if (sess.sseClients.size > 0) continue;
    if (now - (sess.lastActivity || sess.createdAt) > SESSION_IDLE_MS) {
      destroySession(sid).catch(() => {});
    }
  }
  // Trim rate-limit buckets too.
  for (const [ip, b] of uploadBuckets) {
    if (b.resetAt < now) uploadBuckets.delete(ip);
  }
}, 60_000).unref();

// ----------------------------------------------------------------------------
// Boot + shutdown
// ----------------------------------------------------------------------------

const server = app.listen(PORT, HOST, () => {
  console.log(`SBOM upload app listening on http://${HOST}:${PORT}`);
  console.log(`extract-sbom binary: ${EXTRACT_SBOM_BIN}`);
  console.log(`extract-sbom extra args: ${EXTRA_ARGS.join(' ') || '(none)'}`);
  console.log(`scratch dir: ${ROOT_TMP}`);
  console.log(`auth: ${AUTH_USER ? 'basic (' + AUTH_USER + ')' : 'disabled'}`);
  console.log(`trust proxy: ${TRUST_PROXY}`);
});

async function shutdown(sig) {
  console.log(`\n${sig} received, cleaning sessions...`);
  await Promise.all([...sessions.keys()].map(destroySession));
  await rmrf(ROOT_TMP);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
