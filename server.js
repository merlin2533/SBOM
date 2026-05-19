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
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024; // 5 GB
const EXTRACT_SBOM_BIN = process.env.EXTRACT_SBOM_BIN || 'extract-sbom';
const EXTRA_ARGS = (process.env.EXTRACT_SBOM_ARGS || '').split(/\s+/).filter(Boolean);
const ROOT_TMP = path.join(os.tmpdir(), 'sbom-upload-app');
const MAX_LOG_LINES = 2000;

fs.mkdirSync(ROOT_TMP, { recursive: true });

const sessions = new Map();

async function rmrf(dir) {
  if (!dir) return;
  try { await fsp.rm(dir, { recursive: true, force: true }); }
  catch (err) { console.warn(`cleanup failed for ${dir}:`, err.message); }
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
      args: j.args,
      inputName: j.inputName,
      inputSize: j.inputSize,
      passwordCount: j.passwordCount,
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
  const prev = JSON.stringify(sess.job.outputs);
  const next = JSON.stringify(files);
  if (prev !== next) {
    sess.job.outputs = files;
    broadcast(sess, 'outputs', files);
  }
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
  await rmrf(sess.dir);
}

function newSession() {
  const sid = crypto.randomBytes(16).toString('hex');
  const dir = path.join(ROOT_TMP, sid);
  fs.mkdirSync(path.join(dir, 'upload'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'out'), { recursive: true });
  const sess = {
    sid,
    dir,
    job: null,
    createdAt: Date.now(),
    sseClients: new Set(),
    watcher: null,
  };
  sessions.set(sid, sess);
  return sess;
}

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
// index: false so GET / hits our handler and rotates the session cookie.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', async (req, res) => {
  const prev = req.cookies.sid;
  if (prev) await destroySession(prev);
  const sess = newSession();
  res.cookie('sid', sess.sid, { httpOnly: true, sameSite: 'lax' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function requireSession(req, res) {
  const sid = req.cookies.sid;
  const sess = sid && sessions.get(sid);
  if (!sess) {
    res.status(440).json({ error: 'Session expired. Reload the page.' });
    return null;
  }
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
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
});

app.get('/api/state', (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  res.json(snapshot(sess));
});

app.get('/api/log', (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  res.json({ log: sess.job ? sess.job.log : [] });
});

app.get('/api/events', (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  sess.sseClients.add(res);
  // Initial snapshot so a fresh subscriber doesn't need a separate /api/state call.
  res.write(`event: state\ndata: ${JSON.stringify(snapshot(sess))}\n\n`);
  if (sess.job && sess.job.log.length) {
    res.write(`event: log-replay\ndata: ${JSON.stringify(sess.job.log)}\n\n`);
  }
  // Heartbeat to keep proxies from idling the connection out.
  const beat = setInterval(() => {
    try { res.write(': beat\n\n'); } catch (_) {}
  }, 15000);
  req.on('close', () => {
    clearInterval(beat);
    sess.sseClients.delete(res);
  });
});

app.post('/api/upload', (req, res) => {
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

    // Passwords come as a textarea; strip comments and blank lines, keep order.
    const rawPasswords = (req.body.passwords || '')
      .split(/\r?\n/)
      .map((s) => s.replace(/\s+$/, ''))
      .filter((s) => s.length > 0 && !s.startsWith('#'));

    let passwordFile = null;
    if (rawPasswords.length > 0) {
      passwordFile = path.join(sess.dir, 'passwords.txt');
      await fsp.writeFile(passwordFile, rawPasswords.join('\n') + '\n', { mode: 0o600 });
    }

    const outDir = path.join(sess.dir, 'out');
    const args = ['--output-dir', outDir, ...EXTRA_ARGS];
    if (passwordFile) args.push('--password-file', passwordFile);
    args.push(req.file.path);

    let child;
    try {
      child = spawn(EXTRACT_SBOM_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return res.status(500).json({ error: `Failed to spawn ${EXTRACT_SBOM_BIN}: ${e.message}` });
    }

    const job = {
      child,
      pid: child.pid,
      command: EXTRACT_SBOM_BIN,
      args,
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
      passwordCount: rawPasswords.length,
      passwordFile,
      outDir,
      outputs: [],
      log: [],
    };
    sess.job = job;

    // Stream stdout/stderr line-by-line so the UI sees lines as soon as the
    // subprocess flushes them, not at end-of-run.
    readline.createInterface({ input: child.stdout }).on('line', (l) => pushLog(sess, 'stdout', l));
    readline.createInterface({ input: child.stderr }).on('line', (l) => pushLog(sess, 'stderr', l));

    // Watch the output directory: extract-sbom writes the SBOM/report
    // mid-run, and we want the UI to surface them immediately.
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
      // Drop the password file ASAP and the uploaded artifact too; only the
      // generated outputs remain until the session is torn down.
      if (job.passwordFile) {
        try { await fsp.unlink(job.passwordFile); } catch (_) {}
        job.passwordFile = null;
      }
      try { await fsp.unlink(job.uploadPath); } catch (_) {}
      await refreshOutputs(sess);
      broadcast(sess, 'state', snapshot(sess));
    });

    res.json({ ok: true, snapshot: snapshot(sess) });
  });
});

app.post('/api/cancel', (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (!sess.job || sess.job.finished) {
    return res.status(409).json({ error: 'No job is running.' });
  }
  try { sess.job.child.kill('SIGTERM'); } catch (_) {}
  // If SIGTERM hasn't taken effect after a few seconds, escalate.
  const child = sess.job.child;
  setTimeout(() => {
    if (!child.killed) {
      try { child.kill('SIGKILL'); } catch (_) {}
    }
  }, 5000).unref();
  res.json({ ok: true });
});

app.get('/api/download/:name', async (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (!sess.job || !sess.job.finished) return res.status(409).send('Not ready.');
  const name = path.basename(req.params.name);
  const full = path.join(sess.job.outDir, name);
  if (!full.startsWith(sess.job.outDir + path.sep)) return res.status(400).send('Bad path.');
  try { await fsp.access(full, fs.constants.R_OK); }
  catch { return res.status(404).send('Not found.'); }
  res.download(full, name);
});

app.post('/api/reset', async (req, res) => {
  const sid = req.cookies.sid;
  if (sid) await destroySession(sid);
  res.clearCookie('sid');
  res.json({ ok: true });
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, sessions: sessions.size, bin: EXTRACT_SBOM_BIN });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`SBOM upload app listening on http://${HOST}:${PORT}`);
  console.log(`extract-sbom binary: ${EXTRACT_SBOM_BIN}`);
  console.log(`extract-sbom extra args: ${EXTRA_ARGS.join(' ') || '(none)'}`);
  console.log(`scratch dir: ${ROOT_TMP}`);
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
