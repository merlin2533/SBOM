const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024; // 5 GB
const EXTRACT_SBOM_BIN = process.env.EXTRACT_SBOM_BIN || 'extract-sbom';
const EXTRA_ARGS = (process.env.EXTRACT_SBOM_ARGS || '').split(/\s+/).filter(Boolean);
const ROOT_TMP = path.join(os.tmpdir(), 'sbom-upload-app');

fs.mkdirSync(ROOT_TMP, { recursive: true });

// In-memory job/session registry. Each entry tracks the per-session work dir
// and the state of its single extract-sbom run. Everything is wiped when the
// user reloads the page (a fresh session takes over) or when the process dies.
const sessions = new Map();

async function rmrf(dir) {
  if (!dir) return;
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (err) {
    console.warn(`cleanup failed for ${dir}:`, err.message);
  }
}

async function destroySession(sid) {
  const sess = sessions.get(sid);
  if (!sess) return;
  sessions.delete(sid);
  if (sess.job && sess.job.child && !sess.job.finished) {
    try { sess.job.child.kill('SIGTERM'); } catch (_) {}
  }
  await rmrf(sess.dir);
}

function newSession() {
  const sid = crypto.randomBytes(16).toString('hex');
  const dir = path.join(ROOT_TMP, sid);
  fs.mkdirSync(path.join(dir, 'upload'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'out'), { recursive: true });
  const sess = { sid, dir, job: null, createdAt: Date.now() };
  sessions.set(sid, sess);
  return sess;
}

const app = express();
app.use(cookieParser());
// index: false ensures GET / falls through to our handler below, which
// rotates the session cookie. Asset requests still work normally.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Every visit to the page wipes the previous session and starts a fresh one,
// so leftover uploads/outputs are gone the moment the user reloads.
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
      // Keep the original basename so extract-sbom's output filenames are
      // recognisable to the user. Strip any path components defensively.
      const safe = path.basename(file.originalname).replace(/[^\w.\-]+/g, '_');
      cb(null, safe || 'artifact.bin');
    },
  }),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
});

app.post('/upload', (req, res) => {
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

    const passwords = (req.body.passwords || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    let passwordFile = null;
    if (passwords.length > 0) {
      passwordFile = path.join(sess.dir, 'passwords.txt');
      await fsp.writeFile(passwordFile, passwords.join('\n') + '\n', { mode: 0o600 });
    }

    const outDir = path.join(sess.dir, 'out');
    const args = ['--output-dir', outDir, ...EXTRA_ARGS];
    if (passwordFile) args.push('--password-file', passwordFile);
    args.push(req.file.path);

    const logPath = path.join(sess.dir, 'extract-sbom.log');
    const logStream = fs.createWriteStream(logPath);

    let child;
    try {
      child = spawn(EXTRACT_SBOM_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      return res.status(500).json({ error: `Failed to spawn extract-sbom: ${e.message}` });
    }

    const job = {
      child,
      finished: false,
      exitCode: null,
      error: null,
      startedAt: Date.now(),
      finishedAt: null,
      inputName: req.file.filename,
      passwordFile,
      outDir,
      logPath,
    };
    sess.job = job;

    child.stdout.pipe(logStream, { end: false });
    child.stderr.pipe(logStream, { end: false });

    child.on('error', (e) => {
      job.error = e.message;
    });
    child.on('close', async (code) => {
      job.finished = true;
      job.exitCode = code;
      job.finishedAt = Date.now();
      logStream.end();
      // Password file no longer needed once the run is over; remove it ASAP.
      if (job.passwordFile) {
        try { await fsp.unlink(job.passwordFile); } catch (_) {}
        job.passwordFile = null;
      }
      // The uploaded artifact itself is also dropped once processing is done
      // to free disk; the generated SBOM/report stay until session teardown.
      try { await fsp.unlink(req.file.path); } catch (_) {}
    });

    res.json({ ok: true });
  });
});

async function listOutputs(outDir) {
  let entries;
  try {
    entries = await fsp.readdir(outDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files = [];
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    const full = path.join(outDir, ent.name);
    const st = await fsp.stat(full);
    files.push({ name: ent.name, size: st.size });
  }
  return files.sort((a, b) => a.name.localeCompare(b.name));
}

app.get('/status', async (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  const job = sess.job;
  if (!job) return res.json({ state: 'idle' });
  const outputs = job.finished ? await listOutputs(job.outDir) : [];
  let log = '';
  try { log = await fsp.readFile(job.logPath, 'utf8'); } catch (_) {}
  // Cap the log payload so giant runs don't bloat the polling response.
  if (log.length > 32_000) log = '…\n' + log.slice(-32_000);
  res.json({
    state: job.finished ? 'done' : 'running',
    exitCode: job.exitCode,
    error: job.error,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    outputs,
    log,
  });
});

app.get('/download/:name', async (req, res) => {
  const sess = requireSession(req, res);
  if (!sess) return;
  if (!sess.job || !sess.job.finished) return res.status(409).send('Not ready.');
  const name = path.basename(req.params.name);
  const full = path.join(sess.job.outDir, name);
  if (!full.startsWith(sess.job.outDir + path.sep)) return res.status(400).send('Bad path.');
  try {
    await fsp.access(full, fs.constants.R_OK);
  } catch {
    return res.status(404).send('Not found.');
  }
  res.download(full, name);
});

app.post('/reset', async (req, res) => {
  const sid = req.cookies.sid;
  if (sid) await destroySession(sid);
  res.clearCookie('sid');
  res.json({ ok: true });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`SBOM upload app listening on http://${HOST}:${PORT}`);
  console.log(`extract-sbom binary: ${EXTRACT_SBOM_BIN}`);
  console.log(`scratch dir: ${ROOT_TMP}`);
});

async function shutdown() {
  console.log('shutting down, cleaning sessions...');
  await Promise.all([...sessions.keys()].map(destroySession));
  await rmrf(ROOT_TMP);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
