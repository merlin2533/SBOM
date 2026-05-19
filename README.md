# SBOM Upload App

Ephemeral Node.js web frontend around
[TomTonic/extract-sbom](https://github.com/TomTonic/extract-sbom).

- Drag-and-drop a single artifact per session, up to **5 GB**, streamed
  straight to disk.
- Provide archive passwords (one per line, `#` comments allowed).
- Watch the extract-sbom process live: PID, command line, elapsed time, log
  output streamed line-by-line over Server-Sent Events, output files appearing
  as soon as they are written.
- Cancel a running process (SIGTERM, escalates to SIGKILL after 5 s).
- Download the generated CycloneDX SBOM (`<name>.cdx.json`) and audit report
  (`<name>.report.md` / `<name>.report.json`).
- All files live in a per-session scratch directory and are deleted on page
  reload, on **New session**, on tab close (best-effort via `sendBeacon`),
  after the idle timeout, or on server shutdown (`SIGINT`/`SIGTERM`).

## Requirements

- Node.js ≥ 18
- The `extract-sbom` binary available on `$PATH` (or set `EXTRACT_SBOM_BIN` to
  an absolute path). See [extract-sbom INSTALL.md](https://github.com/TomTonic/extract-sbom/blob/main/INSTALL.md).
- For sandboxed runs on Linux, `bwrap`. Otherwise pass `--unsafe` via
  `EXTRACT_SBOM_ARGS=--unsafe`.

## Run

```bash
npm install
npm start
# open http://localhost:3000
```

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `EXTRACT_SBOM_BIN` | `extract-sbom` | Path to the binary |
| `EXTRACT_SBOM_ARGS` | _(empty)_ | Extra args appended to every invocation, e.g. `--unsafe --grype` |
| `MAX_UPLOAD_BYTES` | `5368709120` | Upload size cap (default 5 GB) |
| `SCRATCH_DIR` | `$TMPDIR/sbom-upload-app` | Where uploads + outputs live. Set to `/dev/shm/sbom` to keep everything in RAM |
| `SESSION_IDLE_MS` | `1800000` | Idle session GC interval (default 30 min) |
| `UPLOAD_RATE_PER_MIN` | `5` | Per-IP upload attempts per minute (429 over that) |
| `AUTH_USER` / `AUTH_PASS` | _(empty)_ | Enable HTTP Basic Auth on every route when both are set |
| `TRUST_PROXY` | `0` | Set to `1` when behind a TLS-terminating reverse proxy. Makes the session cookie `Secure` and honours `X-Forwarded-*` |

## Privacy & security

The app is built to be **ephemeral by default** and to minimise the on-disk
footprint of the uploaded artifact and any archive passwords.

### Where the data lives

- The whole scratch root is created with mode `0700` and **wiped on startup**
  (so a crashed previous process can't leak leftovers) and on graceful
  shutdown (`SIGINT`/`SIGTERM`).
- Set `SCRATCH_DIR=/dev/shm/sbom-upload-app` to keep every byte in RAM —
  uploads, intermediate extraction, the SBOM/report — so nothing ever hits
  block storage.
- Each session gets its own subdirectory (`<scratch>/<sid>/`), also `0700`.
  The session id is a 128-bit random hex string carried in an `HttpOnly`,
  `SameSite=Strict` cookie (plus `Secure` when `TRUST_PROXY=1` and the
  request is HTTPS).

### Passwords

- By default passwords are passed to extract-sbom via the
  `EXTRACT_SBOM_PASSWORDS` env var of the child process — **they never touch
  disk**. The env var disappears with the child.
- Fallback: if any password contains a comma (which the env-var encoding
  can't represent unambiguously) the app writes a `passwords.txt` file in
  the session dir (`0600`), passes it via `--password-file`, and **shreds
  it** (overwrite with random bytes, `fsync`, `unlink`) the moment the child
  exits. The Process panel in the UI shows which transport was used.
- Same threat model in both cases: a same-user process on the host can read
  either `/proc/<pid>/environ` or the 0600 file. Don't run the app on a
  multi-tenant host without a sandbox.

### After the run

- The uploaded artifact is deleted as soon as extract-sbom exits.
- The generated SBOM/report stay only until the session is destroyed
  (reload, **New session**, tab close, idle GC, or shutdown).

### Transport & headers

- Cookie: `HttpOnly; SameSite=Strict; Secure` (the last one when behind an
  HTTPS proxy and `TRUST_PROXY=1`).
- Content Security Policy: `default-src 'self'`, no inline scripts/styles,
  `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`.
- Plus `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, `Permissions-Policy`.
- `Cache-Control: no-store, private` on the SPA shell, all API responses
  and all served JS/CSS so nothing lands in a shared cache.
- CSRF: every state-changing API call rejects requests whose
  `Sec-Fetch-Site` is neither `same-origin` nor `none`. Combined with the
  `SameSite=Strict` cookie this blocks cross-site form-POST attacks.
- HTTP Basic Auth (optional, `AUTH_USER`/`AUTH_PASS`) protects every route;
  credentials compared in constant time.
- Per-IP upload rate limit (default 5/min) returns 429 with `Retry-After`.

### Deployment recipe (production)

```bash
SCRATCH_DIR=/dev/shm/sbom \
EXTRACT_SBOM_ARGS="--unsafe" \
AUTH_USER=ops AUTH_PASS='change-me' \
TRUST_PROXY=1 \
PORT=3000 HOST=127.0.0.1 \
node server.js
```

Behind nginx / Caddy with TLS termination, forwarding
`X-Forwarded-Proto` so the session cookie ends up `Secure`. Make sure the
proxy's upload size limit matches `MAX_UPLOAD_BYTES`.

## API

The browser app talks to a small JSON API. Endpoints are session-scoped via
the `sid` cookie:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Issues a fresh session cookie, wipes the previous session's scratch dir, serves the SPA |
| `POST` | `/api/upload` | Multipart upload (`artifact`, `passwords`); spawns extract-sbom |
| `GET` | `/api/state` | One-shot job/session snapshot |
| `GET` | `/api/events` | Server-Sent Events stream: `state`, `log`, `log-replay`, `outputs`, `closed` |
| `POST` | `/api/cancel` | SIGTERM the running process (then SIGKILL after 5 s) |
| `GET` | `/api/download/:name` | Stream an output file by basename |
| `POST` | `/api/reset` | Destroy this session immediately |
| `GET` | `/api/health` | Liveness + session count |

## Notes

- Uploads stream straight to disk via multer; the process does not buffer the
  whole artifact in memory.
- Concurrent jobs per session are rejected with HTTP 409. Different browsers /
  cookies get independent sessions.
- The Process panel shows file basenames only — full server-side scratch
  paths are stripped before they reach the browser.
