# SBOM Upload App

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream: TomTonic/extract-sbom](https://img.shields.io/badge/upstream-TomTonic%2Fextract--sbom-informational)](https://github.com/TomTonic/extract-sbom)

A small, self-hosted Node.js + TypeScript web frontend that wraps the
[**TomTonic/extract-sbom**](https://github.com/TomTonic/extract-sbom)
supply-chain inspection tool. Drop a software artifact (up to 5 GB) in
your browser; the app uploads it resumably, runs the upstream Go
extractor in a sandbox, and gives you back a CycloneDX SBOM plus audit
report — all without any data ever leaving your own machine and all
deleted again the moment you reload the page.

> The actual SBOM extraction, archive recursion, syft cataloguing and
> audit-report format are entirely the work of the upstream project.
> This repository only adds the web shell, the sandbox wiring, the
> resumable-upload plumbing and the ephemeral session lifecycle. See
> [NOTICE](NOTICE) for attribution and [LICENSE](LICENSE) for the legal
> details.

## Highlights

- **Resumable uploads** via [tus](https://tus.io) — interruptions over
  Wi-Fi don't kill a 5 GB upload, they just resume.
- **Per-session job queue** with history: run multiple artifacts in
  sequence and keep their downloads around for the lifetime of the tab.
- **Sandboxed analysis**: `bwrap` / `firejail` auto-detection. Read-only
  root, only the per-session scratch dir is writable, no network for the
  child process.
- **Live process telemetry over Server-Sent Events**: PID, command,
  elapsed time, phase + progress bar (derived from log step detection),
  cancel button.
- **Ephemeral by design**: every session has its own 0700 scratch
  directory; uploads are deleted once extract-sbom exits, passwords are
  passed via env var (or shredded 0600 file fallback), the entire scratch
  root is wiped on reload, on tab close, on idle GC and on `SIGTERM`.
- **Hardened HTTP**: strict CSP, no inline JS/CSS, `SameSite=Strict`
  cookie, `Sec-Fetch-Site` CSRF guard, optional Basic Auth, per-IP
  rate limit, structured pino logs with secret redaction.
- **Graceful drain** on `SIGTERM`: in-flight jobs are given
  `SHUTDOWN_GRACE_MS` to finish before the process exits.

## Who this is for

Anyone who wants to give non-CLI users a one-click "drop your artifact,
get an SBOM" experience without writing their own glue. The repo is
permissively MIT-licensed and self-contained — fork it, deploy it on an
internal VM behind your SSO proxy, mount the scratch dir on tmpfs, and
you're done. Contributions back are welcome.

## Requirements

- **Node.js ≥ 20**
- **Go ≥ 1.21** to build the upstream extract-sbom binary from source
- **git** with submodule support (for the upstream source)
- **Recommended on Linux:** `bwrap` (Debian/Ubuntu: `apt install bubblewrap`).
  The app auto-detects it and falls back to running unsandboxed if it's
  missing — set `SANDBOX_MODE=none` to be explicit, or
  `EXTRACT_SBOM_ARGS=--unsafe` to disable extract-sbom's own sandbox too.
- **Optional**: `syft` (component cataloging) and `grype` (vulnerability
  enrichment) are runtime deps of extract-sbom itself; the app surfaces
  them as advisory checks via `scripts/preflight.sh`.

## Quickstart

### From source

```bash
git clone https://github.com/merlin2533/sbom.git
cd sbom
./scripts/install.sh         # init submodule, npm ci, build the Go binary, npm run build
npm start                    # listen on http://localhost:3000
```

`install.sh` is idempotent — re-run it any time you pull updates.

### From the published Docker image

A multi-stage image is built and pushed to Docker Hub and GHCR on every
commit to `main` and on every `v*.*.*` tag (see
[`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)).

```bash
# Pull and run a one-shot container:
docker run --rm -p 3000:3000 \
  --tmpfs /scratch:rw,nosuid,nodev,size=8g,mode=1700 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  -e SCRATCH_DIR=/scratch -e SANDBOX_MODE=none \
  merlin2539/sbom:latest

# Or, ready-made compose file:
curl -fsSL https://raw.githubusercontent.com/merlin2533/sbom/main/docker-compose.yml \
    -o docker-compose.yml
docker compose up -d
# open http://localhost:3000
```

The image ships with `bubblewrap`, `syft` and the upstream Go
`extract-sbom` binary already built in; you only need a Docker host.

> Maintainers: pushing requires the repo secrets `DOCKERHUB_USERNAME` and
> `DOCKERHUB_TOKEN` to be set. GHCR uses the workflow's built-in
> `GITHUB_TOKEN` automatically.

## Preflight check

Before exposing the app, verify everything is in place:

```bash
./scripts/preflight.sh        # or: npm run preflight
```

Exits 0 only when the required pieces (Node, `extract-sbom` resolvable,
built assets, writable scratch dir) are all green. Optional tools
(`bwrap`, `firejail`, `syft`, `grype`) print advisory warnings but
never fail the check.

## Configuration

All knobs are environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `EXTRACT_SBOM_BIN` | `extract-sbom` | Path to the binary (defaults to PATH lookup; `./bin/extract-sbom` after `install.sh`) |
| `EXTRACT_SBOM_ARGS` | _(empty)_ | Extra args appended to every invocation, e.g. `--unsafe --grype` |
| `SANDBOX_MODE` | `auto` | `auto` \| `bwrap` \| `firejail` \| `none` |
| `MAX_UPLOAD_BYTES` | `5368709120` | Upload size cap (default 5 GiB) |
| `SCRATCH_DIR` | `$TMPDIR/sbom-upload-app` | Per-session work area. Point at `/dev/shm/...` to keep everything in RAM |
| `SESSION_IDLE_MS` | `1800000` | Idle session GC (default 30 min) |
| `SHUTDOWN_GRACE_MS` | `30000` | Time to wait for in-flight jobs on SIGTERM |
| `UPLOAD_RATE_PER_MIN` | `5` | Per-IP rate limit on new upload creations |
| `AUTH_USER` / `AUTH_PASS` | _(empty)_ | When both set: HTTP Basic Auth on every route |
| `TRUST_PROXY` | `0` | Set to `1` behind a TLS-terminating reverse proxy. Makes the cookie `Secure`, honours `X-Forwarded-*` |
| `LOG_LEVEL` | `info` | pino log level |
| `LOG_PRETTY` | _(auto-detected)_ | Force pretty stdout logs on/off |

## Privacy & security

The app is **ephemeral by default** and tries hard to keep uploads and
secrets out of long-lived storage.

### Where the data lives

- The whole scratch root is created with mode `0700` and **wiped on
  startup** (so a crashed previous process can't leak leftovers) and on
  graceful shutdown.
- Set `SCRATCH_DIR=/dev/shm/sbom-upload-app` to keep every byte in RAM
  — uploads, intermediate extraction, the SBOM and the report.
- Each session gets its own subdirectory `<scratch>/<sid>/`, also `0700`.
  The session id is 128 bits of CSPRNG, carried in an `HttpOnly`,
  `SameSite=Strict` cookie (plus `Secure` when behind an HTTPS proxy and
  `TRUST_PROXY=1`).

### Passwords

- By default passwords are passed to extract-sbom via the
  `EXTRACT_SBOM_PASSWORDS` env var of the child process — **they never
  touch disk**. The env var disappears with the child.
- Fallback: if any password contains a comma (which the env-var
  encoding can't represent unambiguously) the app writes a 0600
  `passwords.txt` in the session dir, passes it via `--password-file`,
  and **shreds it** (overwrite with random bytes, `fsync`, `unlink`)
  the moment the child exits. The UI shows which transport was used.
- Same threat model in both cases: a same-user process on the host can
  read either `/proc/<pid>/environ` or the 0600 file. Don't expose the
  app on a multi-tenant host without a sandbox.

### After the run

- The uploaded artifact is deleted as soon as extract-sbom exits.
- The generated SBOM/report stay only until the session is destroyed
  (reload, **New session**, tab close, idle GC, or shutdown).

### Sandboxing

When `SANDBOX_MODE` resolves to `bwrap` or `firejail`, every
`extract-sbom` invocation runs with:

- read-only root filesystem view,
- only the per-session scratch dir bound read-write,
- no network namespace,
- private `/tmp` and `/dev`,
- `--die-with-parent` so a crash of the Node parent cleans up children.

Set `SANDBOX_MODE=none` to disable.

### Transport & HTTP headers

- Cookie: `HttpOnly; SameSite=Strict; Secure` (the last one when behind
  an HTTPS proxy with `TRUST_PROXY=1`).
- Content Security Policy: `default-src 'self'`, no inline scripts or
  styles, `frame-ancestors 'none'`, `base-uri 'none'`, `object-src
  'none'`.
- Plus `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, `Permissions-Policy`.
- `Cache-Control: no-store, private` on the SPA shell, every API
  response and served JS/CSS — nothing lands in shared caches.
- CSRF: state-changing API calls reject requests whose `Sec-Fetch-Site`
  is neither `same-origin` nor `none`. Combined with `SameSite=Strict`
  this blocks cross-site form-POSTs even from older browsers.
- HTTP Basic Auth (optional, `AUTH_USER`/`AUTH_PASS`) gates every route;
  credentials are compared in constant time.
- Per-IP upload rate limit (default 5/min) returns 429 with
  `Retry-After`.

### Logging

Structured JSON logs via [pino](https://getpino.io), with redaction for
`req.headers.authorization`, `req.headers.cookie`, `set-cookie`, and any
field matching `password*`. `LOG_PRETTY=1` switches to a human-readable
console formatter.

### Deployment recipe (production)

```bash
SCRATCH_DIR=/dev/shm/sbom \
SANDBOX_MODE=bwrap \
AUTH_USER=ops AUTH_PASS='change-me' \
TRUST_PROXY=1 \
PORT=3000 HOST=127.0.0.1 \
LOG_LEVEL=info \
npm start
```

Put it behind nginx / Caddy / Traefik with TLS termination, forwarding
`X-Forwarded-Proto` so the session cookie ends up `Secure`. Set the
proxy's upload size limit to at least `MAX_UPLOAD_BYTES`. The tus
protocol uses `OPTIONS`, `POST`, `HEAD`, `PATCH` and `DELETE` — make
sure your proxy passes those through.

## API

The browser app talks to a small JSON API. Endpoints are session-scoped
via the `sid` cookie.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Issues a fresh session cookie, wipes the previous session's scratch dir, serves the SPA |
| `*` | `/api/tus/*` | Resumable upload protocol ([tus 1.0](https://tus.io/protocols/resumable-upload)) |
| `POST` | `/api/jobs` | Body `{ passwords?: string }`. Starts extract-sbom on the just-finished upload |
| `GET` | `/api/state` | One-shot session snapshot (current job + history) |
| `GET` | `/api/events` | Server-Sent Events stream: `state`, `log`, `log-replay`, `outputs`, `phase`, `closed` |
| `POST` | `/api/cancel` | SIGTERM the running job (then SIGKILL after 5 s) |
| `GET` | `/api/download/:jobId/:name` | Stream an output file from a specific job |
| `POST` | `/api/reset` | Destroy this session immediately |
| `GET` | `/api/health` | Liveness, session count, detected sandbox |

## Repository layout

```
src/                    Node/TypeScript server (compiled to dist/)
public/src/             Browser TypeScript source
public/                 index.html, styles.css, vendored tus client
scripts/install.sh      One-shot bootstrap (submodule + Go build + npm)
scripts/preflight.sh    Deployment readiness check
vendor/extract-sbom/    Git submodule → TomTonic/extract-sbom upstream
tests/                  vitest tests
bin/                    Built extract-sbom binary lands here
```

## Contributing

Issues and PRs welcome. Two ground rules:

1. Don't break the privacy guarantees (ephemeral session, no disk
   passwords by default, no logs of secrets). Tests in `tests/` cover
   the security middlewares — keep them green.
2. Don't fork extract-sbom's logic into this repo. Bug reports and
   feature requests for the extractor itself belong
   [upstream](https://github.com/TomTonic/extract-sbom/issues).

Run `npm run typecheck && npm test` before opening a PR.

## License

MIT — see [LICENSE](LICENSE).

The submodule under `vendor/extract-sbom/` is BSD 3-Clause and remains
the property of its upstream author; see [NOTICE](NOTICE) and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
