# SBOM Upload App

Ephemeral Node.js web frontend around
[TomTonic/extract-sbom](https://github.com/TomTonic/extract-sbom).

- Upload one artifact per session, up to **5 GB**.
- Provide archive passwords (one per line, optional).
- Download the generated CycloneDX SBOM (`<name>.cdx.json`) and audit report
  (`<name>.report.md` / `<name>.report.json`).
- All files live in a per-session temp directory and are deleted on page
  reload, on "Reset session", or on server shutdown.

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

## Ephemerality model

- Each `GET /` issues a fresh session cookie and **destroys** the previous
  session's directory (upload, passwords, outputs).
- The password file is written with mode `0600` and removed as soon as
  extract-sbom exits.
- The uploaded artifact is removed after extract-sbom exits; only the SBOM
  and report stay until session teardown.
- On `SIGINT`/`SIGTERM` the whole scratch directory is wiped.

## Notes

- Uploads stream straight to disk via multer; the process does not buffer the
  whole artifact in memory.
- Concurrent jobs per session are rejected with HTTP 409. Different browsers /
  cookies get independent sessions.
- This app does not authenticate users. Deploy behind a reverse proxy with
  auth if exposed beyond localhost.
