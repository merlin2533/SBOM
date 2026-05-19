import { mkdtempSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createApp } from '../src/app';
import type { ServerConfig } from '../src/types';

export function makeFakeExtractSbom(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-test-bin-'));
  const path = join(dir, 'fake-extract-sbom.sh');
  const script = `#!/bin/bash
OUTDIR=""
INPUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir) OUTDIR="$2"; shift 2;;
    --password-file) shift 2;;
    --*) shift;;
    *) INPUT="$1"; shift;;
  esac
done
mkdir -p "$OUTDIR"
echo "starting extraction"
echo "extracting archives"
echo '{"bomFormat":"CycloneDX"}' > "$OUTDIR/$(basename "$INPUT").cdx.json"
echo "cataloging components"
echo "# Audit Report" > "$OUTDIR/$(basename "$INPUT").report.md"
echo "done"
exit 0
`;
  writeFileSync(path, script, { mode: 0o755 });
  return path;
}

export function makeSpyExtractSbom(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-test-bin-'));
  const path = join(dir, 'spy-extract-sbom.sh');
  const script = `#!/bin/bash
OUTDIR=""; INPUT=""; PWFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir) OUTDIR="$2"; shift 2;;
    --password-file) PWFILE="$2"; shift 2;;
    --*) shift;;
    *) INPUT="$1"; shift;;
  esac
done
mkdir -p "$OUTDIR"
echo "env=\${EXTRACT_SBOM_PASSWORDS:-}" > "$OUTDIR/spy.txt"
echo "pwfile=\${PWFILE}" >> "$OUTDIR/spy.txt"
if [ -n "$PWFILE" ] && [ -f "$PWFILE" ]; then
  echo "pwfile_contents:" >> "$OUTDIR/spy.txt"
  cat "$PWFILE" >> "$OUTDIR/spy.txt"
fi
echo "done"
exit 0
`;
  writeFileSync(path, script, { mode: 0o755 });
  return path;
}

export function makeSleepyExtractSbom(sleepSecs: number = 30): string {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-test-bin-'));
  const path = join(dir, 'sleepy-extract-sbom.sh');
  const script = `#!/bin/bash
OUTDIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir) OUTDIR="$2"; shift 2;;
    --*) shift;;
    *) shift;;
  esac
done
mkdir -p "$OUTDIR"
sleep ${sleepSecs}
exit 0
`;
  writeFileSync(path, script, { mode: 0o755 });
  return path;
}

export function makeApp(overrides: Partial<ServerConfig> = {}) {
  const scratch = mkdtempSync(join(tmpdir(), 'sbom-test-scratch-'));
  const bin = overrides.extractSbomBin ?? makeFakeExtractSbom();
  const config: ServerConfig = {
    port: 0,
    host: '127.0.0.1',
    maxUploadBytes: 100 * 1024 * 1024,
    extractSbomBin: bin,
    extraArgs: [],
    scratchDir: scratch,
    maxLogLines: 200,
    sessionIdleMs: 60_000,
    uploadRatePerMin: 100,
    trustProxy: false,
    authUser: null,
    authPass: null,
    shutdownGraceMs: 2_000,
    logLevel: 'silent',
    logPretty: false,
    sandboxMode: 'none',
    ...overrides,
  };
  return createApp(config);
}

/**
 * Write a fake artifact file into the session's upload dir and set the
 * session's pendingUpload fields so POST /api/jobs can be used directly
 * without going through the TUS protocol.
 */
export function injectPendingUpload(
  sess: import('../src/types').Session,
  filename: string = 'test.zip',
  content: string = 'fake zip content'
): void {
  const uploadDir = join(sess.dir, 'upload');
  mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
  const filePath = join(uploadDir, filename);
  writeFileSync(filePath, content);
  sess.pendingUploadId = 'fake-upload-id';
  sess.pendingUploadPath = filePath;
  sess.pendingUploadName = filename;
  sess.pendingUploadSize = Buffer.byteLength(content);
}

/** Poll until predicate returns true, or timeout. */
export async function waitFor(
  predicate: () => boolean,
  timeoutMs: number = 5000,
  intervalMs: number = 50
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('waitFor: timed out');
}
