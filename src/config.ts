import os from 'os';
import path from 'path';
import type { ServerConfig, SandboxMode } from './types';

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const port = parseInt(env['PORT'] ?? '3000', 10);
  const host = env['HOST'] ?? '0.0.0.0';
  const maxUploadBytes = parseInt(
    env['MAX_UPLOAD_BYTES'] ?? String(5 * 1024 * 1024 * 1024),
    10
  );
  const extractSbomBin = env['EXTRACT_SBOM_BIN'] ?? 'extract-sbom';
  const extraArgs = (env['EXTRACT_SBOM_ARGS'] ?? '').split(/\s+/).filter(Boolean);
  const scratchDir =
    env['SCRATCH_DIR'] ?? path.join(os.tmpdir(), 'sbom-upload-app');
  const maxLogLines = parseInt(env['MAX_LOG_LINES'] ?? '2000', 10);
  const sessionIdleMs = parseInt(
    env['SESSION_IDLE_MS'] ?? String(30 * 60 * 1000),
    10
  );
  const uploadRatePerMin = parseInt(env['UPLOAD_RATE_PER_MIN'] ?? '5', 10);
  const trustProxy = env['TRUST_PROXY'] === '1';
  const authUser = env['AUTH_USER'] ?? null;
  const authPass = env['AUTH_PASS'] ?? null;

  // New in v2:
  const shutdownGraceMs = parseInt(env['SHUTDOWN_GRACE_MS'] ?? '30000', 10);
  const logLevel = env['LOG_LEVEL'] ?? 'info';
  // Default to pretty-print in TTY environments (dev); JSON in production.
  const logPrettyEnv = env['LOG_PRETTY'];
  const logPretty =
    logPrettyEnv !== undefined
      ? logPrettyEnv === '1' || logPrettyEnv === 'true'
      : process.stdout.isTTY === true;

  const sandboxModeRaw = env['SANDBOX_MODE'] ?? 'auto';
  const sandboxMode: SandboxMode =
    sandboxModeRaw === 'bwrap' ||
    sandboxModeRaw === 'firejail' ||
    sandboxModeRaw === 'none' ||
    sandboxModeRaw === 'auto'
      ? (sandboxModeRaw as SandboxMode)
      : 'auto';

  // Anreicherungs-Konfiguration (KEV + EPSS)
  const enrichmentOffline = env['ENRICHMENT_OFFLINE'] === '1';
  const enrichmentCacheDir =
    env['ENRICHMENT_CACHE_DIR'] ?? path.join(os.tmpdir(), 'sbom-enrichment');

  // Größen-Limits für Binär- und Secret-Scan
  const binaryScanMaxBytes = parseInt(
    env['BINARY_SCAN_MAX_BYTES'] ?? String(2 * 1024 * 1024 * 1024),
    10
  );
  const secretScanMaxBytes = parseInt(
    env['SECRET_SCAN_MAX_BYTES'] ?? String(1 * 1024 * 1024 * 1024),
    10
  );

  return {
    port,
    host,
    maxUploadBytes,
    extractSbomBin,
    extraArgs,
    scratchDir,
    maxLogLines,
    sessionIdleMs,
    uploadRatePerMin,
    trustProxy,
    authUser: authUser || null,
    authPass: authPass || null,
    shutdownGraceMs,
    logLevel,
    logPretty,
    sandboxMode,
    enrichmentOffline,
    enrichmentCacheDir,
    binaryScanMaxBytes,
    secretScanMaxBytes,
  };
}
