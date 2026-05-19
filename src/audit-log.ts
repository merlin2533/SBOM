// ─────────────────────────────────────────────────────────────────────────────
// Audit-Log (Append-only JSONL)
//
// Schreibt strukturierte Audit-Einträge in eine JSONL-Datei.
// Default: ${SCRATCH_DIR}/audit.log, überschreibbar via AUDIT_LOG_PATH.
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import os from 'os';

export interface AuditEntry {
  ts: string;           // ISO timestamp
  event: 'job_started' | 'job_finished' | 'session_created' | 'session_destroyed';
  sid?: string;
  jobId?: string;
  inputName?: string;
  inputSize?: number;
  inputSha256?: string;
  state?: string;
  score?: number;
  grade?: string;
  vulnCounts?: { critical: number; high: number; medium: number; low: number };
  durationMs?: number;
  cacheHit?: boolean;
}

function getAuditLogPath(): string {
  if (process.env['AUDIT_LOG_PATH']) {
    return process.env['AUDIT_LOG_PATH'];
  }
  const scratchDir = process.env['SCRATCH_DIR'] ?? path.join(os.tmpdir(), 'sbom-upload-app');
  return path.join(scratchDir, 'audit.log');
}

export async function writeAuditEntry(entry: AuditEntry): Promise<void> {
  try {
    const line = JSON.stringify(entry) + '\n';
    await fsp.appendFile(getAuditLogPath(), line, { encoding: 'utf8', flag: 'a' });
  } catch (_) {
    // Non-fatal — audit logging must never crash the main flow.
  }
}
