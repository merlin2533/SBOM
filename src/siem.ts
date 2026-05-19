// ─────────────────────────────────────────────────────────────────────────────
// SIEM Export — JSONL + CEF output
//
// Generates two files per job:
//   <base>.findings.json  — JSONL, one finding per line
//   <base>.findings.cef   — Common Event Format (Splunk/ArcSight)
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

// ── Types ─────────────────────────────────────────────────────────────────────

export type FindingType = 'cve' | 'eol' | 'typosquat';

export interface SiemFinding {
  timestamp: string;
  artifact: string;
  artifactSha256: string | null;
  jobId: string;
  type: FindingType;
  severity: string;
  id: string;
  package: string;
  version: string;
  epss?: number;
  epssPercentile?: number;
  isKev?: boolean;
  fixVersion?: string;
  description?: string;
}

export interface SiemOpts {
  outDir: string;
  inputName: string;
  inputSha256: string | null;
  jobId: string;
  findings: SiemFinding[];
  logger: pino.Logger;
}

export interface SiemResult {
  jsonlPath: string | null;
  cefPath: string | null;
  findingCount: number;
}

// ── CEF formatting ────────────────────────────────────────────────────────────

const CEF_VERSION = '0';
const CEF_DEVICE_VENDOR = 'SBOM Upload App';
const CEF_DEVICE_PRODUCT = 'sbom-upload';
const CEF_DEVICE_VERSION = '2.10';

/** CEF severity: string map to 0-10 integer */
function cefSeverity(severity: string): number {
  const s = severity.toLowerCase();
  if (s === 'critical') return 10;
  if (s === 'high') return 8;
  if (s === 'medium') return 5;
  if (s === 'low') return 2;
  if (s === 'eol') return 6;
  if (s === 'typosquat') return 7;
  return 1;
}

/** Escape CEF header fields (pipe, backslash) */
function cefEscHeader(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Escape CEF extension values (=, \n, backslash) */
function cefEscValue(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\n/g, '\\n').replace(/\r/g, '');
}

function buildCefLine(finding: SiemFinding): string {
  const name = cefEscHeader(`${finding.type.toUpperCase()}:${finding.id}`);
  const sev = cefSeverity(finding.severity);
  const ext: string[] = [
    `start=${cefEscValue(finding.timestamp)}`,
    `deviceCustomString1=${cefEscValue(finding.artifact)}`,
    `deviceCustomString1Label=artifact`,
    `deviceCustomString2=${cefEscValue(finding.jobId)}`,
    `deviceCustomString2Label=jobId`,
    `deviceCustomString3=${cefEscValue(finding.package)}`,
    `deviceCustomString3Label=package`,
    `deviceCustomString4=${cefEscValue(finding.version)}`,
    `deviceCustomString4Label=version`,
    `msg=${cefEscValue(finding.id)}`,
    `cat=${cefEscValue(finding.type)}`,
    `severity=${cefEscValue(finding.severity)}`,
  ];
  if (finding.artifactSha256) {
    ext.push(`fileHash=${cefEscValue(finding.artifactSha256)}`);
  }
  if (finding.isKev) {
    ext.push(`deviceCustomString5=true`, `deviceCustomString5Label=isKev`);
  }
  if (finding.epss !== undefined) {
    ext.push(`deviceCustomFloatingPoint1=${finding.epss.toFixed(4)}`, `deviceCustomFloatingPoint1Label=epss`);
  }
  if (finding.fixVersion) {
    ext.push(`deviceCustomString6=${cefEscValue(finding.fixVersion)}`, `deviceCustomString6Label=fixVersion`);
  }
  if (finding.description) {
    ext.push(`reason=${cefEscValue(finding.description.slice(0, 512))}`);
  }

  return [
    `CEF:${CEF_VERSION}`,
    cefEscHeader(CEF_DEVICE_VENDOR),
    cefEscHeader(CEF_DEVICE_PRODUCT),
    cefEscHeader(CEF_DEVICE_VERSION),
    cefEscHeader(finding.id),
    name,
    String(sev),
    ext.join(' '),
  ].join('|');
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function writeSiemExport(opts: SiemOpts): Promise<SiemResult> {
  const { outDir, inputName, jobId, findings, logger } = opts;

  if (findings.length === 0) {
    return { jsonlPath: null, cefPath: null, findingCount: 0 };
  }

  const base = path.basename(inputName, path.extname(inputName));
  const jsonlPath = path.join(outDir, `${base}.findings.json`);
  const cefPath = path.join(outDir, `${base}.findings.cef`);

  try {
    const jsonlLines = findings.map((f) => JSON.stringify(f)).join('\n') + '\n';
    await fsp.writeFile(jsonlPath, jsonlLines, 'utf8');

    const cefLines = findings.map(buildCefLine).join('\n') + '\n';
    await fsp.writeFile(cefPath, cefLines, 'utf8');

    logger.info({ jobId, findings: findings.length, jsonl: path.basename(jsonlPath) }, 'siem: exported');
    return { jsonlPath, cefPath, findingCount: findings.length };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'siem: export failed (non-fatal)');
    return { jsonlPath: null, cefPath: null, findingCount: 0 };
  }
}

/** Build SIEM findings from job data (helper to assemble input) */
export function buildFindings(opts: {
  timestamp: string;
  artifact: string;
  artifactSha256: string | null;
  jobId: string;
  vulnMatches: Array<{
    id: string;
    severity: string;
    pkgName: string;
    pkgVersion: string;
    isKev: boolean;
    epss?: number;
    epssPercentile?: number;
    fixVersion?: string;
    description?: string;
  }>;
  eolHits: Array<{
    name: string;
    version: string;
    eolDate: string;
    isExpired: boolean;
  }>;
  typosquatHits: Array<{
    name: string;
    suspiciousOf: string;
    distance: number;
  }>;
}): SiemFinding[] {
  const findings: SiemFinding[] = [];
  const ts = opts.timestamp;

  for (const v of opts.vulnMatches) {
    const f: SiemFinding = {
      timestamp: ts,
      artifact: opts.artifact,
      artifactSha256: opts.artifactSha256,
      jobId: opts.jobId,
      type: 'cve',
      severity: v.severity,
      id: v.id,
      package: v.pkgName,
      version: v.pkgVersion,
      isKev: v.isKev,
    };
    if (v.epss !== undefined) f.epss = v.epss;
    if (v.epssPercentile !== undefined) f.epssPercentile = v.epssPercentile;
    if (v.fixVersion) f.fixVersion = v.fixVersion;
    if (v.description) f.description = v.description.slice(0, 512);
    findings.push(f);
  }

  for (const e of opts.eolHits) {
    findings.push({
      timestamp: ts,
      artifact: opts.artifact,
      artifactSha256: opts.artifactSha256,
      jobId: opts.jobId,
      type: 'eol',
      severity: e.isExpired ? 'Critical' : 'Medium',
      id: `EOL:${e.name}@${e.version}`,
      package: e.name,
      version: e.version,
      description: `End of life: ${e.eolDate}`,
    });
  }

  for (const t of opts.typosquatHits) {
    findings.push({
      timestamp: ts,
      artifact: opts.artifact,
      artifactSha256: opts.artifactSha256,
      jobId: opts.jobId,
      type: 'typosquat',
      severity: 'High',
      id: `TYPOSQUAT:${t.name}`,
      package: t.name,
      version: '?',
      description: `Possible typosquat of "${t.suspiciousOf}" (Levenshtein=${t.distance})`,
    });
  }

  return findings;
}
