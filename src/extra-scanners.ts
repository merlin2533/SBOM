// ─────────────────────────────────────────────────────────────────────────────
// Zusätzliche CVE-Scanner
//
// Führt `trivy` und `osv-scanner` auf der CycloneDX-SBOM aus und sammelt
// ergänzende Befunde. Erkennt auch bösartige Pakete (MAL-* IDs).
//
// Ausgabedateien:
//   <base>.trivy.json         — trivy-Rohdaten
//   <base>.osv.json           — osv-scanner-Rohdaten
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

// ─── Typen ───────────────────────────────────────────────────────────────────

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

export interface ExtraFinding {
  scanner: 'trivy' | 'osv-scanner';
  id: string;
  severity: Severity;
  pkg: string;
  version: string;
  fixedVersion: string | null;
  title: string;
  url: string | null;
}

export interface MaliciousPackage {
  scanner: string;
  id: string;
  pkg: string;
  version: string;
  ecosystem: string;
  summary: string;
}

export interface ExtraScanResult {
  ranTrivy: boolean;
  ranOsv: boolean;
  trivyJsonPath: string | null;
  osvJsonPath: string | null;
  findings: ExtraFinding[];
  maliciousPackages: MaliciousPackage[];
  counts: Record<Severity, number>;
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/** Prüft ob ein Kommando auf dem PATH verfügbar ist. */
function which(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn('sh', ['-c', `command -v ${cmd} >/dev/null 2>&1`], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.on('exit', (code) => resolve(code === 0));
    child.on('error', () => resolve(false));
  });
}

/** Normalisiert Severity-Strings aus verschiedenen Quellen. */
function normalizeSeverity(raw: string | undefined): Severity {
  const s = (raw ?? '').toLowerCase().trim();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'negligible' || s === 'none') return 'Negligible';
  return 'Unknown';
}

/** Leitet Severity-Stufe aus einem CVSS-Score ab. */
function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'Unknown';
}

/** Severity-Rang für Sortierung. */
function sevRank(s: Severity): number {
  const r: Record<Severity, number> = {
    Critical: 0, High: 1, Medium: 2, Low: 3, Negligible: 4, Unknown: 5,
  };
  return r[s];
}

/** Führt ein Kommando mit Timeout aus. */
function runCmd(
  cmd: string,
  args: string[],
  timeoutMs: number
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    let stderr = '';
    const child = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr?.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code: code ?? -1, stderr });
    });
    child.on('error', (e: Error) => {
      clearTimeout(t);
      resolve({ code: -1, stderr: e.message });
    });
  });
}

// ─── trivy ───────────────────────────────────────────────────────────────────

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  PrimaryURL?: string;
}

interface TrivyResult {
  Vulnerabilities?: TrivyVuln[];
}

interface TrivyDoc {
  Results?: TrivyResult[];
}

async function runTrivy(
  cdxPath: string,
  outPath: string,
  logger: pino.Logger,
  jobId: string
): Promise<ExtraFinding[]> {
  const r = await runCmd(
    'trivy',
    ['sbom', cdxPath, '--format', 'json', '--quiet', '--output', outPath],
    600_000
  );

  // trivy kann mit Exit-Code 0 laufen und die Datei trotzdem nicht anlegen
  // wenn keine Befunde da sind — defensiv prüfen
  let raw: string;
  try {
    raw = await fsp.readFile(outPath, 'utf8');
  } catch {
    if (r.code !== 0) {
      logger.warn({ jobId, code: r.code, stderr: r.stderr.slice(0, 400) }, 'trivy: Fehler beim Scan');
    }
    return [];
  }

  let doc: TrivyDoc;
  try {
    doc = JSON.parse(raw) as TrivyDoc;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'trivy: JSON konnte nicht geparst werden');
    return [];
  }

  const findings: ExtraFinding[] = [];
  for (const result of doc.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      findings.push({
        scanner: 'trivy',
        id: v.VulnerabilityID ?? 'UNKNOWN',
        severity: normalizeSeverity(v.Severity),
        pkg: v.PkgName ?? '?',
        version: v.InstalledVersion ?? '?',
        fixedVersion: v.FixedVersion ?? null,
        title: v.Title ?? '',
        url: v.PrimaryURL ?? null,
      });
    }
  }

  logger.info({ jobId, count: findings.length }, 'trivy: Scan abgeschlossen');
  return findings;
}

// ─── osv-scanner ─────────────────────────────────────────────────────────────

interface OsvPackage {
  name?: string;
  version?: string;
  ecosystem?: string;
}

interface OsvDbSpecific {
  severity?: string;
}

interface OsvGroup {
  ids?: string[];
  max_severity?: string;
}

interface OsvVuln {
  id?: string;
  summary?: string;
  aliases?: string[];
  database_specific?: OsvDbSpecific;
}

interface OsvPackageEntry {
  package?: OsvPackage;
  vulnerabilities?: OsvVuln[];
  groups?: OsvGroup[];
}

interface OsvResultEntry {
  packages?: OsvPackageEntry[];
}

interface OsvDoc {
  results?: OsvResultEntry[];
}

async function runOsv(
  cdxPath: string,
  outPath: string,
  logger: pino.Logger,
  jobId: string
): Promise<{ findings: ExtraFinding[]; malicious: MaliciousPackage[] }> {
  // osv-scanner gibt Exit-Code 1 zurück wenn Befunde da sind — das ist OK
  await runCmd(
    'osv-scanner',
    ['--sbom=' + cdxPath, '--format', 'json', '--output', outPath],
    600_000
  );

  // Prüfen ob Ausgabedatei existiert
  let raw: string;
  try {
    raw = await fsp.readFile(outPath, 'utf8');
  } catch {
    logger.warn({ jobId }, 'osv-scanner: Ausgabedatei nicht gefunden');
    return { findings: [], malicious: [] };
  }

  let doc: OsvDoc;
  try {
    doc = JSON.parse(raw) as OsvDoc;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'osv-scanner: JSON konnte nicht geparst werden');
    return { findings: [], malicious: [] };
  }

  const findings: ExtraFinding[] = [];
  const malicious: MaliciousPackage[] = [];

  for (const result of doc.results ?? []) {
    for (const pkgEntry of result.packages ?? []) {
      const pkg = pkgEntry.package ?? {};
      const pkgName = pkg.name ?? '?';
      const pkgVersion = pkg.version ?? '?';
      const pkgEco = pkg.ecosystem ?? '?';

      for (const vuln of pkgEntry.vulnerabilities ?? []) {
        const id = vuln.id ?? 'UNKNOWN';

        // Bösartige Pakete erkennen (MAL-* IDs)
        if (/^MAL-/i.test(id)) {
          malicious.push({
            scanner: 'osv-scanner',
            id,
            pkg: pkgName,
            version: pkgVersion,
            ecosystem: pkgEco,
            summary: vuln.summary ?? '',
          });
          continue;
        }

        // Severity bestimmen
        let severity: Severity = 'Unknown';
        const rawSev = vuln.database_specific?.severity;
        if (rawSev) {
          severity = normalizeSeverity(rawSev);
        } else {
          // Aus groups.max_severity (CVSS-Score als String)
          const group = pkgEntry.groups?.find((g) => g.ids?.includes(id));
          if (group?.max_severity) {
            const score = parseFloat(group.max_severity);
            if (!isNaN(score)) {
              severity = cvssToSeverity(score);
            } else {
              severity = normalizeSeverity(group.max_severity);
            }
          }
        }

        findings.push({
          scanner: 'osv-scanner',
          id,
          severity,
          pkg: pkgName,
          version: pkgVersion,
          fixedVersion: null,
          title: vuln.summary ?? '',
          url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
        });
      }
    }
  }

  logger.info(
    { jobId, findings: findings.length, malicious: malicious.length },
    'osv-scanner: Scan abgeschlossen'
  );
  return { findings, malicious };
}

// ─── Hauptexport ─────────────────────────────────────────────────────────────

/**
 * Führt trivy und osv-scanner auf der CycloneDX-SBOM aus.
 * Fehlt ein Tool, wird dessen Ergebnis weggelassen — nie throw.
 */
export async function runExtraScanners(opts: {
  cdxJsonPath: string;
  outDir: string;
  inputName: string;
  logger: pino.Logger;
  jobId: string;
}): Promise<ExtraScanResult> {
  const { cdxJsonPath, outDir, logger, jobId } = opts;

  const empty: ExtraScanResult = {
    ranTrivy: false,
    ranOsv: false,
    trivyJsonPath: null,
    osvJsonPath: null,
    findings: [],
    maliciousPackages: [],
    counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
  };

  try {
    const base = path.basename(cdxJsonPath)
      .replace(/\.cdx\.json$/i, '')
      .replace(/\.json$/i, '');

    const allFindings: ExtraFinding[] = [];
    const allMalicious: MaliciousPackage[] = [];
    let ranTrivy = false;
    let ranOsv = false;
    let trivyJsonPath: string | null = null;
    let osvJsonPath: string | null = null;

    // ── trivy ────────────────────────────────────────────────────────────────
    if (await which('trivy')) {
      const outPath = path.join(outDir, `${base}.trivy.json`);
      try {
        const findings = await runTrivy(cdxJsonPath, outPath, logger, jobId);
        allFindings.push(...findings);
        ranTrivy = true;
        trivyJsonPath = outPath;
      } catch (e) {
        logger.warn({ jobId, err: e }, 'trivy: Scan-Fehler (nicht-fatal)');
      }
    } else {
      logger.info({ jobId }, 'trivy: nicht installiert, übersprungen');
    }

    // ── osv-scanner ──────────────────────────────────────────────────────────
    if (await which('osv-scanner')) {
      const outPath = path.join(outDir, `${base}.osv.json`);
      try {
        const { findings, malicious } = await runOsv(cdxJsonPath, outPath, logger, jobId);
        allFindings.push(...findings);
        allMalicious.push(...malicious);
        ranOsv = true;
        osvJsonPath = outPath;
      } catch (e) {
        logger.warn({ jobId, err: e }, 'osv-scanner: Scan-Fehler (nicht-fatal)');
      }
    } else {
      logger.info({ jobId }, 'osv-scanner: nicht installiert, übersprungen');
    }

    // Befunde sortieren: nach Severity-Rang, dann nach ID
    allFindings.sort((a, b) => {
      const rd = sevRank(a.severity) - sevRank(b.severity);
      if (rd !== 0) return rd;
      return a.id.localeCompare(b.id);
    });

    // Zählen nach Severity
    const counts: Record<Severity, number> = {
      Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0,
    };
    for (const f of allFindings) {
      counts[f.severity]++;
    }

    return {
      ranTrivy,
      ranOsv,
      trivyJsonPath,
      osvJsonPath,
      findings: allFindings,
      maliciousPackages: allMalicious,
      counts,
    };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'extra-scanners: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
