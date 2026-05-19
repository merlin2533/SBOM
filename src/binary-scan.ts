// ─────────────────────────────────────────────────────────────────────────────
// Binär-Analyse mit cve-bin-tool
//
// Läuft `cve-bin-tool` auf dem rohen Upload-Artefakt und findet CVEs in
// eingebetteten Binär-Bibliotheken (kompilierte Binärdateien, Firmware usw.)
//
// Ausgabe:
//   <base>.binary-cve.json   — Befunde inkl. CVE, Severity, Produkt, Version
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

// ─── Exportierte Typen ───────────────────────────────────────────────────────

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

export interface BinaryFinding {
  id: string;
  severity: Severity;
  product: string;
  version: string;
  source: string;
}

export interface BinaryScanResult {
  ran: boolean;
  jsonPath: string | null;
  findings: BinaryFinding[];
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

/** Normalisiert Severity-Strings aus cve-bin-tool. */
function normalizeSeverity(raw: string | undefined): Severity {
  const s = (raw ?? '').toLowerCase().trim();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'negligible' || s === 'none') return 'Negligible';
  return 'Unknown';
}

// cve-bin-tool Rohdaten-Eintrag (verteidigt gegen verschiedene Spaltennamen)
interface CveBinToolEntry {
  product?: string;
  version?: string;
  cve_number?: string;
  CVE?: string;
  severity?: string;
  Severity?: string;
  paths?: string;
  Paths?: string;
}

// ─── Hauptexport ─────────────────────────────────────────────────────────────

const EMPTY_COUNTS: Record<Severity, number> = {
  Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0,
};

/**
 * Führt cve-bin-tool auf dem Ziel-Artefakt aus.
 * Gibt immer ein valides BinaryScanResult zurück — nie throw.
 */
export async function runBinaryScan(opts: {
  target: string;
  outDir: string;
  inputName: string;
  maxBytes: number;
  logger: pino.Logger;
  jobId: string;
}): Promise<BinaryScanResult> {
  const { target, outDir, inputName, maxBytes, logger, jobId } = opts;

  const empty: BinaryScanResult = {
    ran: false,
    jsonPath: null,
    findings: [],
    counts: { ...EMPTY_COUNTS },
  };

  try {
    // cve-bin-tool prüfen
    if (!(await which('cve-bin-tool'))) {
      logger.info({ jobId }, 'binary-scan: cve-bin-tool nicht installiert, übersprungen');
      return empty;
    }

    // Dateigröße prüfen
    let fileSize: number;
    try {
      const st = await fsp.stat(target);
      fileSize = st.size;
    } catch (e) {
      logger.warn({ jobId, err: e }, 'binary-scan: Ziel-Datei nicht gefunden, übersprungen');
      return empty;
    }

    if (fileSize > maxBytes) {
      logger.info(
        { jobId, fileSize, maxBytes },
        `binary-scan: Datei zu groß (${fileSize} > ${maxBytes} Bytes), übersprungen`
      );
      return empty;
    }

    const base = path.basename(inputName).replace(/\.[^.]+$/, '');
    const tempPath = path.join(outDir, `.cve-bin-tool-raw-${Date.now()}.json`);
    const outJsonPath = path.join(outDir, `${base}.binary-cve.json`);

    // cve-bin-tool ausführen (Exit-Code != 0 wenn CVEs gefunden — nicht als Fehler werten)
    await new Promise<void>((resolve) => {
      const child = spawn(
        'cve-bin-tool',
        ['--format', 'json', '--output-file', tempPath, '--quiet', target],
        { stdio: ['ignore', 'ignore', 'ignore'] }
      );
      const t = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (_) {}
      }, 600_000);
      child.on('exit', () => { clearTimeout(t); resolve(); });
      child.on('error', () => { clearTimeout(t); resolve(); });
    });

    // Ausgabe-Datei lesen und parsen
    let rawEntries: CveBinToolEntry[] = [];
    try {
      const txt = await fsp.readFile(tempPath, 'utf8');
      const parsed = JSON.parse(txt);
      rawEntries = Array.isArray(parsed) ? parsed as CveBinToolEntry[] : [];
    } catch {
      // Keine Befunde oder Parse-Fehler — leer weiter
      rawEntries = [];
    }

    // Temp-Datei aufräumen (nur wenn verschieden vom finalen Pfad)
    if (tempPath !== outJsonPath) {
      await fsp.unlink(tempPath).catch(() => {});
    }

    // Befunde mappen
    const findings: BinaryFinding[] = rawEntries.map((entry) => {
      const id = entry.cve_number ?? entry.CVE ?? 'UNKNOWN';
      const severity = normalizeSeverity(entry.severity ?? entry.Severity);
      const source = entry.paths ?? entry.Paths ?? '';
      return {
        id,
        severity,
        product: entry.product ?? '?',
        version: entry.version ?? '?',
        source,
      };
    });

    // Zählen nach Severity
    const counts: Record<Severity, number> = { ...EMPTY_COUNTS };
    for (const f of findings) {
      counts[f.severity]++;
    }

    // Ausgabedatei schreiben
    const output = {
      tool: 'cve-bin-tool',
      generated: new Date().toISOString(),
      count: findings.length,
      findings,
    };
    await fsp.writeFile(outJsonPath, JSON.stringify(output, null, 2), 'utf8');

    logger.info(
      { jobId, count: findings.length, file: path.basename(outJsonPath) },
      `[binary-scan] ${findings.length} CVEs in Binärdateien`
    );

    return {
      ran: true,
      jsonPath: outJsonPath,
      findings,
      counts,
    };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'binary-scan: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
