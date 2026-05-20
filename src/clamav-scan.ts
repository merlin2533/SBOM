// ─────────────────────────────────────────────────────────────────────────────
// Malware-Scan mit ClamAV (clamscan)
//
// `clamscan` läuft als One-Shot-Prozess: pro Job gestartet, beendet sich nach
// dem Scan von selbst — es läuft KEIN dauerhafter clamd-Daemon. clamscan
// entpackt Archive selbst und hat eingebaute Decompression-Bomb-Limits
// (--max-filesize / --max-scansize / --max-recursion / --max-files).
//
// Ausgabe:
//   <base>.clamav.json   — infizierte Dateien inkl. Signaturname
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

// ─── Exportierte Typen ───────────────────────────────────────────────────────

export interface ClamFinding {
  file: string;       // Datei/Eintrag, in dem der Treffer lag
  signature: string;  // ClamAV-Signaturname
}

export interface ClamScanResult {
  ran: boolean;
  jsonPath: string | null;
  infectedCount: number;
  findings: ClamFinding[];
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

// ─── Hauptexport ─────────────────────────────────────────────────────────────

/**
 * Führt clamscan auf dem Ziel-Artefakt aus.
 * Gibt immer ein valides ClamScanResult zurück — nie throw.
 */
export async function runClamScan(opts: {
  target: string;
  outDir: string;
  inputName: string;
  maxBytes: number;
  logger: pino.Logger;
  jobId: string;
}): Promise<ClamScanResult> {
  const { target, outDir, inputName, maxBytes, logger, jobId } = opts;

  const empty: ClamScanResult = {
    ran: false, jsonPath: null, infectedCount: 0, findings: [],
  };

  try {
    // clamscan prüfen
    if (!(await which('clamscan'))) {
      logger.info({ jobId }, 'clamav-scan: clamscan nicht installiert, übersprungen');
      return empty;
    }

    // Dateigröße prüfen
    let fileSize: number;
    try {
      fileSize = (await fsp.stat(target)).size;
    } catch (e) {
      logger.warn({ jobId, err: e }, 'clamav-scan: Ziel-Datei nicht gefunden, übersprungen');
      return empty;
    }
    if (fileSize > maxBytes) {
      logger.info(
        { jobId, fileSize, maxBytes },
        `clamav-scan: Datei zu groß (${fileSize} > ${maxBytes} Bytes), übersprungen`
      );
      return empty;
    }

    // clamscan ausführen. Exit-Codes: 0 = sauber, 1 = Malware gefunden,
    // 2 = Fehler. Befund-Zeilen auf stdout: "<datei>: <signatur> FOUND".
    const maxArg = String(Math.max(maxBytes, 1));
    let stdout = '';
    const exitCode = await new Promise<number | null>((resolve) => {
      const child = spawn('clamscan', [
        '--infected',
        '--no-summary',
        '--recursive',
        '--stdout',
        `--max-filesize=${maxArg}`,
        `--max-scansize=${maxArg}`,
        target,
      ], { stdio: ['ignore', 'pipe', 'ignore'] });
      child.stdout.on('data', (b: Buffer) => {
        stdout += b.toString('utf8');
        // Ausgabe begrenzen — ein Archiv mit Unmengen Treffern darf den
        // Speicher nicht sprengen.
        if (stdout.length > 8 * 1024 * 1024) { try { child.kill('SIGKILL'); } catch (_) {} }
      });
      const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, 600_000);
      child.on('exit', (code) => { clearTimeout(t); resolve(code); });
      child.on('error', () => { clearTimeout(t); resolve(null); });
    });

    // Exit 2 / null = clamscan-Fehler — häufigste Ursache: keine Signatur-DB
    // (freshclam nie gelaufen). Graceful als "nicht gelaufen" werten.
    if (exitCode === 2 || exitCode === null) {
      logger.warn(
        { jobId, exitCode },
        'clamav-scan: clamscan-Fehler (evtl. fehlende Signatur-DB), übersprungen'
      );
      return empty;
    }

    // Den absoluten Upload-Pfad in der Ausgabe durch den Artefaktnamen
    // ersetzen — keine internen Scratch-Pfade in den Bericht durchreichen.
    const baseName = path.basename(target);
    const displayFile = (raw: string): string => {
      if (raw === target) return baseName;
      if (raw.startsWith(target)) return baseName + raw.slice(target.length);
      return path.basename(raw);
    };

    // stdout parsen: Zeilen "<datei>: <signatur> FOUND"
    const findings: ClamFinding[] = [];
    for (const line of stdout.split('\n')) {
      const m = line.match(/^(.*): (.+) FOUND$/);
      if (m) {
        findings.push({ file: displayFile(m[1]!.trim()), signature: m[2]!.trim() });
      }
    }

    // Ausgabedatei schreiben
    const base = path.basename(inputName).replace(/\.[^.]+$/, '');
    const outJsonPath = path.join(outDir, `${base}.clamav.json`);
    const output = {
      tool: 'clamav (clamscan)',
      generated: new Date().toISOString(),
      infectedCount: findings.length,
      findings,
    };
    await fsp.writeFile(outJsonPath, JSON.stringify(output, null, 2), 'utf8');

    logger.info(
      { jobId, infectedCount: findings.length, file: path.basename(outJsonPath) },
      `[clamav-scan] ${findings.length} Malware-Treffer`
    );

    return {
      ran: true,
      jsonPath: outJsonPath,
      infectedCount: findings.length,
      findings,
    };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'clamav-scan: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
