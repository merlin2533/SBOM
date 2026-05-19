// ─────────────────────────────────────────────────────────────────────────────
// Secret-Scanner (gitleaks)
//
// Läuft `gitleaks` über ein Verzeichnis und erzeugt eine REDACTED
// Befundliste — der Originalwert eines gefundenen Secrets wird NIEMALS
// in eine Ausgabedatei oder Log-Zeile geschrieben.
//
// Ausgabe:
//   <base>.secrets.json   — bereinigte Fundstellen (nur maskierte Vorschau)
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';
import { shredUnlink } from './shred';

// ─── Exportierte Typen ───────────────────────────────────────────────────────

export interface SecretFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
  /** Bereinigte Vorschau — NIEMALS der echte Wert */
  preview: string;
  entropy: number | null;
}

export interface SecretScanResult {
  ran: boolean;
  jsonPath: string | null;
  findings: SecretFinding[];
  count: number;
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

/**
 * Maskiert einen Secret-Wert: erste 3 Zeichen + "…(N Zeichen)".
 * NIEMALS den vollständigen Wert zurückgeben.
 */
export function redactSecret(secret: string): string {
  if (!secret) return '(leer)';
  const preview = secret.slice(0, 3);
  return `${preview}…(${secret.length} Zeichen)`;
}

// gitleaks-Rohdaten-Eintrag
interface GitleaksRawEntry {
  Description?: string;
  StartLine?: number;
  File?: string;
  RuleID?: string;
  Match?: string;
  Secret?: string;
  Entropy?: number;
}

// ─── Hauptexport ─────────────────────────────────────────────────────────────

/**
 * Führt gitleaks über scanDir aus und gibt bereinigte Befunde zurück.
 * Gibt immer ein valides SecretScanResult zurück — nie throw.
 */
export async function runSecretScan(opts: {
  scanDir: string;
  outDir: string;
  inputName: string;
  logger: pino.Logger;
  jobId: string;
}): Promise<SecretScanResult> {
  const { scanDir, outDir, inputName, logger, jobId } = opts;

  const empty: SecretScanResult = { ran: false, jsonPath: null, findings: [], count: 0 };

  try {
    // gitleaks prüfen
    if (!(await which('gitleaks'))) {
      logger.info({ jobId }, 'secret-scan: gitleaks nicht installiert, übersprungen');
      return empty;
    }

    // Verzeichnis existiert?
    try {
      await fsp.stat(scanDir);
    } catch {
      logger.info({ jobId, scanDir }, 'secret-scan: Scan-Verzeichnis fehlt, übersprungen');
      return empty;
    }

    const base = path.basename(inputName).replace(/\.[^.]+$/, '');
    const tempPath = path.join(outDir, '.gitleaks-raw.json');
    const outJsonPath = path.join(outDir, `${base}.secrets.json`);

    // gitleaks ausführen — exit-code 0 erzwingen (sonst Exit-Code 1 bei Befunden)
    await new Promise<void>((resolve) => {
      const child = spawn(
        'gitleaks',
        ['dir', scanDir, '--no-banner', '--report-format', 'json', '--report-path', tempPath, '--exit-code', '0'],
        { stdio: ['ignore', 'ignore', 'ignore'] }
      );
      const t = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (_) {}
      }, 300_000);
      child.on('exit', () => { clearTimeout(t); resolve(); });
      child.on('error', () => { clearTimeout(t); resolve(); });
    });

    // Rohdaten lesen (könnten fehlen wenn gitleaks abstürzt)
    let rawEntries: GitleaksRawEntry[] = [];
    try {
      const txt = await fsp.readFile(tempPath, 'utf8');
      rawEntries = JSON.parse(txt) as GitleaksRawEntry[];
      if (!Array.isArray(rawEntries)) rawEntries = [];
    } catch {
      // Keine Befunde oder Parse-Fehler — leer weiter
      rawEntries = [];
    }

    // Rohdatei SCHREDDERN — enthält möglicherweise echte Secret-Werte
    await shredUnlink(tempPath);

    // Bereinigte Befunde erstellen — NIEMALS den echten Secret-Wert aufnehmen
    const findings: SecretFinding[] = rawEntries.map((entry) => {
      const rawSecret = entry.Secret ?? entry.Match ?? '';
      return {
        rule: entry.RuleID ?? 'unknown',
        description: entry.Description ?? '',
        // Pfad relativ zu scanDir
        file: entry.File
          ? path.relative(scanDir, entry.File).replace(/\\/g, '/')
          : '?',
        line: entry.StartLine ?? 0,
        // MASKIEREN — nur Vorschau, nie der echte Wert
        preview: redactSecret(rawSecret),
        entropy: typeof entry.Entropy === 'number' ? entry.Entropy : null,
      };
    });

    // Bereinigte Ausgabedatei schreiben
    const output = {
      tool: 'gitleaks',
      generated: new Date().toISOString(),
      count: findings.length,
      findings,
    };
    await fsp.writeFile(outJsonPath, JSON.stringify(output, null, 2), 'utf8');

    logger.info(
      { jobId, count: findings.length, file: path.basename(outJsonPath) },
      `[secret-scan] ${findings.length} Secret-Funde`
    );

    return {
      ran: true,
      jsonPath: outJsonPath,
      findings,
      count: findings.length,
    };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'secret-scan: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
