// ─────────────────────────────────────────────────────────────────────────────
// Pre-Extraction-Schicht
//
// extract-sbom kennt nur ZIP, TAR, MSI, CAB, 7z, RAR und InstallShield-CAB.
// Allgemeine Windows-`.exe`-Installer (Inno Setup, NSIS, custom) sind dort
// nicht definiert und werden im Identify-Schritt als „Unknown" verworfen —
// extract-sbom probiert dann gar keine Tools mehr.
//
// Wir setzen dem ein freundliches Pre-Processing davor:
//   1. Wenn der Upload eine .exe ist, probieren wir `7z x` (deckt NSIS,
//      Self-extracting 7z/ZIP, MSI-Wrapper) und `innoextract` (Inno Setup).
//   2. Bei Erfolg packen wir das entpackte Verzeichnis als ZIP, das
//      extract-sbom dann ganz normal verarbeitet.
//   3. Bei Misserfolg geben wir den Original-Pfad zurück und extract-sbom
//      bekommt was es gewohnt ist.
//
// Das ZIP-Artefakt wird nach dem Job in `cleanup()` entfernt.
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

export interface PreExtractResult {
  /** Pfad, der an extract-sbom übergeben werden soll. */
  inputPath: string;
  /** Dateiname, wie er im Job-Snapshot landen soll. */
  displayName: string;
  /** true wenn wir vorher entpackt + neu gezippt haben. */
  didPreExtract: boolean;
  /** Falls didPreExtract: Wege, die `cleanup()` aufräumt. */
  tempFiles: string[];
  /** Welches Tool den Job gemacht hat — fürs Log. */
  tool: '7z' | 'innoextract' | 'none';
}

export interface PreExtractOpts {
  uploadPath: string;
  uploadName: string;
  workDir: string;        // ein leeres tmp-Verzeichnis das wir frei nutzen dürfen
  logger: pino.Logger;
  jobId: string;
}

async function runWithTimeout(
  cmd: string,
  args: string[],
  timeoutMs: number
): Promise<{ code: number; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'ignore'] });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    child.on('exit', (code, signal) => {
      clearTimeout(t);
      resolve({ code: code ?? -1, signal });
    });
    child.on('error', () => {
      clearTimeout(t);
      resolve({ code: -1, signal: null });
    });
  });
}

async function dirHasFiles(dir: string): Promise<boolean> {
  try {
    const entries = await fsp.readdir(dir);
    if (entries.length === 0) return false;
    // mindestens eine Datei (nicht nur leere Unterordner)
    for (const e of entries) {
      const full = path.join(dir, e);
      const st = await fsp.stat(full).catch(() => null);
      if (!st) continue;
      if (st.isFile() && st.size > 0) return true;
      if (st.isDirectory() && await dirHasFiles(full)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function which(cmd: string): Promise<boolean> {
  const r = await runWithTimeout('sh', ['-c', `command -v ${cmd} >/dev/null 2>&1`], 5_000);
  return r.code === 0;
}

/**
 * Versucht, eine `.exe` mit 7z bzw. innoextract zu entpacken und das
 * Ergebnis als ZIP zu repacken. Bei Erfolg landet das ZIP unter
 * `<workDir>/<basename>.unpacked.zip` und wird an extract-sbom geschickt.
 */
export async function preExtract(opts: PreExtractOpts): Promise<PreExtractResult> {
  const { uploadPath, uploadName, workDir, logger, jobId } = opts;

  const lower = uploadName.toLowerCase();
  const tryExe = lower.endsWith('.exe');
  // Wir versuchen die Pre-Extraktion nur, wenn extract-sbom das File
  // ohnehin als „Unknown" rausschmeißen würde. Heuristik: .exe ist der
  // einzige verbreitete Fall.
  if (!tryExe) {
    return {
      inputPath: uploadPath,
      displayName: uploadName,
      didPreExtract: false,
      tempFiles: [],
      tool: 'none',
    };
  }

  await fsp.mkdir(workDir, { recursive: true, mode: 0o700 });
  const stage = path.join(workDir, 'stage');
  await fsp.mkdir(stage, { recursive: true, mode: 0o700 });

  // 1. Versuch: 7z (NSIS, SFX-7z/ZIP, manche MSI-Wrapper)
  if (await which('7z')) {
    logger.info({ jobId, tool: '7z' }, 'pre-extract: trying 7z');
    const r = await runWithTimeout('7z', ['x', '-y', `-o${stage}`, uploadPath], 120_000);
    if (r.code === 0 && (await dirHasFiles(stage))) {
      const zipPath = await repackAsZip(stage, workDir, uploadName, logger, jobId);
      if (zipPath) {
        return {
          inputPath: zipPath,
          displayName: uploadName,
          didPreExtract: true,
          tempFiles: [zipPath, stage],
          tool: '7z',
        };
      }
    }
    // Stage säubern für nächsten Versuch
    await fsp.rm(stage, { recursive: true, force: true }).catch(() => {});
    await fsp.mkdir(stage, { recursive: true, mode: 0o700 });
  }

  // 2. Versuch: innoextract (Inno Setup)
  if (await which('innoextract')) {
    logger.info({ jobId, tool: 'innoextract' }, 'pre-extract: trying innoextract');
    const r = await runWithTimeout(
      'innoextract',
      ['-d', stage, '-s', '-m', '--silent', uploadPath],
      120_000
    );
    if (r.code === 0 && (await dirHasFiles(stage))) {
      const zipPath = await repackAsZip(stage, workDir, uploadName, logger, jobId);
      if (zipPath) {
        return {
          inputPath: zipPath,
          displayName: uploadName,
          didPreExtract: true,
          tempFiles: [zipPath, stage],
          tool: 'innoextract',
        };
      }
    }
    await fsp.rm(stage, { recursive: true, force: true }).catch(() => {});
  }

  // Nichts hat funktioniert — Original-Pfad weiterreichen.
  logger.info({ jobId }, 'pre-extract: no tool could open the .exe, passing through');
  await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
  return {
    inputPath: uploadPath,
    displayName: uploadName,
    didPreExtract: false,
    tempFiles: [],
    tool: 'none',
  };
}

async function repackAsZip(
  stageDir: string,
  workDir: string,
  origName: string,
  logger: pino.Logger,
  jobId: string
): Promise<string | null> {
  // Wir packen den Inhalt von stageDir in <workDir>/<basename>.unpacked.zip.
  // 7z baut das ZIP — wir wissen, dass 7z im Image ist (sonst kämen wir hier
  // gar nicht an).
  const zipName = origName.replace(/\.exe$/i, '') + '.unpacked.zip';
  const zipPath = path.join(workDir, zipName);
  // Wichtig: `cd stage && 7z a … .` nimmt nur den INHALT des Stage-Verzeichnisses
  // auf, nicht „stage/" selbst.
  const r = await new Promise<number>((resolve) => {
    const child = spawn('7z', ['a', '-tzip', '-mx=1', zipPath, '.'], {
      cwd: stageDir,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.on('exit', (code) => resolve(code ?? -1));
    child.on('error', () => resolve(-1));
  });
  if (r !== 0 || !fs.existsSync(zipPath)) {
    logger.warn({ jobId, r }, 'pre-extract: re-zipping failed');
    return null;
  }
  return zipPath;
}

export async function cleanupPreExtract(result: PreExtractResult): Promise<void> {
  for (const p of result.tempFiles) {
    await fsp.rm(p, { recursive: true, force: true }).catch(() => {});
  }
}
