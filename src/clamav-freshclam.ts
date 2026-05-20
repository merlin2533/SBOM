// ─────────────────────────────────────────────────────────────────────────────
// Wöchentlicher freshclam-Refresh der ClamAV-Signatur-DB
//
// KEIN Daemon: der ohnehin laufende Server-Prozess plant per setInterval
// einen freshclam-Lauf. freshclam selbst ist ein One-Shot — es aktualisiert
// die DB in /var/lib/clamav und beendet sich.
//
// Ablauf: einmal kurz nach dem Start (die ins Image gebackene DB kann alt
// sein), danach wöchentlich. Schlägt ein Refresh fehl (Netzpolicy, fehlende
// Tools), bleibt die vorhandene DB unverändert — nie fatal.
// ─────────────────────────────────────────────────────────────────────────────

import { spawn } from 'child_process';
import type pino from 'pino';

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
// Erster Refresh kurz nach dem Start — verzögert, damit er nicht mit dem
// Boot (KEV/EPSS-Downloads, grype-DB) konkurriert.
const STARTUP_DELAY_MS = 60_000;
// freshclam lädt im Normalfall nur kleine Deltas; großzügiges Limit für den
// Fall eines vollständigen DB-Downloads über eine langsame Leitung.
const FRESHCLAM_TIMEOUT_MS = 600_000;

let refreshTimer: ReturnType<typeof setInterval> | null = null;

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

/** Führt freshclam einmal als One-Shot aus. Nie throw. */
function runFreshclamOnce(logger: pino.Logger): Promise<void> {
  return new Promise((resolve) => {
    const child = spawn('freshclam', ['--quiet'], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, FRESHCLAM_TIMEOUT_MS);
    child.on('exit', (code) => {
      clearTimeout(t);
      if (code === 0) {
        logger.info('[freshclam] ClamAV-Signatur-DB aktualisiert');
      } else {
        logger.warn({ code }, '[freshclam] Refresh fehlgeschlagen (nicht-fatal)');
      }
      resolve();
    });
    child.on('error', (err) => {
      clearTimeout(t);
      logger.warn({ err }, '[freshclam] konnte nicht gestartet werden (nicht-fatal)');
      resolve();
    });
  });
}

/**
 * Plant den wöchentlichen freshclam-Refresh. Tut nichts, wenn freshclam
 * nicht installiert ist. Non-blocking, nie throw.
 */
export async function scheduleFreshclam(logger: pino.Logger): Promise<void> {
  if (!(await which('freshclam'))) {
    logger.info('[freshclam] nicht installiert — ClamAV-DB-Refresh deaktiviert');
    return;
  }

  // Erster Refresh kurz nach dem Start.
  const startupTimer = setTimeout(() => { void runFreshclamOnce(logger); }, STARTUP_DELAY_MS);
  if (startupTimer.unref) startupTimer.unref();

  // Danach wöchentlich.
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { void runFreshclamOnce(logger); }, WEEK_MS);
  // Der Timer darf den Prozess nicht am Leben halten.
  if (refreshTimer.unref) refreshTimer.unref();

  logger.info('[freshclam] wöchentlicher ClamAV-DB-Refresh geplant');
}
