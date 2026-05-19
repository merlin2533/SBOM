// ─────────────────────────────────────────────────────────────────────────────
// KEV + EPSS Bedrohungs-Intelligenz-Anreicherung
//
// Lädt CISA Known Exploited Vulnerabilities (KEV) und FIRST EPSS-Daten
// und verknüpft sie mit einer Liste von CVE-IDs.
//
// KEV-Feed:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// EPSS-API:  https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY,...
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import os from 'os';
import type pino from 'pino';

// ─── Exportierte Typen ───────────────────────────────────────────────────────

export interface VulnEnrichment {
  cve: string;
  kev: boolean;
  kevDateAdded: string | null;
  kevRansomware: boolean;
  epss: number | null;
  epssPercentile: number | null;
}

export interface EnrichmentResult {
  byId: Map<string, VulnEnrichment>;
  kevAvailable: boolean;
  epssAvailable: boolean;
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/** Prüft, ob eine Cache-Datei jünger als maxAgeMs ist. */
async function isCacheFresh(filePath: string, maxAgeMs: number): Promise<boolean> {
  try {
    const st = await fsp.stat(filePath);
    return Date.now() - st.mtimeMs < maxAgeMs;
  } catch {
    return false;
  }
}

/** fetch mit AbortController-Timeout. */
async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

// ─── KEV-Laden ───────────────────────────────────────────────────────────────

interface KevEntry {
  cveID?: string;
  dateAdded?: string;
  knownRansomwareCampaignUse?: string;
}

interface KevDoc {
  vulnerabilities?: KevEntry[];
}

async function loadKev(
  cacheDir: string,
  logger: pino.Logger,
  jobId: string
): Promise<Map<string, { dateAdded: string; ransomware: boolean }> | null> {
  const cachePath = path.join(cacheDir, 'kev.json');
  const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 Stunden

  let rawJson: string | null = null;

  // Cache verwenden wenn frisch genug
  if (await isCacheFresh(cachePath, MAX_AGE_MS)) {
    try {
      rawJson = await fsp.readFile(cachePath, 'utf8');
      logger.debug({ jobId }, 'enrichment: KEV aus Cache geladen');
    } catch {
      rawJson = null;
    }
  }

  // Sonst: frisch laden
  if (!rawJson) {
    try {
      const res = await fetchWithTimeout(KEV_URL, 20_000);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      rawJson = await res.text();
      // In Cache schreiben
      try {
        await fsp.mkdir(cacheDir, { recursive: true });
        await fsp.writeFile(cachePath, rawJson, 'utf8');
      } catch (e) {
        logger.warn({ jobId, err: e }, 'enrichment: KEV-Cache konnte nicht geschrieben werden');
      }
      logger.debug({ jobId }, 'enrichment: KEV frisch von CISA geladen');
    } catch (e) {
      logger.warn({ jobId, err: e }, 'enrichment: KEV-Abruf fehlgeschlagen (nicht-fatal)');
      return null;
    }
  }

  try {
    const doc = JSON.parse(rawJson) as KevDoc;
    const map = new Map<string, { dateAdded: string; ransomware: boolean }>();
    for (const entry of doc.vulnerabilities ?? []) {
      if (!entry.cveID) continue;
      map.set(entry.cveID, {
        dateAdded: entry.dateAdded ?? '',
        ransomware: (entry.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known',
      });
    }
    return map;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'enrichment: KEV-JSON konnte nicht geparst werden');
    return null;
  }
}

// ─── EPSS-Laden ──────────────────────────────────────────────────────────────

interface EpssEntry {
  cve?: string;
  epss?: string;
  percentile?: string;
}

interface EpssDoc {
  data?: EpssEntry[];
}

async function loadEpss(
  cveIds: string[],
  logger: pino.Logger,
  jobId: string
): Promise<Map<string, { epss: number; percentile: number }> | null> {
  // Nur echte CVE-IDs (CVE-YYYY-NNNNN) anfragen
  const cvesOnly = cveIds.filter((id) => /^CVE-\d{4}-\d+$/i.test(id));
  if (cvesOnly.length === 0) return new Map();

  const EPSS_BASE = 'https://api.first.org/data/v1/epss';
  const BATCH_SIZE = 100;
  const result = new Map<string, { epss: number; percentile: number }>();

  for (let i = 0; i < cvesOnly.length; i += BATCH_SIZE) {
    const batch = cvesOnly.slice(i, i + BATCH_SIZE);
    const url = `${EPSS_BASE}?cve=${batch.join(',')}`;
    try {
      const res = await fetchWithTimeout(url, 20_000);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const doc = (await res.json()) as EpssDoc;
      for (const entry of doc.data ?? []) {
        if (!entry.cve) continue;
        const epssVal = parseFloat(entry.epss ?? '');
        const pctVal = parseFloat(entry.percentile ?? '');
        if (!isNaN(epssVal)) {
          result.set(entry.cve, {
            epss: epssVal,
            percentile: isNaN(pctVal) ? 0 : pctVal,
          });
        }
      }
    } catch (e) {
      logger.warn({ jobId, err: e, batch: batch.slice(0, 3) }, 'enrichment: EPSS-Batch-Abruf fehlgeschlagen (nicht-fatal)');
      return null;
    }
  }

  return result;
}

// ─── Hauptexport ─────────────────────────────────────────────────────────────

/**
 * Reichert eine Liste von CVE-IDs mit KEV- und EPSS-Daten an.
 * Gibt immer ein valides EnrichmentResult zurück — nie throw.
 */
export async function enrichVulnerabilities(
  cveIds: string[],
  opts: {
    logger: pino.Logger;
    jobId: string;
    offline?: boolean;
    cacheDir?: string;
  }
): Promise<EnrichmentResult> {
  const { logger, jobId, offline = false } = opts;
  const cacheDir = opts.cacheDir ?? path.join(os.tmpdir(), 'sbom-enrichment');

  const empty: EnrichmentResult = {
    byId: new Map(),
    kevAvailable: false,
    epssAvailable: false,
  };

  try {
    // Offline-Modus oder keine CVEs → direkt leer zurückgeben
    if (offline || cveIds.length === 0) {
      return empty;
    }

    // Sicherstellen, dass das Cache-Verzeichnis existiert
    try {
      await fsp.mkdir(cacheDir, { recursive: true });
    } catch {
      // Ignorieren — Fehler beim Laden wird später abgefangen
    }

    // KEV laden
    const kevMap = await loadKev(cacheDir, logger, jobId);
    const kevAvailable = kevMap !== null;

    // EPSS laden
    const epssMap = await loadEpss(cveIds, logger, jobId);
    const epssAvailable = epssMap !== null;

    // byId aufbauen — nur CVEs, die KEV und/oder EPSS-Daten haben
    const byId = new Map<string, VulnEnrichment>();
    const allIds = new Set(cveIds);

    for (const cve of allIds) {
      const kevEntry = kevMap?.get(cve);
      const epssEntry = epssMap?.get(cve);

      // Nur aufnehmen wenn mindestens eine Quelle Daten hat
      if (!kevEntry && !epssEntry) continue;

      byId.set(cve, {
        cve,
        kev: kevEntry != null,
        kevDateAdded: kevEntry?.dateAdded ?? null,
        kevRansomware: kevEntry?.ransomware ?? false,
        epss: epssEntry?.epss ?? null,
        epssPercentile: epssEntry?.percentile ?? null,
      });
    }

    logger.info(
      { jobId, kevEntries: byId.size, kevAvailable, epssAvailable },
      'enrichment: Anreicherung abgeschlossen'
    );

    return { byId, kevAvailable, epssAvailable };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'enrichment: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
