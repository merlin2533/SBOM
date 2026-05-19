// ─────────────────────────────────────────────────────────────────────────────
// CISA Known Exploited Vulnerabilities (KEV) integration
//
// Loads the official KEV catalog once at startup, caches it in-memory,
// refreshes every 24 hours. Fails gracefully (empty set) on network errors.
// Persists the last-good download to disk as fallback.
// ─────────────────────────────────────────────────────────────────────────────

import https from 'https';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import os from 'os';

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 h

export interface KevDetails {
  dateAdded?: string;
  dueDate?: string;
  vendor?: string;
  product?: string;
  vulnerabilityName?: string;
  ransomwareUse?: string;
}

// In-memory state
let kevSet: Set<string> = new Set();
let kevMap: Map<string, KevDetails> = new Map();
let lastFetched: number | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;

// ── Persistent cache location ─────────────────────────────────────────────────

function cachePath(): string {
  const dir =
    process.env['KEV_CACHE_DIR'] ??
    path.join(
      process.env['SCRATCH_DIR'] ?? path.join(os.tmpdir(), 'sbom-upload-app'),
      '_kev'
    );
  return path.join(dir, 'kev.json');
}

async function saveCache(raw: unknown): Promise<void> {
  try {
    const p = cachePath();
    await fsp.mkdir(path.dirname(p), { recursive: true });
    await fsp.writeFile(p, JSON.stringify(raw), 'utf8');
  } catch (_) {
    // Non-fatal — cache save failure should never crash the process.
  }
}

async function loadCacheFile(): Promise<unknown | null> {
  try {
    const txt = await fsp.readFile(cachePath(), 'utf8');
    return JSON.parse(txt);
  } catch {
    return null;
  }
}

// ── HTTP fetch (Node stdlib only) ─────────────────────────────────────────────

function fetchJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 30_000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`KEV fetch HTTP ${res.statusCode}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (e) {
          reject(e);
        }
      });
      res.on('error', reject);
    });
    req.on('timeout', () => {
      req.destroy(new Error('KEV fetch timed out'));
    });
    req.on('error', reject);
  });
}

// ── Parse the KEV payload ─────────────────────────────────────────────────────

interface KevVulnerability {
  cveID?: string;
  dateAdded?: string;
  dueDate?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  knownRansomwareCampaignUse?: string;
}

interface KevPayload {
  vulnerabilities?: KevVulnerability[];
}

function applyPayload(raw: unknown): void {
  const payload = raw as KevPayload;
  const vulns = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];
  const newSet = new Set<string>();
  const newMap = new Map<string, KevDetails>();
  for (const v of vulns) {
    if (!v.cveID) continue;
    const id = v.cveID.trim().toUpperCase();
    newSet.add(id);
    newMap.set(id, {
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      vendor: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      ransomwareUse: v.knownRansomwareCampaignUse,
    });
  }
  kevSet = newSet;
  kevMap = newMap;
  lastFetched = Date.now();
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initial load at server start. Tries live download first; falls back to
 * persisted cache if network is unavailable. Never throws.
 */
export async function loadKev(): Promise<void> {
  try {
    const raw = await fetchJson(KEV_URL);
    applyPayload(raw);
    await saveCache(raw);
    console.info(`[kev] loaded ${kevSet.size} entries from CISA`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[kev] network fetch failed (${msg}), trying disk cache`);
    const cached = await loadCacheFile();
    if (cached) {
      applyPayload(cached);
      console.info(`[kev] loaded ${kevSet.size} entries from disk cache`);
    } else {
      console.warn('[kev] no disk cache available — KEV set empty');
    }
  }

  // Schedule periodic refresh
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    fetchJson(KEV_URL)
      .then(async (raw) => {
        applyPayload(raw);
        await saveCache(raw);
        console.info(`[kev] refreshed — ${kevSet.size} entries`);
      })
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[kev] refresh failed: ${msg}`);
      });
  }, REFRESH_INTERVAL_MS);

  // Don't keep Node alive just for the timer
  if (refreshTimer.unref) refreshTimer.unref();
}

/** Returns true when the CVE-ID is in the CISA KEV catalog. */
export function isKev(cveId: string): boolean {
  return kevSet.has(cveId.trim().toUpperCase());
}

/** Returns the KEV catalog entry for the given CVE-ID, or undefined. */
export function kevEntry(cveId: string): KevDetails | undefined {
  return kevMap.get(cveId.trim().toUpperCase());
}

/** How many entries are currently cached */
export function kevSize(): number {
  return kevSet.size;
}

/** Timestamp of last successful fetch (ms since epoch), or null */
export function kevLastFetched(): number | null {
  return lastFetched;
}

/** For testing: reset internal state */
export function _resetKev(): void {
  kevSet = new Set();
  kevMap = new Map();
  lastFetched = null;
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

/** For testing: inject data directly */
export function _injectKev(entries: Array<{ id: string; details: KevDetails }>): void {
  kevSet = new Set(entries.map((e) => e.id.toUpperCase()));
  kevMap = new Map(entries.map((e) => [e.id.toUpperCase(), e.details]));
}

/** Allow external code to read the current fs path (for tests) */
export { cachePath as kevCachePath };
