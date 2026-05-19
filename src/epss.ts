// ─────────────────────────────────────────────────────────────────────────────
// EPSS (Exploit Prediction Scoring System) integration
//
// Downloads the current EPSS scores CSV.GZ from Cyentia, decompresses via
// Node's built-in zlib, stores ~250k entries in a Map. Refreshes every 24h.
// Fails gracefully (empty map) on network/parse errors.
// ─────────────────────────────────────────────────────────────────────────────

import https from 'https';
import zlib from 'zlib';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import os from 'os';

const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 h

export interface EpssScore {
  score: number;
  percentile: number;
}

// In-memory state
let epssMap: Map<string, EpssScore> = new Map();
let lastFetched: number | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;

// ── Persistent cache ──────────────────────────────────────────────────────────

function cachePath(): string {
  const dir =
    process.env['EPSS_CACHE_DIR'] ??
    path.join(
      process.env['SCRATCH_DIR'] ?? path.join(os.tmpdir(), 'sbom-upload-app'),
      '_epss'
    );
  return path.join(dir, 'epss.json');
}

async function saveCache(entries: Array<[string, EpssScore]>): Promise<void> {
  try {
    const p = cachePath();
    await fsp.mkdir(path.dirname(p), { recursive: true });
    // Store as a compact JSON object {CVE: [score, pct], ...}
    const obj: Record<string, [number, number]> = {};
    for (const [id, s] of entries) {
      obj[id] = [s.score, s.percentile];
    }
    await fsp.writeFile(p, JSON.stringify(obj), 'utf8');
  } catch (_) {
    // Non-fatal
  }
}

async function loadCacheFile(): Promise<Map<string, EpssScore> | null> {
  try {
    const txt = await fsp.readFile(cachePath(), 'utf8');
    const obj = JSON.parse(txt) as Record<string, [number, number]>;
    const m = new Map<string, EpssScore>();
    for (const [id, arr] of Object.entries(obj)) {
      if (Array.isArray(arr) && arr.length === 2) {
        m.set(id, { score: arr[0] as number, percentile: arr[1] as number });
      }
    }
    return m;
  } catch {
    return null;
  }
}

// ── HTTP fetch with gunzip ────────────────────────────────────────────────────

function fetchGzipBuffer(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 60_000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`EPSS fetch HTTP ${res.statusCode}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('EPSS fetch timed out')));
    req.on('error', reject);
  });
}

// ── CSV parser ────────────────────────────────────────────────────────────────

function parseCsv(csv: string): Map<string, EpssScore> {
  const m = new Map<string, EpssScore>();
  const lines = csv.split('\n');
  // First line may be a comment (#model_version,...); second is header; data follows.
  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!.trim();
    if (l.startsWith('#')) continue;
    headerIdx = i;
    break;
  }
  if (headerIdx < 0) return m;
  // Header: cve,epss,percentile
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line) continue;
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const id = (parts[0] ?? '').trim().toUpperCase();
    const score = parseFloat(parts[1] ?? '');
    const percentile = parseFloat(parts[2] ?? '');
    if (!id || isNaN(score) || isNaN(percentile)) continue;
    m.set(id, { score, percentile });
  }
  return m;
}

// ── Fetch + parse pipeline ────────────────────────────────────────────────────

async function fetchAndParse(): Promise<Map<string, EpssScore>> {
  const buf = await fetchGzipBuffer(EPSS_URL);
  const csv = zlib.gunzipSync(buf).toString('utf8');
  return parseCsv(csv);
}

function applyMap(m: Map<string, EpssScore>): void {
  epssMap = m;
  lastFetched = Date.now();
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initial load at server start. Graceful degradation on failure.
 */
export async function loadEpss(): Promise<void> {
  try {
    const m = await fetchAndParse();
    applyMap(m);
    await saveCache([...m.entries()]);
    console.info(`[epss] loaded ${epssMap.size} scores from Cyentia`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[epss] network fetch failed (${msg}), trying disk cache`);
    const cached = await loadCacheFile();
    if (cached) {
      applyMap(cached);
      console.info(`[epss] loaded ${epssMap.size} scores from disk cache`);
    } else {
      console.warn('[epss] no disk cache available — EPSS map empty');
    }
  }

  // Schedule periodic refresh
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    fetchAndParse()
      .then(async (m) => {
        applyMap(m);
        await saveCache([...m.entries()]);
        console.info(`[epss] refreshed — ${epssMap.size} scores`);
      })
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[epss] refresh failed: ${msg}`);
      });
  }, REFRESH_INTERVAL_MS);

  if (refreshTimer.unref) refreshTimer.unref();
}

/** Returns the EPSS score+percentile for a CVE-ID, or undefined. */
export function epssFor(cveId: string): EpssScore | undefined {
  return epssMap.get(cveId.trim().toUpperCase());
}

/** How many entries are cached */
export function epssSize(): number {
  return epssMap.size;
}

/** Timestamp of last successful fetch (ms), or null */
export function epssLastFetched(): number | null {
  return lastFetched;
}

/** For testing: reset */
export function _resetEpss(): void {
  epssMap = new Map();
  lastFetched = null;
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

/** For testing: inject data */
export function _injectEpss(entries: Array<[string, EpssScore]>): void {
  epssMap = new Map(entries.map(([id, s]) => [id.toUpperCase(), s]));
}
