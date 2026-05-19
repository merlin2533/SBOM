// ─────────────────────────────────────────────────────────────────────────────
// Component Catalog — in-memory cross-job component tracker
//
// After each job the pipeline upserts all components + CVEs. APIs:
//   GET /api/catalog/components
//   GET /api/catalog/components/:purl
// ─────────────────────────────────────────────────────────────────────────────

import type pino from 'pino';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface CatalogVersionEntry {
  firstSeenAt: number;
  lastSeenAt: number;
  jobs: string[];
}

export interface CatalogCveEntry {
  severity: string;
  firstSeenAt: number;
  jobs: string[];
}

export interface CatalogEntry {
  name: string;
  type: string;
  versions: Map<string, CatalogVersionEntry>;
  cveHistory: Map<string, CatalogCveEntry>;
}

// ── In-memory store ───────────────────────────────────────────────────────────
// Key: purl or "type:name" fallback
const catalog = new Map<string, CatalogEntry>();

function entryKey(comp: { purl?: string; name: string; type: string }): string {
  return comp.purl ?? `${comp.type}:${comp.name}`;
}

// ── Upsert logic ──────────────────────────────────────────────────────────────

export interface CatalogComponent {
  name: string;
  type: string;
  version?: string;
  purl?: string;
}

export interface CatalogCve {
  id: string;
  pkgName: string;
  pkgVersion: string;
  pkgType: string;
  pkgPurl?: string;
  severity: string;
}

export function upsertCatalog(opts: {
  jobId: string;
  components: CatalogComponent[];
  cves: CatalogCve[];
  logger: pino.Logger;
}): void {
  const { jobId, components, cves, logger } = opts;
  const now = Date.now();

  for (const comp of components) {
    const key = entryKey({ purl: comp.purl, name: comp.name, type: comp.type });
    let entry = catalog.get(key);
    if (!entry) {
      entry = {
        name: comp.name,
        type: comp.type,
        versions: new Map(),
        cveHistory: new Map(),
      };
      catalog.set(key, entry);
    }

    const version = comp.version ?? 'unknown';
    const ve = entry.versions.get(version);
    if (!ve) {
      entry.versions.set(version, { firstSeenAt: now, lastSeenAt: now, jobs: [jobId] });
    } else {
      ve.lastSeenAt = now;
      if (!ve.jobs.includes(jobId)) ve.jobs.push(jobId);
    }
  }

  // Upsert CVE history on the affected component's catalog entry
  for (const cve of cves) {
    const key = entryKey({ purl: cve.pkgPurl, name: cve.pkgName, type: cve.pkgType });
    const entry = catalog.get(key);
    if (!entry) continue; // component not in catalog (shouldn't happen)

    const ce = entry.cveHistory.get(cve.id);
    if (!ce) {
      entry.cveHistory.set(cve.id, { severity: cve.severity, firstSeenAt: now, jobs: [jobId] });
    } else {
      if (!ce.jobs.includes(jobId)) ce.jobs.push(jobId);
    }
  }

  logger.info({ jobId, components: components.length, cves: cves.length }, 'catalog: upserted');
}

// ── Serialization helpers ─────────────────────────────────────────────────────

function serializeEntry(key: string, entry: CatalogEntry) {
  return {
    purl: key,
    name: entry.name,
    type: entry.type,
    versionCount: entry.versions.size,
    cveCount: entry.cveHistory.size,
    versions: Object.fromEntries(
      [...entry.versions.entries()].map(([v, ve]) => [v, {
        firstSeenAt: ve.firstSeenAt,
        lastSeenAt: ve.lastSeenAt,
        jobCount: ve.jobs.length,
      }])
    ),
    cveHistory: Object.fromEntries(
      [...entry.cveHistory.entries()].map(([id, ce]) => [id, {
        severity: ce.severity,
        firstSeenAt: ce.firstSeenAt,
        jobCount: ce.jobs.length,
      }])
    ),
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/** List summary of all catalog entries */
export function listCatalog(): Array<{ purl: string; name: string; type: string; versionCount: number; cveCount: number }> {
  const out = [];
  for (const [key, entry] of catalog.entries()) {
    out.push({
      purl: key,
      name: entry.name,
      type: entry.type,
      versionCount: entry.versions.size,
      cveCount: entry.cveHistory.size,
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Full detail for a single catalog entry */
export function getCatalogEntry(purl: string): ReturnType<typeof serializeEntry> | null {
  // Accept purl directly or URL-decoded
  const key = decodeURIComponent(purl);
  const entry = catalog.get(key) ?? catalog.get(purl);
  if (!entry) return null;
  const k = catalog.get(key) ? key : purl;
  return serializeEntry(k, entry);
}

/** Register express routes for the catalog API */
export function registerCatalogRoutes(
  app: import('express').Application,
  sameOriginOnly: import('express').RequestHandler
): void {
  // GET /api/catalog/components
  app.get(
    '/api/catalog/components',
    sameOriginOnly,
    (_req: import('express').Request, res: import('express').Response) => {
      res.json(listCatalog());
    }
  );

  // GET /api/catalog/components/:purl (purl may contain slashes — catch-all)
  app.get(
    '/api/catalog/components/*',
    sameOriginOnly,
    (req: import('express').Request, res: import('express').Response) => {
      const raw = (req.params as Record<string, string>)['0'] ?? '';
      if (!raw) {
        res.json(listCatalog());
        return;
      }
      const entry = getCatalogEntry(raw);
      if (!entry) {
        res.status(404).json({ error: 'Component not found in catalog' });
        return;
      }
      res.json(entry);
    }
  );
}

/** For testing: reset catalog */
export function _resetCatalog(): void {
  catalog.clear();
}
