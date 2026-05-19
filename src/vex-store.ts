// ─────────────────────────────────────────────────────────────────────────────
// VEX Store — in-memory VEX entries, CycloneDX-VEX-konform
//
// API:
//   GET  /api/vex/:jobId
//   PUT  /api/vex/:jobId/:cveId
//   DELETE /api/vex/:jobId/:cveId
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

// ── CycloneDX VEX state values ────────────────────────────────────────────────
export type VexState =
  | 'in_triage'
  | 'resolved'
  | 'exploitable'
  | 'not_affected'
  | 'false_positive';

const VALID_STATES: Set<string> = new Set([
  'in_triage', 'resolved', 'exploitable', 'not_affected', 'false_positive',
]);

export interface VexEntry {
  state: VexState;
  justification?: string;
  response?: string;
  detail?: string;
  updatedAt: string;
  updatedBy: string;
}

// Key: artifactSha256 (or jobId when hash unavailable) → CVE-ID → VexEntry
const store = new Map<string, Map<string, VexEntry>>();

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Resolve the storage key for a job: prefer sha256, fall back to jobId */
function storeKey(artifactSha256: string | null, jobId: string): string {
  return artifactSha256 ?? `job:${jobId}`;
}

/** Get or create the inner map for a key */
function innerMap(key: string): Map<string, VexEntry> {
  let m = store.get(key);
  if (!m) {
    m = new Map();
    store.set(key, m);
  }
  return m;
}

// ── Public API ────────────────────────────────────────────────────────────────

export function getVexEntries(
  artifactSha256: string | null,
  jobId: string
): Record<string, VexEntry> {
  const key = storeKey(artifactSha256, jobId);
  const m = store.get(key);
  if (!m) return {};
  const out: Record<string, VexEntry> = {};
  for (const [cveId, entry] of m.entries()) {
    out[cveId] = entry;
  }
  return out;
}

export function putVexEntry(opts: {
  artifactSha256: string | null;
  jobId: string;
  cveId: string;
  state: string;
  justification?: string;
  response?: string;
  detail?: string;
  updatedBy: string;
}): { ok: boolean; error?: string } {
  if (!VALID_STATES.has(opts.state)) {
    return {
      ok: false,
      error: `Invalid state "${opts.state}". Must be one of: ${[...VALID_STATES].join(', ')}`,
    };
  }
  const key = storeKey(opts.artifactSha256, opts.jobId);
  const m = innerMap(key);
  const cveId = opts.cveId.toUpperCase();
  const entry: VexEntry = {
    state: opts.state as VexState,
    updatedAt: new Date().toISOString(),
    updatedBy: opts.updatedBy,
  };
  if (opts.justification !== undefined) entry.justification = opts.justification;
  if (opts.response !== undefined) entry.response = opts.response;
  if (opts.detail !== undefined) entry.detail = opts.detail;
  m.set(cveId, entry);
  return { ok: true };
}

export function deleteVexEntry(
  artifactSha256: string | null,
  jobId: string,
  cveId: string
): boolean {
  const key = storeKey(artifactSha256, jobId);
  const m = store.get(key);
  if (!m) return false;
  return m.delete(cveId.toUpperCase());
}

/**
 * Merges current VEX entries into an existing vex.json skeleton.
 * The skeleton is CycloneDX-VEX format with a "vulnerabilities" array.
 */
export async function mergeVexIntoFile(
  vexJsonPath: string,
  artifactSha256: string | null,
  jobId: string,
  logger: pino.Logger
): Promise<void> {
  const entries = getVexEntries(artifactSha256, jobId);
  if (Object.keys(entries).length === 0) return;

  try {
    const txt = await fsp.readFile(vexJsonPath, 'utf8');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const doc = JSON.parse(txt) as any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const vulns: any[] = Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities : [];

    for (const [cveId, entry] of Object.entries(entries)) {
      const idx = vulns.findIndex(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (v: any) => v.id === cveId || (v.ids && v.ids.some((i: any) => i.id === cveId))
      );
      if (idx >= 0) {
        // Update existing
        vulns[idx].analysis = {
          state: entry.state,
          justification: entry.justification,
          response: entry.response ? [entry.response] : undefined,
          detail: entry.detail,
        };
      } else {
        // Append new entry
        vulns.push({
          id: cveId,
          analysis: {
            state: entry.state,
            justification: entry.justification,
            response: entry.response ? [entry.response] : undefined,
            detail: entry.detail,
          },
        });
      }
    }

    doc.vulnerabilities = vulns;
    await fsp.writeFile(vexJsonPath, JSON.stringify(doc, null, 2), 'utf8');
    logger.info({ jobId, entries: Object.keys(entries).length }, 'vex-store: merged into vex.json');
  } catch (e) {
    logger.warn({ jobId, err: e }, 'vex-store: merge failed (non-fatal)');
  }
}

/** For testing: reset all entries */
export function _resetVexStore(): void {
  store.clear();
}

/** For testing: get raw store reference */
export function _getStore(): Map<string, Map<string, VexEntry>> {
  return store;
}

/** Register express routes for VEX API */
export function registerVexRoutes(
  app: import('express').Application,
  sessions: {
    iterate(): Array<{ jobs: Array<{ id: string; inputSha256: string | null; sid?: string }> }>;
  },
  logger: pino.Logger,
  sameOriginOnly: import('express').RequestHandler
): void {
  const express = require('express') as typeof import('express');
  const jsonParser = express.json({ limit: '64kb' });

  /** Resolve jobId → sha256 by searching sessions */
  function findSha256(jobId: string): string | null {
    for (const sess of sessions.iterate()) {
      const job = sess.jobs.find((j) => j.id === jobId);
      if (job) return job.inputSha256;
    }
    return null;
  }

  // GET /api/vex/:jobId
  app.get(
    '/api/vex/:jobId',
    sameOriginOnly,
    (req: import('express').Request, res: import('express').Response) => {
      const jobId = req.params['jobId'] ?? '';
      const sha256 = findSha256(jobId);
      const entries = getVexEntries(sha256, jobId);
      res.json(entries);
    }
  );

  // PUT /api/vex/:jobId/:cveId
  app.put(
    '/api/vex/:jobId/:cveId',
    sameOriginOnly,
    jsonParser,
    (req: import('express').Request, res: import('express').Response) => {
      const jobId = req.params['jobId'] ?? '';
      const cveId = req.params['cveId'] ?? '';
      const sha256 = findSha256(jobId);
      const body = req.body as {
        state?: string;
        justification?: string;
        response?: string;
        detail?: string;
      };

      if (!body.state) {
        res.status(400).json({ error: 'state is required' });
        return;
      }

      // Use sid prefix as updatedBy if available
      const sidCookie = req.cookies?.['sid'] as string | undefined;
      const updatedBy = sidCookie ? sidCookie.slice(0, 8) : 'api';

      const result = putVexEntry({
        artifactSha256: sha256,
        jobId,
        cveId,
        state: body.state,
        justification: body.justification,
        response: body.response,
        detail: body.detail,
        updatedBy,
      });

      if (!result.ok) {
        res.status(400).json({ error: result.error });
        return;
      }

      logger.info({ jobId, cveId, state: body.state }, 'vex: entry updated');
      res.json({ ok: true });
    }
  );

  // DELETE /api/vex/:jobId/:cveId
  app.delete(
    '/api/vex/:jobId/:cveId',
    sameOriginOnly,
    (req: import('express').Request, res: import('express').Response) => {
      const jobId = req.params['jobId'] ?? '';
      const cveId = req.params['cveId'] ?? '';
      const sha256 = findSha256(jobId);
      const deleted = deleteVexEntry(sha256, jobId, cveId);
      if (!deleted) {
        res.status(404).json({ error: 'VEX entry not found' });
        return;
      }
      logger.info({ jobId, cveId }, 'vex: entry deleted');
      res.json({ ok: true });
    }
  );
}
