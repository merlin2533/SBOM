// ─────────────────────────────────────────────────────────────────────────────
// OpenVEX 0.2.0 Generator
//
// Erzeugt eine <base>.openvex.json aus grype-JSON-Daten.
// Format: https://github.com/openvex/spec
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

interface GrypeVulnerability {
  id?: string;
  urls?: string[];
  dataSource?: string;
}

interface GrypeArtifact {
  purl?: string;
  name?: string;
  version?: string;
}

interface GrypeMatch {
  vulnerability?: GrypeVulnerability;
  artifact?: GrypeArtifact;
}

interface GrypeOutput {
  matches?: GrypeMatch[];
}

interface OpenVexStatement {
  vulnerability: { name: string; '@id': string };
  products: Array<{ '@id': string }>;
  status: string;
  status_notes?: string;
}

interface OpenVexDocument {
  '@context': string;
  '@id': string;
  author: string;
  timestamp: string;
  version: number;
  statements: OpenVexStatement[];
}

export async function writeOpenVex(opts: {
  grypeJsonPath: string;
  outDir: string;
  inputName: string;
  jobId: string;
  logger: pino.Logger;
}): Promise<{ vexPath: string | null }> {
  const { grypeJsonPath, outDir, inputName, jobId, logger } = opts;

  let data: GrypeOutput;
  try {
    const txt = await fsp.readFile(grypeJsonPath, 'utf8');
    data = JSON.parse(txt) as GrypeOutput;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'openvex: could not read grype JSON');
    return { vexPath: null };
  }

  const matches = data.matches ?? [];
  const timestamp = new Date().toISOString();
  const docId = `https://openvex.dev/docs/${crypto.randomUUID()}`;

  const statements: OpenVexStatement[] = matches.map((m) => {
    const v = m.vulnerability ?? {};
    const a = m.artifact ?? {};
    const cveId = v.id ?? 'UNKNOWN';
    const nvdUrl = (v.urls ?? []).find((u) => /nvd\.nist\.gov/i.test(u))
      ?? v.dataSource
      ?? `https://nvd.nist.gov/vuln/detail/${cveId}`;
    const productId = a.purl ?? `pkg:generic/${encodeURIComponent(a.name ?? inputName)}@${encodeURIComponent(a.version ?? 'unknown')}`;

    return {
      vulnerability: {
        name: cveId,
        '@id': nvdUrl,
      },
      products: [{ '@id': productId }],
      status: 'under_investigation',
      status_notes: `Automatically generated skeleton for ${inputName} — please update status after triage.`,
    };
  });

  const doc: OpenVexDocument = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': docId,
    author: 'SBOM Upload App',
    timestamp,
    version: 1,
    statements,
  };

  const base = path.basename(grypeJsonPath).replace(/\.vulnerabilities\.json$/i, '');
  const vexPath = path.join(outDir, `${base}.openvex.json`);
  await fsp.writeFile(vexPath, JSON.stringify(doc, null, 2), 'utf8');

  logger.info(
    { jobId, count: statements.length, file: path.basename(vexPath) },
    '[openvex] geschrieben'
  );

  return { vexPath };
}
