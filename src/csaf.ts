// ─────────────────────────────────────────────────────────────────────────────
// CSAF 2.0 Generator
//
// Erzeugt eine <base>.csaf.json aus grype-JSON-Daten.
// Format: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

interface GrypeVulnerability {
  id?: string;
  severity?: string;
  cvss?: Array<{ metrics?: { baseScore?: number }; source?: string }>;
  urls?: string[];
  dataSource?: string;
  description?: string;
}

interface GrypeArtifact {
  purl?: string;
  name?: string;
  version?: string;
  type?: string;
}

interface GrypeMatch {
  vulnerability?: GrypeVulnerability;
  artifact?: GrypeArtifact;
}

interface GrypeOutput {
  matches?: GrypeMatch[];
}

interface CsafScore {
  cvss_v3?: {
    version: string;
    baseScore: number;
    baseSeverity: string;
    vectorString: string;
  };
  products: string[];
}

interface CsafVulnerability {
  cve: string;
  notes?: Array<{ category: string; text: string }>;
  product_status?: {
    known_affected?: string[];
    under_investigation?: string[];
  };
  scores?: CsafScore[];
  references?: Array<{ category: string; summary: string; url: string }>;
}

interface CsafDocument {
  document: {
    category: string;
    csaf_version: string;
    distribution: { tlp: { label: string } };
    publisher: { category: string; name: string; namespace: string };
    title: string;
    tracking: {
      id: string;
      initial_release_date: string;
      current_release_date: string;
      version: string;
      status: string;
      revision_history: Array<{ date: string; number: string; summary: string }>;
    };
  };
  product_tree?: {
    branches?: Array<{
      category: string;
      name: string;
      branches?: Array<{
        category: string;
        name: string;
        product?: { name: string; product_id: string };
      }>;
    }>;
  };
  vulnerabilities: CsafVulnerability[];
}

export async function writeCsaf(opts: {
  grypeJsonPath: string;
  outDir: string;
  inputName: string;
  jobId: string;
  logger: pino.Logger;
}): Promise<{ csafPath: string | null }> {
  const { grypeJsonPath, outDir, inputName, jobId, logger } = opts;

  let data: GrypeOutput;
  try {
    const txt = await fsp.readFile(grypeJsonPath, 'utf8');
    data = JSON.parse(txt) as GrypeOutput;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'csaf: could not read grype JSON');
    return { csafPath: null };
  }

  const matches = data.matches ?? [];
  const now = new Date().toISOString();
  const docId = crypto.randomUUID();

  // Collect unique product IDs
  const productMap = new Map<string, { name: string; version: string; type: string }>();
  for (const m of matches) {
    const a = m.artifact ?? {};
    const productId = sanitizeProductId(a.purl ?? `${a.name ?? 'unknown'}-${a.version ?? 'unknown'}`);
    if (!productMap.has(productId)) {
      productMap.set(productId, {
        name: a.name ?? 'unknown',
        version: a.version ?? 'unknown',
        type: a.type ?? 'library',
      });
    }
  }

  // Group matches by CVE ID
  const byCve = new Map<string, GrypeMatch[]>();
  for (const m of matches) {
    const cveId = m.vulnerability?.id ?? 'UNKNOWN';
    if (!byCve.has(cveId)) byCve.set(cveId, []);
    byCve.get(cveId)!.push(m);
  }

  const vulnerabilities: CsafVulnerability[] = [];
  for (const [cveId, cveMatches] of byCve.entries()) {
    const firstMatch = cveMatches[0]!;
    const v = firstMatch.vulnerability ?? {};
    const affectedProductIds = cveMatches.map((m) => {
      const a = m.artifact ?? {};
      return sanitizeProductId(a.purl ?? `${a.name ?? 'unknown'}-${a.version ?? 'unknown'}`);
    });

    const vuln: CsafVulnerability = {
      cve: cveId,
      product_status: {
        under_investigation: affectedProductIds,
      },
    };

    if (v.description) {
      vuln.notes = [{ category: 'description', text: v.description }];
    }

    const cvssScore = v.cvss?.[0]?.metrics?.baseScore;
    if (cvssScore != null) {
      const severity = normalizeSeverityUpper(v.severity);
      vuln.scores = [{
        cvss_v3: {
          version: '3.1',
          baseScore: cvssScore,
          baseSeverity: severity,
          vectorString: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, // placeholder
        },
        products: affectedProductIds,
      }];
    }

    const urls = v.urls ?? [];
    if (urls.length > 0) {
      vuln.references = urls.slice(0, 3).map((url) => ({
        category: 'external',
        summary: cveId,
        url,
      }));
    }

    vulnerabilities.push(vuln);
  }

  // Build product tree branches from unique products
  const branches: CsafDocument['product_tree'] = {
    branches: [{
      category: 'product_name',
      name: inputName,
      branches: [...productMap.entries()].map(([pid, info]) => ({
        category: 'product_version',
        name: info.version,
        product: {
          name: `${info.name} ${info.version}`,
          product_id: pid,
        },
      })),
    }],
  };

  const doc: CsafDocument = {
    document: {
      category: 'csaf_security_advisory',
      csaf_version: '2.0',
      distribution: { tlp: { label: 'WHITE' } },
      publisher: {
        category: 'vendor',
        name: 'SBOM Upload App',
        namespace: 'https://example.org',
      },
      title: `Security advisory for ${inputName}`,
      tracking: {
        id: docId,
        initial_release_date: now,
        current_release_date: now,
        version: '1',
        status: 'draft',
        revision_history: [{
          date: now,
          number: '1',
          summary: 'Initial draft — automatically generated',
        }],
      },
    },
    product_tree: branches,
    vulnerabilities,
  };

  const base = path.basename(grypeJsonPath).replace(/\.vulnerabilities\.json$/i, '');
  const csafPath = path.join(outDir, `${base}.csaf.json`);
  await fsp.writeFile(csafPath, JSON.stringify(doc, null, 2), 'utf8');

  logger.info(
    { jobId, count: vulnerabilities.length, file: path.basename(csafPath) },
    '[csaf] geschrieben'
  );

  return { csafPath };
}

function sanitizeProductId(raw: string): string {
  // CSAF product IDs must match /^[a-zA-Z0-9_\-\.]+$/; replace anything else
  return raw.replace(/[^a-zA-Z0-9_\-\.]/g, '_').slice(0, 128);
}

function normalizeSeverityUpper(raw: string | undefined): string {
  const s = (raw ?? '').toUpperCase();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH') return 'HIGH';
  if (s === 'MEDIUM') return 'MEDIUM';
  if (s === 'LOW') return 'LOW';
  return 'NONE';
}
