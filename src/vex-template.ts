// ─────────────────────────────────────────────────────────────────────────────
// VEX-Skelett-Generator (CycloneDX VEX 1.6)
//
// Erzeugt eine <base>.vex.json neben dem grype-JSON. Jeder CVE-Treffer wird
// als VEX-Eintrag mit state "in_triage" angelegt — die Felder sind bewusst
// leer gehalten, damit das Security-Team sie befüllen kann.
//
// Wie das VEX befüllt wird:
//   "state": eines von in_triage | exploitable | in_scope | not_affected | fixed
//   "justification": z.B. "code_not_reachable" | "vulnerable_code_not_in_execute_path" | …
//   "response": z.B. ["will_not_fix"] | ["update"] | []
//   "detail": freier Text mit Begründung / Ticket-Link
//
// Spec: https://github.com/CycloneDX/bom-examples/tree/master/VEX
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

interface GrypeVulnerability {
  id?: string;
  severity?: string;
  urls?: string[];
  dataSource?: string;
}

interface GrypeArtifact {
  purl?: string;
}

interface GrypeMatch {
  vulnerability?: GrypeVulnerability;
  artifact?: GrypeArtifact;
}

interface GrypeOutput {
  matches?: GrypeMatch[];
}

interface VexRating {
  severity: string;
}

interface VexAnalysis {
  state: string;
  justification: string;
  response: string[];
  detail: string;
}

interface VexVulnerability {
  id: string;
  source: { name: string; url: string };
  ratings: VexRating[];
  affects: Array<{ ref: string }>;
  analysis: VexAnalysis;
}

interface VexDocument {
  _comment: string;
  bomFormat: string;
  specVersion: string;
  version: number;
  metadata: {
    timestamp: string;
    component: { name: string; type: string };
  };
  vulnerabilities: VexVulnerability[];
}

function sourceName(urls: string[]): string {
  const first = urls[0] ?? '';
  if (/github\.com\/advisories|ghsa/i.test(first)) return 'GHSA';
  if (/nvd\.nist\.gov/i.test(first)) return 'NVD';
  if (/osv\.dev/i.test(first)) return 'OSV';
  return 'NVD';
}

export async function writeVexSkeleton(opts: {
  grypeJsonPath: string;
  outDir: string;
  inputName: string;
  logger: pino.Logger;
  jobId: string;
}): Promise<{ vexPath: string | null; count: number }> {
  const { grypeJsonPath, outDir, inputName, logger, jobId } = opts;

  let data: GrypeOutput;
  try {
    const txt = await fsp.readFile(grypeJsonPath, 'utf8');
    data = JSON.parse(txt) as GrypeOutput;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'vex: could not read grype JSON');
    return { vexPath: null, count: 0 };
  }

  const matches = data.matches ?? [];
  const timestamp = new Date().toISOString();

  const vulnerabilities: VexVulnerability[] = matches.map((m) => {
    const v = m.vulnerability ?? {};
    const a = m.artifact ?? {};
    const urls = v.urls ?? [];
    const sourceUrl = urls[0] ?? v.dataSource ?? '';
    return {
      id: v.id ?? 'UNKNOWN',
      source: { name: sourceName(urls), url: sourceUrl },
      ratings: [{ severity: (v.severity ?? 'unknown').toLowerCase() }],
      affects: a.purl ? [{ ref: a.purl }] : [],
      analysis: {
        state: 'in_triage',
        justification: '',
        response: [],
        detail: '',
      },
    };
  });

  const vexDoc: VexDocument = {
    _comment: [
      'CycloneDX VEX 1.6 — automatisch generiertes Skelett.',
      'Bitte jeden Eintrag unter "vulnerabilities[].analysis" befüllen:',
      '  state: in_triage | exploitable | in_scope | not_affected | fixed',
      '  justification: code_not_reachable | vulnerable_code_not_in_execute_path | …',
      '  response: [] | ["will_not_fix"] | ["update"] | …',
      '  detail: freier Text, z.B. Ticket-URL oder Begründung',
      'Spec: https://github.com/CycloneDX/bom-examples/tree/master/VEX',
    ].join(' | '),
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp,
      component: { name: inputName, type: 'application' },
    },
    vulnerabilities,
  };

  const base = path.basename(grypeJsonPath).replace(/\.vulnerabilities\.json$/i, '');
  const vexPath = path.join(outDir, `${base}.vex.json`);
  await fsp.writeFile(vexPath, JSON.stringify(vexDoc, null, 2), 'utf8');

  logger.info(
    { jobId, count: vulnerabilities.length, vex: path.basename(vexPath) },
    `[vex] vex.json Skelett mit ${vulnerabilities.length} Einträgen`
  );

  return { vexPath, count: vulnerabilities.length };
}
