// ─────────────────────────────────────────────────────────────────────────────
// SLSA v1.0 Provenance Generator
//
// Erzeugt eine <base>.provenance.json im SLSA v1.0-Format.
// Spec: https://slsa.dev/spec/v1.0/provenance
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../package.json') as { version: string };
const APP_VERSION = process.env['APP_VERSION']?.trim() || pkg.version;

interface SlsaResourceDescriptor {
  name: string;
  digest: { sha256: string };
  mediaType?: string;
}

interface SlsaBuilder {
  id: string;
  version?: Record<string, string>;
}

interface SlsaBuildDefinition {
  buildType: string;
  externalParameters: Record<string, unknown>;
  internalParameters?: Record<string, unknown>;
  resolvedDependencies?: SlsaResourceDescriptor[];
}

interface SlsaRunDetails {
  builder: SlsaBuilder;
  metadata: {
    invocationId: string;
    startedOn: string;
    finishedOn: string;
  };
}

interface SlsaProvenance {
  '_type': string;
  subject: SlsaResourceDescriptor[];
  predicateType: string;
  predicate: {
    buildDefinition: SlsaBuildDefinition;
    runDetails: SlsaRunDetails;
  };
}

async function getExtractSbomVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const child = spawn('extract-sbom', ['--version'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout?.on('data', (b: Buffer) => { out += b.toString('utf8'); });
    child.stderr?.on('data', (b: Buffer) => { out += b.toString('utf8'); });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
      resolve(null);
    }, 5_000);
    child.on('exit', () => {
      clearTimeout(t);
      const match = out.match(/[\d]+\.[\d]+\.[\d]+/);
      resolve(match ? match[0] : null);
    });
    child.on('error', () => {
      clearTimeout(t);
      resolve(null);
    });
  });
}

export async function writeSlsa(opts: {
  cdxJsonPath: string;
  outDir: string;
  inputName: string;
  inputSha256: string | null;
  jobId: string;
  logger: pino.Logger;
}): Promise<{ provenancePath: string | null }> {
  const { cdxJsonPath, outDir, inputName, inputSha256, jobId, logger } = opts;

  if (!inputSha256) {
    logger.warn({ jobId }, 'slsa: no input SHA-256 available, skipping provenance');
    return { provenancePath: null };
  }

  const now = new Date().toISOString();
  const extractSbomVersion = await getExtractSbomVersion();

  const provenance: SlsaProvenance = {
    '_type': 'https://in-toto.io/Statement/v0.1',
    subject: [
      {
        name: inputName,
        digest: { sha256: inputSha256 },
      },
    ],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://example.org/sbom-upload-app/v1',
        externalParameters: {
          inputName,
          jobId,
        },
        internalParameters: {
          appVersion: APP_VERSION,
          ...(extractSbomVersion ? { extractSbomVersion } : {}),
        },
        resolvedDependencies: [
          {
            name: inputName,
            digest: { sha256: inputSha256 },
          },
        ],
      },
      runDetails: {
        builder: {
          id: `https://example.org/sbom-upload-app@v${APP_VERSION}`,
          version: {
            'sbom-upload-app': APP_VERSION,
            ...(extractSbomVersion ? { 'extract-sbom': extractSbomVersion } : {}),
          },
        },
        metadata: {
          invocationId: crypto.randomUUID(),
          startedOn: now,
          finishedOn: now,
        },
      },
    },
  };

  const base = path.basename(cdxJsonPath).replace(/\.cdx\.json$/i, '');
  const provenancePath = path.join(outDir, `${base}.provenance.json`);
  await fsp.writeFile(provenancePath, JSON.stringify(provenance, null, 2), 'utf8');

  logger.info(
    { jobId, file: path.basename(provenancePath) },
    '[slsa] geschrieben'
  );

  return { provenancePath };
}
