// ─────────────────────────────────────────────────────────────────────────────
// Cosign Signing (optional)
//
// Signiert Output-Dateien mit cosign, wenn COSIGN_PRIVATE_KEY gesetzt ist.
// Wenn cosign nicht verfügbar oder Keys fehlen: silent skip.
// ─────────────────────────────────────────────────────────────────────────────

import { spawn } from 'child_process';
import type pino from 'pino';

function which(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn('sh', ['-c', `command -v ${cmd} >/dev/null 2>&1`], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.on('exit', (code) => resolve(code === 0));
    child.on('error', () => resolve(false));
  });
}

function runCosignSign(opts: {
  keyPath: string;
  password: string;
  filePath: string;
  sigPath: string;
  crtPath: string;
  timeoutMs: number;
}): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) env[k] = v;
    }
    // cosign reads the password from COSIGN_PASSWORD env var
    env['COSIGN_PASSWORD'] = opts.password;

    const child = spawn(
      'cosign',
      [
        'sign-blob',
        '--key', opts.keyPath,
        '--output-signature', opts.sigPath,
        '--output-certificate', opts.crtPath,
        '--yes',
        opts.filePath,
      ],
      { stdio: ['ignore', 'ignore', 'pipe'], env }
    );

    let stderr = '';
    child.stderr?.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });

    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, opts.timeoutMs);

    child.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code: code ?? -1, stderr });
    });
    child.on('error', (e) => {
      clearTimeout(t);
      resolve({ code: -1, stderr: e.message });
    });
  });
}

export async function signWithCosign(opts: {
  filesToSign: string[];
  outDir: string;
  logger: pino.Logger;
}): Promise<void> {
  const { filesToSign, logger } = opts;

  const keyPath = process.env['COSIGN_PRIVATE_KEY'];
  if (!keyPath) {
    // No key configured — silent skip.
    return;
  }

  const password = process.env['COSIGN_PASSWORD'] ?? '';

  // Check if cosign is available.
  const hasCosign = await which('cosign');
  if (!hasCosign) {
    logger.info('[cosign] cosign not found on PATH — signing skipped');
    return;
  }

  for (const filePath of filesToSign) {
    const sigPath = `${filePath}.sig`;
    const crtPath = `${filePath}.crt`;
    try {
      const result = await runCosignSign({
        keyPath,
        password,
        filePath,
        sigPath,
        crtPath,
        timeoutMs: 30_000,
      });
      if (result.code === 0) {
        logger.info({ file: filePath }, '[cosign] signed');
      } else {
        logger.warn({ file: filePath, code: result.code, stderr: result.stderr.slice(0, 400) }, '[cosign] sign failed (non-fatal)');
      }
    } catch (e) {
      logger.warn({ file: filePath, err: e }, '[cosign] sign error (non-fatal)');
    }
  }
}
