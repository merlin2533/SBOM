import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import { loadConfig } from './config';
import { createApp } from './app';

async function main(): Promise<void> {
  const config = loadConfig();

  // Wipe any leftovers from a previous crashed process and recreate the
  // scratch root with mode 0700 so other local users cannot read it.
  try {
    fs.rmSync(config.scratchDir, { recursive: true, force: true });
  } catch (_) {}
  fs.mkdirSync(config.scratchDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(config.scratchDir, 0o700);
  } catch (_) {}

  const { app, logger, sandboxKind, drain } = createApp(config);

  // Check whether the extract-sbom binary is accessible.
  const bin = config.extractSbomBin;
  const isAbsolute = path.isAbsolute(bin);
  let binResolved = false;

  if (isAbsolute) {
    try {
      await fsp.access(bin, fs.constants.X_OK);
      binResolved = true;
    } catch (_) {}
  } else {
    // which-style lookup in $PATH
    for (const dir of (process.env['PATH'] ?? '').split(path.delimiter)) {
      if (!dir) continue;
      const full = path.join(dir, bin);
      try {
        fs.accessSync(full, fs.constants.X_OK);
        binResolved = true;
        break;
      } catch (_) {}
    }
  }

  if (!binResolved) {
    logger.warn({ bin }, 'extract-sbom binary not found — jobs will fail at spawn');
  } else {
    logger.info({ bin }, 'extract-sbom binary found');
  }

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      {
        port: config.port,
        host: config.host,
        sandbox: sandboxKind,
        bin,
        scratchDir: config.scratchDir,
        auth: config.authUser ? `basic (${config.authUser})` : 'disabled',
        trustProxy: config.trustProxy,
      },
      'listening'
    );
  });

  let shuttingDown = false;

  async function shutdown(sig: string): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ sig }, 'shutdown signal received');

    try {
      await drain();
    } catch (e) {
      logger.error({ err: e }, 'drain error');
    }

    server.close((err) => {
      if (err) logger.error({ err }, 'server.close error');
      logger.info('server closed');
      process.exit(0);
    });

    // Hard timeout in case server.close stalls (e.g. SSE connections).
    setTimeout(() => {
      logger.warn('forced exit after server.close timeout');
      process.exit(0);
    }, 5000).unref();
  }

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('fatal startup error:', err);
  process.exit(1);
});
