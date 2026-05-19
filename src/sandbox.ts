import fs from 'fs';
import path from 'path';
import type { SandboxKind, SandboxMode } from './types';

/**
 * Try to find an executable `name` via the directories in $PATH (or the
 * provided override). Returns the full path or null.
 */
function which(name: string, envPath?: string): string | null {
  const searchPath = envPath ?? process.env['PATH'] ?? '';
  for (const dir of searchPath.split(path.delimiter)) {
    if (!dir) continue;
    const full = path.join(dir, name);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      return full;
    } catch (_) {
      // not found in this directory
    }
  }
  return null;
}

/**
 * Detect which sandbox tool is available.
 *
 * - 'auto': try bwrap first, then firejail, else 'none'.
 * - 'bwrap'/'firejail': verify it's present; warn + return 'none' if missing.
 * - 'none': always 'none'.
 */
export function detectSandbox(
  mode: SandboxMode,
  logger?: { warn(msg: string): void }
): SandboxKind {
  if (mode === 'none') return 'none';

  if (mode === 'auto') {
    if (which('bwrap') !== null) return 'bwrap';
    if (which('firejail') !== null) return 'firejail';
    return 'none';
  }

  // Explicit request for bwrap or firejail — verify it exists.
  if (which(mode) !== null) return mode;

  const msg = `SANDBOX_MODE=${mode} requested but '${mode}' binary not found in $PATH; falling back to no sandbox`;
  if (logger) {
    logger.warn(msg);
  } else {
    console.warn(msg);
  }
  return 'none';
}

export interface WrapCommandOpts {
  command: string;
  args: string[];
  rwPaths: string[];
  env?: Record<string, string>;
}

export interface WrappedCommand {
  command: string;
  args: string[];
}

/**
 * Wrap a command invocation in a sandbox.
 *
 * bwrap: bind-mount / read-only, bind rw paths read-write, no network,
 *        --die-with-parent so the child can't outlive the node process.
 *
 * firejail: read-only root, no network, private /tmp, whitelist rw paths.
 *
 * none: identity transform.
 */
export function wrapCommand(
  sandbox: SandboxKind,
  opts: WrapCommandOpts
): WrappedCommand {
  const { command, args, rwPaths } = opts;

  if (sandbox === 'none') {
    return { command, args };
  }

  if (sandbox === 'bwrap') {
    const bwrapArgs: string[] = [
      '--ro-bind', '/', '/',
      '--dev', '/dev',
      '--proc', '/proc',
      '--tmpfs', '/tmp',
    ];
    for (const p of rwPaths) {
      bwrapArgs.push('--bind', p, p);
    }
    bwrapArgs.push(
      '--unshare-all',
      // Deliberately no --share-net: we want no network inside the sandbox.
      '--die-with-parent',
      '--new-session',
      '--',
      command,
      ...args
    );
    return { command: 'bwrap', args: bwrapArgs };
  }

  if (sandbox === 'firejail') {
    const fjArgs: string[] = [
      '--quiet',
      '--noprofile',
      '--net=none',
      '--private-tmp',
      '--read-only=/',
    ];
    for (const p of rwPaths) {
      fjArgs.push(`--whitelist=${p}`);
    }
    fjArgs.push('--', command, ...args);
    return { command: 'firejail', args: fjArgs };
  }

  // Exhaustive check — TypeScript should prevent reaching here.
  return { command, args };
}
