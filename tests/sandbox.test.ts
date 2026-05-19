import { describe, it, expect } from 'vitest';
import { detectSandbox, wrapCommand } from '../src/sandbox';

describe('detectSandbox', () => {
  it('returns "none" when mode is "none"', () => {
    expect(detectSandbox('none')).toBe('none');
  });

  it('returns "none" when mode is "bwrap" but bwrap is not in PATH', () => {
    const origPath = process.env['PATH'];
    try {
      process.env['PATH'] = '/nonexistent-dir-that-has-no-binaries';
      const result = detectSandbox('bwrap', { warn: () => {} });
      expect(result).toBe('none');
    } finally {
      process.env['PATH'] = origPath;
    }
  });

  it('returns "none" when mode is "firejail" but firejail is not in PATH', () => {
    const origPath = process.env['PATH'];
    try {
      process.env['PATH'] = '/nonexistent-dir-that-has-no-binaries';
      const result = detectSandbox('firejail', { warn: () => {} });
      expect(result).toBe('none');
    } finally {
      process.env['PATH'] = origPath;
    }
  });

  it('returns "none" when mode is "auto" and neither bwrap nor firejail is in PATH', () => {
    const origPath = process.env['PATH'];
    try {
      process.env['PATH'] = '/nonexistent-dir-that-has-no-binaries';
      const result = detectSandbox('auto');
      expect(result).toBe('none');
    } finally {
      process.env['PATH'] = origPath;
    }
  });
});

describe('wrapCommand with sandbox "none"', () => {
  it('returns identity — same command and args', () => {
    const result = wrapCommand('none', {
      command: 'foo',
      args: ['a', 'b'],
      rwPaths: ['/tmp/x'],
    });
    expect(result.command).toBe('foo');
    expect(result.args).toEqual(['a', 'b']);
  });
});

describe('wrapCommand with sandbox "bwrap"', () => {
  const result = wrapCommand('bwrap', {
    command: 'foo',
    args: ['a', 'b'],
    rwPaths: ['/tmp/x'],
  });

  it('sets command to "bwrap"', () => {
    expect(result.command).toBe('bwrap');
  });

  it('args contain --ro-bind / / flag', () => {
    expect(result.args).toContain('--ro-bind');
  });

  it('args contain --bind for rw path', () => {
    expect(result.args).toContain('--bind');
    // --bind /tmp/x /tmp/x should be present
    const idx = result.args.indexOf('--bind');
    expect(idx).toBeGreaterThan(-1);
    expect(result.args[idx + 1]).toBe('/tmp/x');
    expect(result.args[idx + 2]).toBe('/tmp/x');
  });

  it('args contain --unshare-all', () => {
    expect(result.args).toContain('--unshare-all');
  });

  it('args contain --die-with-parent', () => {
    expect(result.args).toContain('--die-with-parent');
  });

  it('args end with --, command, and original args', () => {
    // The separator -- is followed by command and all its args.
    // Use indexOf('--') to find the separator position robustly.
    const sep = result.args.lastIndexOf('--');
    expect(sep).toBeGreaterThan(-1);
    expect(result.args[sep + 1]).toBe('foo');
    expect(result.args[sep + 2]).toBe('a');
    expect(result.args[sep + 3]).toBe('b');
  });

  it('original args appear at the tail after "--"', () => {
    const sep = result.args.indexOf('--');
    expect(sep).toBeGreaterThan(-1);
    const tail = result.args.slice(sep + 1);
    expect(tail).toEqual(['foo', 'a', 'b']);
  });
});

describe('wrapCommand with sandbox "firejail"', () => {
  const result = wrapCommand('firejail', {
    command: 'foo',
    args: ['a', 'b'],
    rwPaths: ['/tmp/x'],
  });

  it('sets command to "firejail"', () => {
    expect(result.command).toBe('firejail');
  });

  it('args contain --read-only=/', () => {
    expect(result.args).toContain('--read-only=/');
  });

  it('args contain --net=none', () => {
    expect(result.args).toContain('--net=none');
  });

  it('args contain --whitelist for rw path', () => {
    expect(result.args).toContain('--whitelist=/tmp/x');
  });

  it('args end with --, command, and original args', () => {
    const sep = result.args.indexOf('--');
    expect(sep).toBeGreaterThan(-1);
    const tail = result.args.slice(sep + 1);
    expect(tail).toEqual(['foo', 'a', 'b']);
  });
});
