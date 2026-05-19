import { describe, it, expect } from 'vitest';
import { existsSync, writeFileSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { shredUnlink } from '../src/shred';

describe('shredUnlink', () => {
  it('overwrites and removes a file with known content', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shred-test-'));
    const file = join(dir, 'secret.txt');
    writeFileSync(file, 'super secret password');
    expect(existsSync(file)).toBe(true);

    await shredUnlink(file);

    expect(existsSync(file)).toBe(false);
  });

  it('handles a non-empty multi-chunk file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shred-test-'));
    const file = join(dir, 'bigfile.txt');
    // Write something larger than 64KiB to exercise the loop
    writeFileSync(file, Buffer.alloc(128 * 1024, 'x'));
    await shredUnlink(file);
    expect(existsSync(file)).toBe(false);
  });

  it('resolves without throwing for null', async () => {
    await expect(shredUnlink(null)).resolves.toBeUndefined();
  });

  it('resolves without throwing for a nonexistent path', async () => {
    await expect(shredUnlink('/nonexistent/path/that/does/not/exist.txt')).resolves.toBeUndefined();
  });

  it('handles a zero-byte file (only unlinks)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shred-test-'));
    const file = join(dir, 'empty.txt');
    writeFileSync(file, '');
    await shredUnlink(file);
    expect(existsSync(file)).toBe(false);
  });
});
