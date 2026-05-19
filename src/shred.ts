import crypto from 'crypto';
import fsp from 'fs/promises';

/**
 * Overwrite a file with random bytes (64 KiB chunks), fsync, then unlink.
 * Not a cryptographic guarantee on CoW/SSD filesystems but meaningful on tmpfs
 * (the bytes live in RAM). All errors are swallowed silently — the caller must
 * not depend on this for correctness, only as a belt-and-braces measure.
 */
export async function shredUnlink(file: string | null): Promise<void> {
  if (!file) return;
  try {
    const st = await fsp.stat(file);
    if (st.size > 0) {
      const fd = await fsp.open(file, 'r+');
      try {
        const chunkSize = Math.min(64 * 1024, st.size);
        const buf = crypto.randomBytes(chunkSize);
        let written = 0;
        while (written < st.size) {
          const n = Math.min(buf.length, st.size - written);
          await fd.write(buf, 0, n, written);
          written += n;
        }
        try {
          await fd.sync();
        } catch (_) {
          // fsync may fail on some fs types — that's acceptable
        }
      } finally {
        await fd.close();
      }
    }
  } catch (_) {
    // file may not exist or may not be readable — that's fine
  }
  try {
    await fsp.unlink(file);
  } catch (_) {
    // best-effort
  }
}
