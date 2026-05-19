// ─────────────────────────────────────────────────────────────────────────────
// Artefakt-Hash-Cache (In-Memory)
//
// Verhindert doppelte Analyseläufe für identische Uploads via SHA-256-Lookup.
// Persistenz kommt später (SQLite); hier reicht die In-Memory-Variante.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import fs from 'fs';

export interface CacheEntry {
  hash: string;          // SHA-256 des Upload-Files
  sourceJobId: string;
  sourceOutDir: string;  // Wo die Outputs liegen
  createdAt: number;     // epoch ms
}

const cache = new Map<string, CacheEntry>();

/**
 * Berechnet den SHA-256-Hash einer Datei via Streaming.
 */
export function hashFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Sucht einen Cache-Eintrag für den gegebenen SHA-256-Hash.
 */
export function lookup(hash: string): CacheEntry | undefined {
  return cache.get(hash);
}

/**
 * Registriert einen neuen Cache-Eintrag.
 */
export function register(hash: string, jobId: string, outDir: string): void {
  cache.set(hash, {
    hash,
    sourceJobId: jobId,
    sourceOutDir: outDir,
    createdAt: Date.now(),
  });
}

/**
 * Entfernt Cache-Einträge, die älter als maxAgeMs Millisekunden sind.
 */
export function gc(maxAgeMs: number): void {
  const cutoff = Date.now() - maxAgeMs;
  for (const [key, entry] of cache.entries()) {
    if (entry.createdAt < cutoff) {
      cache.delete(key);
    }
  }
}
