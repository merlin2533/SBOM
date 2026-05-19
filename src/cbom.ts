// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic Bill of Materials (CBOM)
//
// Analysiert heuristisch die CycloneDX-SBOM-Komponenten und identifiziert
// kryptografische Bibliotheken. Erzeugt eine CycloneDX-1.6-kompatible
// CBOM-Datei.
//
// Ausgabe:
//   <base>.cbom.json   — CBOM im CycloneDX-1.6-Format
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

// ─── Exportierte Typen ───────────────────────────────────────────────────────

export interface CryptoComponent {
  name: string;
  version: string;
  purl: string;
  library: string;
  role: string;
  pqcSafe: boolean;
  weak: boolean;
  notes: string;
}

export interface CbomResult {
  jsonPath: string | null;
  components: CryptoComponent[];
  weakCount: number;
  pqcUnsafeCount: number;
}

// ─── CycloneDX-Eingabetypen ──────────────────────────────────────────────────

interface CdxComponent {
  name?: string;
  version?: string;
  purl?: string;
  type?: string;
}

interface CdxDoc {
  components?: CdxComponent[];
  metadata?: { component?: { name?: string } };
}

// ─── Kuratierte Krypto-Bibliothekstabelle ────────────────────────────────────

interface CryptoEntry {
  /** Substring-Muster (lowercase) zur Erkennung */
  match: string;
  /** Angezeigter Bibliotheksname */
  library: string;
  /** Kryptografische Rolle */
  role: string;
  /** Post-Quantum-sicher? (klassische asymmetrische Krypto: false) */
  pqcSafe: boolean;
  /** Hinweistext (deutsch) */
  notes: string;
  /**
   * Nur als ganzes Token (von Nicht-Alphanumerik begrenzt) matchen statt als
   * beliebiger Substring. Nötig für kurze, mehrdeutige Muster wie `ring`
   * (sonst Treffer in "string", "spring") oder `nss` (Treffer in "jansson").
   */
  wholeWord?: boolean;
}

const CRYPTO_TABLE: CryptoEntry[] = [
  // ── OpenSSL-Familie ─────────────────────────────────────────────────────────
  { match: 'openssl',      library: 'OpenSSL',     role: 'TLS/SSL, Allgemeine Kryptografie', pqcSafe: false, notes: 'Weit verbreitete C-Krypto-Bibliothek. Klassisches RSA/ECDSA/AES — nicht PQC-sicher.' },
  { match: 'libssl',       library: 'libssl',      role: 'TLS/SSL',                          pqcSafe: false, notes: 'TLS-Schicht aus dem OpenSSL-Paket.' },
  { match: 'libcrypto',    library: 'libcrypto',   role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Krypto-Schicht aus dem OpenSSL-Paket.' },
  { match: 'boringssl',    library: 'BoringSSL',   role: 'TLS/SSL, Allgemeine Kryptografie', pqcSafe: false, notes: 'Google-Fork von OpenSSL. Gut gewartet, aber proprietär.' },
  { match: 'libressl',     library: 'LibreSSL',    role: 'TLS/SSL, Allgemeine Kryptografie', pqcSafe: false, notes: 'OpenBSD-Fork von OpenSSL. Sicherheitsorientierte Variante.' },
  { match: 'wolfssl',      library: 'wolfSSL',     role: 'TLS/SSL (Embedded)',                pqcSafe: false, notes: 'Leichtgewichtige TLS-Bibliothek für eingebettete Systeme.' },
  { match: 'mbedtls',      library: 'mbedTLS',     role: 'TLS/SSL (Embedded)',                pqcSafe: false, notes: 'ARM/Mbed TLS für IoT und eingebettete Systeme.' },
  { match: 'mbed tls',     library: 'mbedTLS',     role: 'TLS/SSL (Embedded)',                pqcSafe: false, notes: 'ARM/Mbed TLS für IoT und eingebettete Systeme.' },
  { match: 'gnutls',       library: 'GnuTLS',      role: 'TLS/SSL',                          pqcSafe: false, notes: 'GNU TLS-Implementierung, verbreitet unter Linux.' },

  // ── NSS ─────────────────────────────────────────────────────────────────────
  { match: 'nss',          library: 'NSS',         role: 'TLS/SSL, Hashing/Signaturen',      pqcSafe: false, wholeWord: true, notes: 'Mozillas Network Security Services. Basis für Firefox/Thunderbird TLS.' },

  // ── Java/JVM ─────────────────────────────────────────────────────────────────
  { match: 'bouncy castle', library: 'Bouncy Castle', role: 'Allgemeine Kryptografie',       pqcSafe: false, notes: 'Umfangreiche Java/Kotlin-Krypto-Bibliothek. Enthält PQC-Preview-APIs.' },
  { match: 'bouncycastle',  library: 'Bouncy Castle', role: 'Allgemeine Kryptografie',       pqcSafe: false, notes: 'Umfangreiche Java/Kotlin-Krypto-Bibliothek. Enthält PQC-Preview-APIs.' },
  { match: 'bcprov',        library: 'Bouncy Castle', role: 'Allgemeine Kryptografie',       pqcSafe: false, notes: 'Bouncy Castle Provider JAR.' },
  { match: 'bcpkix',        library: 'Bouncy Castle', role: 'PKI/Zertifikate',               pqcSafe: false, notes: 'Bouncy Castle PKIX/PKI-Erweiterungen.' },

  // ── libsodium/NaCl ──────────────────────────────────────────────────────────
  { match: 'libsodium',    library: 'libsodium',   role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Modernes, benutzerfreundliches Krypto-Framework. Keine PQC-Unterstützung.' },
  { match: 'nacl',         library: 'NaCl',        role: 'Allgemeine Kryptografie',           pqcSafe: false, wholeWord: true, notes: 'Networking and Cryptography library — Basis für libsodium.' },

  // ── Weitere C/C++ ────────────────────────────────────────────────────────────
  { match: 'libgcrypt',    library: 'libgcrypt',   role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Krypto-Backend der GnuPG-Suite.' },
  { match: 'nettle',       library: 'Nettle',      role: 'Hashing/Signaturen',                pqcSafe: false, notes: 'Niedrig-ebene Krypto-Bibliothek, genutzt von GnuTLS.' },

  // ── Python ──────────────────────────────────────────────────────────────────
  { match: 'cryptography', library: 'pyca/cryptography', role: 'Allgemeine Kryptografie',   pqcSafe: false, notes: 'Standard-Python-Krypto-Bibliothek (pyca). Basiert auf OpenSSL.' },
  { match: 'pycryptodome', library: 'PyCryptodome', role: 'Allgemeine Kryptografie',         pqcSafe: false, notes: 'Selbst enthaltene Python-Krypto-Bibliothek (kein OpenSSL-Binding).' },
  { match: 'pycrypto',     library: 'PyCrypto',    role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Ältere Python-Krypto-Bibliothek (veraltet, durch PyCryptodome ersetzt).' },

  // ── JavaScript/Node ─────────────────────────────────────────────────────────
  { match: 'node-forge',   library: 'node-forge',  role: 'TLS/SSL, PKI',                     pqcSafe: false, notes: 'Rein-JavaScript TLS/PKI-Implementierung.' },
  { match: 'crypto-js',    library: 'crypto-js',   role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'JavaScript-Krypto-Bibliothek — nur für Browser-Kompatibilität empfohlen.' },
  { match: 'jsrsasign',    library: 'jsrsasign',   role: 'PKI/Signaturen',                   pqcSafe: false, notes: 'RSA/ECDSA-Signaturbibliothek für JavaScript.' },
  { match: 'sjcl',         library: 'SJCL',        role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Stanford JavaScript Crypto Library.' },

  // ── Go ──────────────────────────────────────────────────────────────────────
  { match: 'golang.org/x/crypto', library: 'Go crypto', role: 'Allgemeine Kryptografie',   pqcSafe: false, notes: 'Zusätzliche Krypto-Pakete der Go-Standardbibliothek.' },

  // ── Rust ─────────────────────────────────────────────────────────────────────
  { match: 'ring',         library: 'ring',        role: 'Allgemeine Kryptografie',           pqcSafe: false, wholeWord: true, notes: 'Sichere Krypto-Bibliothek für Rust — verwendet BoringSSL-Primitive.' },
  { match: 'rustls',       library: 'rustls',      role: 'TLS/SSL',                          pqcSafe: false, notes: 'Modernes TLS in reinem Rust (basiert auf ring).' },

  // ── SSH ──────────────────────────────────────────────────────────────────────
  { match: 'openssh',      library: 'OpenSSH',     role: 'SSH',                              pqcSafe: false, notes: 'SSH-Implementierung. Neuere Versionen unterstützen ML-KEM (PQC-Hybrid).' },
  { match: 'libssh',       library: 'libssh',      role: 'SSH',                              pqcSafe: false, notes: 'C-SSH-Bibliothek für Clients und Server.' },

  // ── GPG/Kerberos ─────────────────────────────────────────────────────────────
  { match: 'gpgme',        library: 'GPGME',       role: 'Verschlüsselung/Signaturen',       pqcSafe: false, notes: 'GnuPG Made Easy — C-API für GnuPG.' },
  { match: 'kerberos',     library: 'Kerberos',    role: 'Authentifizierung',                pqcSafe: false, notes: 'Kerberos-Protokoll-Implementierung.' },
  { match: 'krb5',         library: 'MIT Kerberos', role: 'Authentifizierung',               pqcSafe: false, notes: 'MIT Kerberos 5 Bibliothek.' },

  // ── C++ ─────────────────────────────────────────────────────────────────────
  { match: 'cryptopp',     library: 'Crypto++',    role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Umfangreiche C++-Krypto-Bibliothek.' },
  { match: 'crypto++',     library: 'Crypto++',    role: 'Allgemeine Kryptografie',           pqcSafe: false, notes: 'Umfangreiche C++-Krypto-Bibliothek.' },
];

// Token, bei denen eine Bibliothek als "schwach" gilt (bekannt-defekte Primitive)
const WEAK_TOKENS = [
  /\bmd5\b/i,
  /\bmd4\b/i,
  /\bsha-?1\b/i,
  /\brc4\b/i,
  // DES-Treffer: \bdes\b oder -des- aber NICHT "design", "described" usw.
  /(?:^|-|_|\/|\.)des(?:$|-|_|\/|\.)/i,
];

/**
 * Prüft, ob ein (bereits lowercase) Komponentenname auf einen Tabelleneintrag
 * passt. Reguläre Einträge per Substring; `wholeWord`-Einträge nur als von
 * Nicht-Alphanumerik begrenztes Token.
 */
function matchesEntry(compName: string, entry: CryptoEntry): boolean {
  if (!entry.wholeWord) return compName.includes(entry.match);
  const escaped = entry.match.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, 'i').test(compName);
}

/** Prüft ob ein Komponentenname schwache kryptografische Primitive enthält. */
function isWeak(name: string, version: string): boolean {
  // Token-basierte Prüfung auf den Namen
  for (const re of WEAK_TOKENS) {
    if (re.test(name)) return true;
  }
  // Sonderfall: openssl < 1.1 (Legacy-Version mit schwachen Defaults)
  if (/openssl/i.test(name) && version) {
    const m = version.match(/^(\d+)\.(\d+)/);
    if (m) {
      const major = parseInt(m[1]!, 10);
      const minor = parseInt(m[2]!, 10);
      if (major < 1 || (major === 1 && minor < 1)) return true;
    }
  }
  return false;
}

// ─── Hauptexport ─────────────────────────────────────────────────────────────

/**
 * Erzeugt ein Cryptographic Bill of Materials aus den CycloneDX-Komponenten.
 * Rein heuristisch/offline — keine externe Tool-Abhängigkeit.
 * Gibt immer ein valides CbomResult zurück — nie throw.
 */
export async function buildCbom(opts: {
  cdxJsonPath: string;
  outDir: string;
  inputName: string;
  logger: pino.Logger;
  jobId: string;
}): Promise<CbomResult> {
  const { cdxJsonPath, outDir, inputName, logger, jobId } = opts;

  const empty: CbomResult = { jsonPath: null, components: [], weakCount: 0, pqcUnsafeCount: 0 };

  try {
    // CycloneDX laden
    let cdx: CdxDoc;
    try {
      const txt = await fsp.readFile(cdxJsonPath, 'utf8');
      cdx = JSON.parse(txt) as CdxDoc;
    } catch (e) {
      logger.warn({ jobId, err: e }, 'cbom: SBOM konnte nicht gelesen werden');
      return empty;
    }

    const cdxComponents = cdx.components ?? [];
    const cryptoComps: CryptoComponent[] = [];

    for (const comp of cdxComponents) {
      const compName = (comp.name ?? '').toLowerCase();
      if (!compName) continue;

      // Suche nach einem passenden Krypto-Tabellen-Eintrag
      for (const entry of CRYPTO_TABLE) {
        if (matchesEntry(compName, entry)) {
          const version = comp.version ?? '';
          const purl = comp.purl ?? `${comp.name ?? 'unknown'}@${version}`;
          const weak = isWeak(compName, version);
          cryptoComps.push({
            name: comp.name ?? '?',
            version,
            purl,
            library: entry.library,
            role: entry.role,
            pqcSafe: entry.pqcSafe,
            weak,
            notes: entry.notes,
          });
          break; // erstes Treffer gewinnt
        }
      }
    }

    const weakCount = cryptoComps.filter((c) => c.weak).length;
    const pqcUnsafeCount = cryptoComps.filter((c) => !c.pqcSafe).length;

    // CBOM-Datei schreiben (CycloneDX-1.6-Format)
    const timestamp = new Date().toISOString();
    const base = path.basename(cdxJsonPath).replace(/\.cdx\.json$/i, '').replace(/\.json$/i, '');
    const cbomPath = path.join(outDir, `${base}.cbom.json`);

    const cbomDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: {
        timestamp,
        component: {
          name: inputName,
          type: 'application',
        },
      },
      components: cryptoComps.map((c) => ({
        type: 'cryptographic-asset',
        name: c.name,
        version: c.version,
        'bom-ref': c.purl || `${c.name}@${c.version}`,
        cryptoProperties: {
          assetType: 'related-crypto-material',
          algorithmProperties: {
            role: c.role,
            primitive: c.library,
          },
          implementationPlatform: 'unknown',
          certificationLevel: [],
          mode: 'unknown',
        },
        properties: [
          { name: 'sbom:crypto:library', value: c.library },
          { name: 'sbom:crypto:role', value: c.role },
          { name: 'sbom:crypto:pqcSafe', value: String(c.pqcSafe) },
          { name: 'sbom:crypto:weak', value: String(c.weak) },
          { name: 'sbom:crypto:notes', value: c.notes },
        ],
      })),
    };

    await fsp.writeFile(cbomPath, JSON.stringify(cbomDoc, null, 2), 'utf8');

    logger.info(
      {
        jobId,
        total: cryptoComps.length,
        weak: weakCount,
        pqcUnsafe: pqcUnsafeCount,
        file: path.basename(cbomPath),
      },
      `[cbom] ${cryptoComps.length} Krypto-Komponenten gefunden`
    );

    return {
      jsonPath: cbomPath,
      components: cryptoComps,
      weakCount,
      pqcUnsafeCount,
    };
  } catch (e) {
    logger.warn({ jobId, err: e }, 'cbom: unerwarteter Fehler (nicht-fatal)');
    return empty;
  }
}
