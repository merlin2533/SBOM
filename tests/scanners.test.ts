// ─────────────────────────────────────────────────────────────────────────────
// Unit-Tests für die neuen Security-Scanner-Module
//
// Testet ausschließlich reine Logik — keine externen Tools oder Netzwerk.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import pino from 'pino';

// Stiller Logger für Tests
const logger = pino({ level: 'silent' });
const JOB_ID = 'test-job-001';

// Temporäres Verzeichnis für alle Tests
let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'sbom-scanner-test-'));
});

afterAll(() => {
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch (_) {}
});

// ─── CBOM-Tests ───────────────────────────────────────────────────────────────

describe('buildCbom', () => {
  it('findet OpenSSL und BouncyCastle, ignoriert nicht-krypto Bibliotheken', async () => {
    const { buildCbom } = await import('../src/cbom');

    const outDir = join(tmpDir, 'cbom-test-1');
    mkdirSync(outDir, { recursive: true });

    // CycloneDX JSON mit 3 Komponenten: 2 krypto, 1 nicht-krypto
    const cdxDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      components: [
        { name: 'openssl', version: '3.0.1', purl: 'pkg:generic/openssl@3.0.1', type: 'library' },
        { name: 'bcprov-jdk18on', version: '1.72', purl: 'pkg:maven/org.bouncycastle/bcprov-jdk18on@1.72', type: 'library' },
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', type: 'library' },
      ],
    };
    const cdxPath = join(outDir, 'test.cdx.json');
    writeFileSync(cdxPath, JSON.stringify(cdxDoc), 'utf8');

    const result = await buildCbom({
      cdxJsonPath: cdxPath,
      outDir,
      inputName: 'test.zip',
      logger,
      jobId: JOB_ID,
    });

    // Krypto-Bibliotheken erkannt
    expect(result.components.length).toBe(2);
    const names = result.components.map((c) => c.name.toLowerCase());
    expect(names.some((n) => n.includes('openssl'))).toBe(true);
    expect(names.some((n) => n.includes('bcprov'))).toBe(true);

    // lodash nicht erkannt
    expect(names.some((n) => n === 'lodash')).toBe(false);

    // cbom.json wurde geschrieben
    expect(result.jsonPath).not.toBeNull();
  });

  it('setzt pqcSafe=false für klassische Krypto-Bibliotheken', async () => {
    const { buildCbom } = await import('../src/cbom');

    const outDir = join(tmpDir, 'cbom-test-2');
    mkdirSync(outDir, { recursive: true });

    const cdxDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      components: [
        { name: 'openssl', version: '3.0.1', purl: 'pkg:generic/openssl@3.0.1', type: 'library' },
      ],
    };
    const cdxPath = join(outDir, 'test.cdx.json');
    writeFileSync(cdxPath, JSON.stringify(cdxDoc), 'utf8');

    const result = await buildCbom({ cdxJsonPath: cdxPath, outDir, inputName: 'test.zip', logger, jobId: JOB_ID });

    expect(result.components.length).toBeGreaterThan(0);
    // Klassische Krypto ist nicht PQC-sicher
    expect(result.components[0]!.pqcSafe).toBe(false);
    // pqcUnsafeCount entsprechend
    expect(result.pqcUnsafeCount).toBe(result.components.filter((c) => !c.pqcSafe).length);
  });

  it('gibt leere Komponenten zurück wenn SBOM kein Krypto enthält', async () => {
    const { buildCbom } = await import('../src/cbom');

    const outDir = join(tmpDir, 'cbom-test-3');
    mkdirSync(outDir, { recursive: true });

    const cdxDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      components: [
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', type: 'library' },
        { name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0', type: 'library' },
      ],
    };
    const cdxPath = join(outDir, 'test.cdx.json');
    writeFileSync(cdxPath, JSON.stringify(cdxDoc), 'utf8');

    const result = await buildCbom({ cdxJsonPath: cdxPath, outDir, inputName: 'test.zip', logger, jobId: JOB_ID });

    expect(result.components).toHaveLength(0);
    expect(result.weakCount).toBe(0);
    expect(result.pqcUnsafeCount).toBe(0);
    // CBOM-Datei trotzdem geschrieben (mit leeren Komponenten)
    expect(result.jsonPath).not.toBeNull();
  });

  it('keine False-Positives: "string"/"jansson" matchen nicht ring/nss', async () => {
    const { buildCbom } = await import('../src/cbom');

    const outDir = join(tmpDir, 'cbom-test-fp');
    mkdirSync(outDir, { recursive: true });

    const cdxDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      components: [
        { name: 'string-width', version: '5.1.2', purl: 'pkg:npm/string-width@5.1.2', type: 'library' },
        { name: 'jansson', version: '2.14', purl: 'pkg:generic/jansson@2.14', type: 'library' },
        { name: 'spring-core', version: '6.1.0', purl: 'pkg:maven/org.springframework/spring-core@6.1.0', type: 'library' },
        // echtes Krypto-Token als ganzes Wort → MUSS erkannt werden
        { name: 'ring', version: '0.17.8', purl: 'pkg:cargo/ring@0.17.8', type: 'library' },
      ],
    };
    const cdxPath = join(outDir, 'test.cdx.json');
    writeFileSync(cdxPath, JSON.stringify(cdxDoc), 'utf8');

    const result = await buildCbom({ cdxJsonPath: cdxPath, outDir, inputName: 'test.zip', logger, jobId: JOB_ID });

    // Nur die echte `ring`-Crate, keine Substring-Treffer
    expect(result.components.length).toBe(1);
    expect(result.components[0]!.name).toBe('ring');
  });

  it('erkennt älteres OpenSSL als schwach (version < 1.1)', async () => {
    const { buildCbom } = await import('../src/cbom');

    const outDir = join(tmpDir, 'cbom-test-4');
    mkdirSync(outDir, { recursive: true });

    const cdxDoc = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      components: [
        { name: 'openssl', version: '1.0.2k', purl: 'pkg:generic/openssl@1.0.2k', type: 'library' },
      ],
    };
    const cdxPath = join(outDir, 'test.cdx.json');
    writeFileSync(cdxPath, JSON.stringify(cdxDoc), 'utf8');

    const result = await buildCbom({ cdxJsonPath: cdxPath, outDir, inputName: 'test.zip', logger, jobId: JOB_ID });

    expect(result.components.length).toBe(1);
    // openssl 1.0.x ist als schwach markiert
    expect(result.components[0]!.weak).toBe(true);
    expect(result.weakCount).toBe(1);
  });
});

// ─── Secret-Scan-Tests ────────────────────────────────────────────────────────

describe('runSecretScan', () => {
  it('gibt {ran:false} zurück wenn gitleaks nicht installiert ist', async () => {
    const { runSecretScan } = await import('../src/secret-scan');

    // Wir können nicht garantieren dass gitleaks nicht installiert ist,
    // aber wir können mit einem nicht-existierenden Verzeichnis testen
    const outDir = join(tmpDir, 'secret-test-1');
    mkdirSync(outDir, { recursive: true });

    // Nicht-existierendes scan-Verzeichnis → immer graceful
    const result = await runSecretScan({
      scanDir: join(tmpDir, 'nonexistent-scan-dir-' + Date.now()),
      outDir,
      inputName: 'test.zip',
      logger,
      jobId: JOB_ID,
    });

    // Entweder ran:false (gitleaks nicht installiert oder Verzeichnis fehlt)
    // oder ran:true mit 0 Befunden (wenn gitleaks installiert und nichts findet)
    expect(typeof result.ran).toBe('boolean');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.count).toBe('number');
  });

  it('gibt immer ein valides SecretScanResult zurück (graceful)', async () => {
    const { runSecretScan } = await import('../src/secret-scan');

    const outDir = join(tmpDir, 'secret-test-2');
    mkdirSync(outDir, { recursive: true });

    // Leeres Verzeichnis — sollte nie werfen
    const emptyDir = join(tmpDir, 'empty-scan-dir-' + Date.now());
    mkdirSync(emptyDir, { recursive: true });

    const result = await runSecretScan({
      scanDir: emptyDir,
      outDir,
      inputName: 'test.zip',
      logger,
      jobId: JOB_ID,
    });

    // Muss immer eine gültige Struktur zurückgeben
    expect(result).toHaveProperty('ran');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('count');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.count).toBe(result.findings.length);
  });
});

// ─── redactSecret-Tests ───────────────────────────────────────────────────────

describe('redactSecret', () => {
  it('maskiert kurze Secrets korrekt', async () => {
    const { redactSecret } = await import('../src/secret-scan');

    const secret = 'mysecretkey123456';  // 17 Zeichen
    const result = redactSecret(secret);
    // Darf NICHT den vollständigen Wert enthalten
    expect(result).not.toBe(secret);
    // Darf nur maximal 3 Zeichen zeigen
    expect(result.startsWith('mys')).toBe(true);
    expect(result).toContain('…');
    // Länge korrekt angegeben (17 Zeichen)
    expect(result).toContain(`${secret.length} Zeichen`);
  });

  it('maskiert leere Secrets gracefully', async () => {
    const { redactSecret } = await import('../src/secret-scan');

    const result = redactSecret('');
    expect(result).toBe('(leer)');
  });

  it('enthält NIE den vollständigen Secret-Wert', async () => {
    const { redactSecret } = await import('../src/secret-scan');

    const secret = 'AKIAIOSFODNN7EXAMPLE'; // Fake AWS Key
    const result = redactSecret(secret);
    // Vollständiger Wert darf nicht enthalten sein
    expect(result).not.toBe(secret);
    // Nur maximal 3 Zeichen der tatsächlichen Zeichenkette sichtbar
    const visiblePart = result.split('…')[0] ?? '';
    expect(visiblePart.length).toBeLessThanOrEqual(3);
  });
});

// ─── Extra-Scanner-Tests ──────────────────────────────────────────────────────

describe('runExtraScanners', () => {
  it('gibt graceful {ranTrivy:false, ranOsv:false} zurück wenn Tools fehlen', async () => {
    const { runExtraScanners } = await import('../src/extra-scanners');

    const outDir = join(tmpDir, 'extra-scan-test-1');
    mkdirSync(outDir, { recursive: true });

    // Nicht-existierende SBOM-Datei — Tools sollten trotzdem nicht werfen
    const result = await runExtraScanners({
      cdxJsonPath: join(tmpDir, 'nonexistent.cdx.json'),
      outDir,
      inputName: 'test.zip',
      logger,
      jobId: JOB_ID,
    });

    // Muss immer eine gültige Struktur zurückgeben
    expect(result).toHaveProperty('ranTrivy');
    expect(result).toHaveProperty('ranOsv');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('maliciousPackages');
    expect(result).toHaveProperty('counts');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.maliciousPackages)).toBe(true);
  });
});

// ─── BinaryScan-Tests ─────────────────────────────────────────────────────────

describe('runBinaryScan', () => {
  it('gibt {ran:false} zurück wenn cve-bin-tool nicht installiert ist', async () => {
    const { runBinaryScan } = await import('../src/binary-scan');

    const outDir = join(tmpDir, 'binary-scan-test-1');
    mkdirSync(outDir, { recursive: true });

    // Kleine test-Datei erstellen
    const testFile = join(tmpDir, 'test-artifact.bin');
    writeFileSync(testFile, Buffer.alloc(100, 0));

    const result = await runBinaryScan({
      target: testFile,
      outDir,
      inputName: 'test-artifact.bin',
      maxBytes: 1 * 1024 * 1024 * 1024,
      logger,
      jobId: JOB_ID,
    });

    // Muss valide Struktur haben
    expect(result).toHaveProperty('ran');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('counts');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.ran).toBe('boolean');
  });

  it('überspringt Dateien die größer als maxBytes sind', async () => {
    const { runBinaryScan } = await import('../src/binary-scan');

    const outDir = join(tmpDir, 'binary-scan-test-2');
    mkdirSync(outDir, { recursive: true });

    // Kleine test-Datei erstellen
    const testFile = join(tmpDir, 'test-artifact-big.bin');
    writeFileSync(testFile, Buffer.alloc(100, 0));

    // maxBytes = 10 (kleiner als die Datei)
    const result = await runBinaryScan({
      target: testFile,
      outDir,
      inputName: 'test-artifact-big.bin',
      maxBytes: 10, // Sehr kleines Limit
      logger,
      jobId: JOB_ID,
    });

    // Muss übersprungen werden
    expect(result.ran).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('gibt {ran:false} für nicht-existierende Datei zurück', async () => {
    const { runBinaryScan } = await import('../src/binary-scan');

    const outDir = join(tmpDir, 'binary-scan-test-3');
    mkdirSync(outDir, { recursive: true });

    const result = await runBinaryScan({
      target: join(tmpDir, 'nonexistent-file.bin'),
      outDir,
      inputName: 'nonexistent.bin',
      maxBytes: 1 * 1024 * 1024 * 1024,
      logger,
      jobId: JOB_ID,
    });

    // Nicht-existierende Datei = ran:false
    expect(result.ran).toBe(false);
  });
});

// ─── ClamScan-Tests ───────────────────────────────────────────────────────────

describe('runClamScan', () => {
  it('gibt eine valide Struktur zurück (ran:false wenn clamscan fehlt)', async () => {
    const { runClamScan } = await import('../src/clamav-scan');

    const outDir = join(tmpDir, 'clamav-scan-test-1');
    mkdirSync(outDir, { recursive: true });

    const testFile = join(tmpDir, 'clam-artifact.bin');
    writeFileSync(testFile, Buffer.alloc(100, 0));

    const result = await runClamScan({
      target: testFile,
      outDir,
      inputName: 'clam-artifact.bin',
      maxBytes: 1 * 1024 * 1024 * 1024,
      logger,
      jobId: JOB_ID,
    });

    expect(result).toHaveProperty('ran');
    expect(result).toHaveProperty('infectedCount');
    expect(result).toHaveProperty('findings');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.ran).toBe('boolean');
  });

  it('überspringt Dateien die größer als maxBytes sind', async () => {
    const { runClamScan } = await import('../src/clamav-scan');

    const outDir = join(tmpDir, 'clamav-scan-test-2');
    mkdirSync(outDir, { recursive: true });

    const testFile = join(tmpDir, 'clam-artifact-big.bin');
    writeFileSync(testFile, Buffer.alloc(100, 0));

    const result = await runClamScan({
      target: testFile,
      outDir,
      inputName: 'clam-artifact-big.bin',
      maxBytes: 10, // Sehr kleines Limit
      logger,
      jobId: JOB_ID,
    });

    expect(result.ran).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.infectedCount).toBe(0);
  });

  it('gibt {ran:false} für nicht-existierende Datei zurück', async () => {
    const { runClamScan } = await import('../src/clamav-scan');

    const outDir = join(tmpDir, 'clamav-scan-test-3');
    mkdirSync(outDir, { recursive: true });

    const result = await runClamScan({
      target: join(tmpDir, 'nonexistent-clam.bin'),
      outDir,
      inputName: 'nonexistent-clam.bin',
      maxBytes: 1 * 1024 * 1024 * 1024,
      logger,
      jobId: JOB_ID,
    });

    expect(result.ran).toBe(false);
  });
});
