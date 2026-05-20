import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import pino from 'pino';
import type { ServerConfig, Session, Job, SandboxKind } from './types';
import { SessionManager } from './session';
import { wrapCommand } from './sandbox';
import { shredUnlink } from './shred';
import { preExtract, cleanupPreExtract, PreExtractResult } from './pre-extract';
import { runVulnReport } from './vuln-report';
import { buildSummaryReport } from './summary-report';
import type { SummaryExtras } from './summary-report';
import { writeVexSkeleton } from './vex-template';
import { runExtraScanners } from './extra-scanners';
import type { ExtraScanResult } from './extra-scanners';
import { runSecretScan } from './secret-scan';
import type { SecretScanResult } from './secret-scan';
import { buildCbom } from './cbom';
import type { CbomResult } from './cbom';
import { runBinaryScan } from './binary-scan';
import type { BinaryScanResult } from './binary-scan';
import { writeAuditEntry } from './audit-log';
import { hashFile, lookup, register } from './hash-cache';
import { writeOpenVex } from './openvex';
import { writeCsaf } from './csaf';
import { writeSlsa } from './slsa';
import { signWithCosign } from './cosign';
import { isKev, kevEntry } from './kev';
import type { KevDetails } from './kev';
import { epssFor } from './epss';
import type { EpssScore } from './epss';
import { lookupEol } from './eol';
import { detectTyposquat } from './typosquat';
import { evaluatePolicy } from './policy';
import { writeSiemExport, buildFindings } from './siem';
import { mergeVexIntoFile } from './vex-store';
import { writeComplianceReports } from './compliance';
import { upsertCatalog } from './catalog';

export interface EnqueueOpts {
  uploadPath: string;
  uploadName: string;
  uploadSize: number;
  passwords: string[];
}

export class JobRunner {
  constructor(
    private sessions: SessionManager,
    private config: ServerConfig,
    private logger: pino.Logger,
    private sandboxKind: SandboxKind
  ) {}

  enqueue(sess: Session, opts: EnqueueOpts): Job {
    const id = crypto.randomBytes(12).toString('hex');
    const outDir = path.join(sess.dir, 'jobs', id, 'out');
    fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

    const job: Job = {
      id,
      state: 'queued',
      command: this.config.extractSbomBin,
      args: [],
      argsDisplay: [],
      child: null,
      pid: null,
      exitCode: null,
      signal: null,
      error: null,
      startedAt: null,
      finishedAt: null,
      createdAt: Date.now(),
      inputName: opts.uploadName,
      inputSize: opts.uploadSize,
      uploadPath: opts.uploadPath,
      passwordCount: opts.passwords.length,
      passwordTransport: 'none',
      passwordFile: null,
      outDir,
      outputs: [],
      log: [],
      phase: null,
      progress: null,
      sandbox: this.sandboxKind,
      inputSha256: null,
    };

    // Stash plaintext passwords temporarily until the job is launched;
    // they are erased in preparePasswords().
    (job as JobWithPending)._pendingPasswords = opts.passwords;

    sess.jobs.push(job);

    this.logger.debug({ sid: sess.sid, jobId: id }, 'job enqueued');

    // Kick off the queue if nothing is currently running.
    const running = this.sessions.runningJob(sess);
    if (!running || running.state !== 'running') {
      this.runNext(sess);
    }

    return job;
  }

  // --------------------------------------------------------------------------
  // Private: job execution
  // --------------------------------------------------------------------------

  private async runNext(sess: Session): Promise<void> {
    const nextJob = sess.jobs.find((j) => j.state === 'queued');
    if (!nextJob) return;

    // Update currentJobIdx to point at the new active job.
    sess.currentJobIdx = sess.jobs.indexOf(nextJob);

    await this.launchJob(sess, nextJob);
  }

  private async launchJob(sess: Session, job: Job): Promise<void> {
    const { passwords } = await this.preparePasswords(sess, job);

    // Audit: job_started
    writeAuditEntry({
      ts: new Date().toISOString(),
      event: 'job_started',
      sid: sess.sid,
      jobId: job.id,
      inputName: job.inputName,
      inputSize: job.inputSize,
    }).catch(() => {});

    // Hash-Cache: berechne SHA-256 des Uploads und prüfe ob bereits analysiert.
    let inputHash: string | null = null;
    try {
      inputHash = await hashFile(job.uploadPath);
      job.inputSha256 = inputHash;
    } catch (e) {
      this.logger.warn({ jobId: job.id, err: e }, 'hash-cache: could not hash upload (non-fatal)');
    }

    if (inputHash) {
      const cached = lookup(inputHash);
      if (cached) {
        // Cache-Hit: Outputs aus dem Quell-Job kopieren
        this.sessions.pushLog(sess, job, 'stdout',
          `[cache] Hash ${inputHash.slice(0, 16)}… bekannt aus Job ${cached.sourceJobId} — Resultate wiederverwendet`);
        let cacheApplied = false;
        try {
          await fsp.cp(cached.sourceOutDir, job.outDir, { recursive: true });
          cacheApplied = true;
        } catch (e) {
          this.logger.warn({ jobId: job.id, err: e }, 'hash-cache: cp failed, falling through to fresh run');
        }

        if (cacheApplied) {
          // Cleanup upload immediately (same as in exit handler)
          await shredUnlink(job.passwordFile);
          job.passwordFile = null;
          try { await fsp.unlink(job.uploadPath); } catch (_) {}

          job.state = 'done';
          job.startedAt = Date.now();
          job.finishedAt = Date.now();
          job.exitCode = 0;

          await this.sessions.refreshOutputs(sess, job);
          this.sessions.touch(sess);
          this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));

          this.logger.info(
            { sid: sess.sid, jobId: job.id, sourceJobId: cached.sourceJobId },
            'job finished (cache hit)'
          );

          writeAuditEntry({
            ts: new Date().toISOString(),
            event: 'job_finished',
            sid: sess.sid,
            jobId: job.id,
            inputName: job.inputName,
            inputSha256: inputHash,
            state: 'done',
            durationMs: 0,
            cacheHit: true,
          }).catch(() => {});

          this.runNext(sess);
          return;
        }
      }
    }

    // Pre-Extract: extract-sbom kennt nur Container-Formate per Magic-Bytes.
    // Für reine `.exe`-Installer (Inno Setup, NSIS, ...) versuchen wir, das
    // Archiv mit 7z bzw. innoextract aufzuknacken und als ZIP zu repacken,
    // damit extract-sbom überhaupt was zu tun bekommt.
    const preWorkDir = path.join(sess.dir, 'jobs', job.id, 'pre');
    let pre: PreExtractResult | null = null;
    try {
      pre = await preExtract({
        uploadPath: job.uploadPath,
        uploadName: job.inputName,
        workDir: preWorkDir,
        logger: this.logger,
        jobId: job.id,
      });
    } catch (e) {
      this.logger.warn({ jobId: job.id, err: e }, 'pre-extract threw, skipping');
    }
    const effectiveInput = pre?.inputPath ?? job.uploadPath;
    if (pre?.didPreExtract) {
      this.logger.info(
        { jobId: job.id, tool: pre.tool, original: job.inputName, zipped: path.basename(pre.inputPath) },
        'pre-extract: succeeded, passing repacked zip to extract-sbom'
      );
      this.sessions.pushLog(
        sess,
        job,
        'stdout',
        `[pre-extract] ${job.inputName} via ${pre.tool} → ${path.basename(pre.inputPath)}`
      );
    }

    // Build args list.
    const args: string[] = ['--output-dir', job.outDir, ...this.config.extraArgs];
    if (job.passwordFile) {
      args.push('--password-file', job.passwordFile);
    }
    args.push(effectiveInput);

    // Display args: replace scratch-dir prefix with basename so the client
    // never sees internal server paths.
    const argsDisplay = args.map((a) =>
      a.startsWith(sess.dir + path.sep) ? path.basename(a) : a
    );

    job.args = args;
    job.argsDisplay = argsDisplay;

    // Wrap for sandbox.
    // rw paths = session dir (contains upload, jobs subdir, password file).
    const wrapped = wrapCommand(this.sandboxKind, {
      command: job.command,
      args,
      rwPaths: [sess.dir],
    });

    // Build child process environment.
    const childEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) childEnv[k] = v;
    }
    if (passwords.length > 0 && job.passwordTransport === 'env') {
      childEnv['EXTRACT_SBOM_PASSWORDS'] = passwords.join(',');
    }

    let child;
    try {
      child = spawn(wrapped.command, wrapped.args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: childEnv,
      });
    } catch (e: unknown) {
      await shredUnlink(job.passwordFile);
      job.passwordFile = null;
      job.state = 'failed';
      job.error = e instanceof Error ? e.message : String(e);
      job.finishedAt = Date.now();
      this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));
      this.logger.error({ sid: sess.sid, jobId: job.id, err: e }, 'failed to spawn');
      return;
    }

    job.child = child;
    job.pid = child.pid ?? null;
    job.state = 'running';
    job.startedAt = Date.now();

    this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));
    this.logger.info(
      { sid: sess.sid, jobId: job.id, pid: job.pid, sandbox: this.sandboxKind },
      'job started'
    );

    // Wire stdout/stderr to the log ring buffer.
    readline
      .createInterface({ input: child.stdout! })
      .on('line', (line) => this.sessions.pushLog(sess, job, 'stdout', line));
    readline
      .createInterface({ input: child.stderr! })
      .on('line', (line) => this.sessions.pushLog(sess, job, 'stderr', line));

    // Watch output directory for new files.
    try {
      sess.outputWatcher = fs.watch(job.outDir, { persistent: false }, () => {
        this.sessions.refreshOutputs(sess, job).catch(() => {});
      });
    } catch (_) {
      // fs.watch may not be supported on all platforms — not fatal.
    }

    child.on('error', (e) => {
      job.error = e.message;
      this.sessions.pushLog(sess, job, 'stderr', `[spawn error] ${e.message}`);
      this.logger.error({ sid: sess.sid, jobId: job.id }, e.message);
    });

    child.on('exit', async (code, signal) => {
      job.exitCode = code;
      job.signal = signal as NodeJS.Signals | null;
      job.finishedAt = Date.now();
      job.state = code === 0 ? 'done' : signal ? 'cancelled' : 'failed';

      if (sess.outputWatcher) {
        try {
          sess.outputWatcher.close();
        } catch (_) {}
        sess.outputWatcher = null;
      }

      // Rohartefakt-Scans (benötigen Upload + stage-Verzeichnis): vor dem Löschen ausführen.
      let binaryScanResult: BinaryScanResult | null = null;
      let secretScanResult: SecretScanResult | null = null;

      if (job.state === 'done') {
        // Binär-Scan auf das Upload-Artefakt
        try {
          binaryScanResult = await runBinaryScan({
            target: job.uploadPath,
            outDir: job.outDir,
            inputName: job.inputName,
            maxBytes: this.config.binaryScanMaxBytes,
            logger: this.logger,
            jobId: job.id,
          });
          const msg = binaryScanResult.ran
            ? `[binary-scan] ${binaryScanResult.findings.length} CVEs in Binärdateien`
            : '[binary-scan] übersprungen';
          this.sessions.pushLog(sess, job, 'stdout', msg);
        } catch (e) {
          this.logger.warn({ jobId: job.id, err: e }, 'binary-scan: Fehler (nicht-fatal)');
        }

        // Secret-Scan: bevorzugt das stage-Verzeichnis aus pre-extract
        let secretScanDir: string | null = null;
        let secretTmpDir: string | null = null;
        if (pre?.didPreExtract) {
          // stage-Verzeichnis aus dem pre-extract verwenden
          secretScanDir = path.join(path.dirname(pre.inputPath), 'stage');
        } else {
          // Versuchen den Upload zu entpacken wenn klein genug und 7z verfügbar
          const uploadSize = job.inputSize;
          if (uploadSize <= this.config.secretScanMaxBytes) {
            const has7z = await new Promise<boolean>((resolve) => {
              const c = spawn('sh', ['-c', 'command -v 7z >/dev/null 2>&1'], { stdio: 'ignore' });
              c.on('exit', (ec) => resolve(ec === 0));
              c.on('error', () => resolve(false));
            });
            // Decompression-Bomb-Schutz: unkomprimierte Gesamtgröße vorab
            // prüfen (via `7z l`), bevor wir tatsächlich entpacken.
            const uncompressed = has7z ? await probe7zUncompressedSize(job.uploadPath) : null;
            if (has7z && uncompressed != null && uncompressed > MAX_SECRET_EXTRACT_BYTES) {
              this.logger.warn(
                { jobId: job.id, uncompressed, max: MAX_SECRET_EXTRACT_BYTES },
                'secret-scan: Archiv entpackt zu groß (mögliche Decompression-Bomb), übersprungen'
              );
            } else if (has7z) {
              secretTmpDir = path.join(sess.dir, 'jobs', job.id, 'secret-scan');
              try {
                await fsp.mkdir(secretTmpDir, { recursive: true, mode: 0o700 });
                await new Promise<void>((resolve) => {
                  const c = spawn('7z', ['x', '-y', `-o${secretTmpDir}`, job.uploadPath], {
                    stdio: ['ignore', 'ignore', 'ignore'],
                  });
                  const t = setTimeout(() => { try { c.kill('SIGKILL'); } catch (_) {} }, 120_000);
                  c.on('exit', () => { clearTimeout(t); resolve(); });
                  c.on('error', () => { clearTimeout(t); resolve(); });
                });
                secretScanDir = secretTmpDir;
              } catch (_) {
                secretScanDir = null;
              }
            }
          }
        }

        if (secretScanDir) {
          try {
            secretScanResult = await runSecretScan({
              scanDir: secretScanDir,
              outDir: job.outDir,
              inputName: job.inputName,
              logger: this.logger,
              jobId: job.id,
            });
            const msg = secretScanResult.ran
              ? `[secret-scan] ${secretScanResult.count} Secret-Funde`
              : '[secret-scan] übersprungen';
            this.sessions.pushLog(sess, job, 'stdout', msg);
          } catch (e) {
            this.logger.warn({ jobId: job.id, err: e }, 'secret-scan: Fehler (nicht-fatal)');
          }
        } else {
          this.sessions.pushLog(sess, job, 'stdout', '[secret-scan] übersprungen');
        }

        // 7z-tmpDir aufräumen (falls wir es angelegt haben)
        if (secretTmpDir) {
          await fsp.rm(secretTmpDir, { recursive: true, force: true }).catch(() => {});
        }
      }

      // Shred password file and remove the upload artifact immediately.
      await shredUnlink(job.passwordFile);
      job.passwordFile = null;
      try {
        await fsp.unlink(job.uploadPath);
      } catch (_) {}
      // Pre-Extract-Müll wegräumen (ZIP + stage-Dir).
      if (pre) await cleanupPreExtract(pre);

      // Schwachstellen-Scan: wenn extract-sbom eine CycloneDX-SBOM erzeugt
      // hat, grype gegen sie laufen lassen und einen farbig kategorisierten
      // HTML-Bericht plus die rohe JSON-Datei ins Output-Verzeichnis legen.
      if (job.state === 'done') {
        try {
          const entries = await fsp.readdir(job.outDir);
          const cdx = entries.find((n) => /\.cdx\.json$/i.test(n));
          if (cdx) {
            const cdxPath = path.join(job.outDir, cdx);

            // 1. Schwachstellen-Scan → JSON + HTML + CSV
            this.sessions.pushLog(sess, job, 'stdout', `[vuln-report] running grype on ${cdx}`);
            const vr = await runVulnReport({
              cdxJsonPath: cdxPath,
              outDir: job.outDir,
              inputName: job.inputName,
              logger: this.logger,
              jobId: job.id,
            });
            if (vr.ranGrype) {
              const summary =
                vr.total === 0
                  ? 'keine bekannten Schwachstellen'
                  : Object.entries(vr.counts)
                      .filter(([, n]) => n > 0)
                      .map(([s, n]) => `${s}=${n}`)
                      .join(' ');
              this.sessions.pushLog(
                sess,
                job,
                'stdout',
                `[vuln-report] ${vr.total} Treffer (${summary})`
              );
              if (vr.csvPath) {
                this.sessions.pushLog(
                  sess,
                  job,
                  'stdout',
                  `[csv] vulnerabilities.csv geschrieben (${vr.total} Zeilen)`
                );
              }
            } else {
              this.sessions.pushLog(
                sess,
                job,
                'stdout',
                `[vuln-report] übersprungen (grype nicht verfügbar oder fehlgeschlagen)`
              );
            }

            // ── Enterprise pre-processing (synchronous lookups) ───────────────

            // Parse grype matches for enterprise lookups
            let grypeMatchesForEnterprise: Array<{
              id: string; severity: string; pkgName: string; pkgVersion: string;
              pkgType: string; pkgPurl?: string;
              fixVersion?: string; description?: string;
            }> = [];
            if (vr.ranGrype && vr.jsonPath) {
              try {
                const grypeRaw = JSON.parse(await fsp.readFile(vr.jsonPath!, 'utf8')) as {
                  matches?: Array<{
                    vulnerability?: {
                      id?: string; severity?: string;
                      fix?: { versions?: string[] }; description?: string;
                    };
                    artifact?: { name?: string; version?: string; type?: string; purl?: string };
                  }>;
                };
                grypeMatchesForEnterprise = (grypeRaw.matches ?? []).map((m) => ({
                  id: m.vulnerability?.id ?? '',
                  severity: m.vulnerability?.severity ?? 'Unknown',
                  pkgName: m.artifact?.name ?? '',
                  pkgVersion: m.artifact?.version ?? '',
                  pkgType: m.artifact?.type ?? '',
                  pkgPurl: m.artifact?.purl,
                  fixVersion: m.vulnerability?.fix?.versions?.join(', '),
                  description: m.vulnerability?.description?.slice(0, 512),
                }));
              } catch { /* graceful */ }
            }

            // Parse CDX components for EOL + typosquat
            let cdxComponents: Array<{ name: string; version?: string; type?: string; purl?: string }> = [];
            try {
              const cdxRaw = JSON.parse(await fsp.readFile(cdxPath, 'utf8')) as {
                components?: Array<{ name?: string; version?: string; type?: string; purl?: string }>;
              };
              cdxComponents = (cdxRaw.components ?? []).map((c) => ({
                name: c.name ?? '',
                version: c.version,
                type: c.type,
                purl: c.purl,
              }));
            } catch { /* graceful */ }

            // 1. EOL Detection
            const eolHits: Array<{ name: string; version: string; info: import('./eol').EolInfo }> = [];
            for (const comp of cdxComponents) {
              if (!comp.name || !comp.version) continue;
              const info = lookupEol(comp.name, comp.version);
              if (info) eolHits.push({ name: comp.name, version: comp.version, info });
            }
            if (eolHits.length > 0) {
              this.sessions.pushLog(sess, job, 'stdout',
                `[eol] ${eolHits.length} EOL-Komponente(n) gefunden`);
            }

            // 2. Typosquat Detection
            const typosquatHits = detectTyposquat(
              cdxComponents.map((c) => ({ name: c.name, type: c.type }))
            );
            if (typosquatHits.length > 0) {
              this.sessions.pushLog(sess, job, 'stdout',
                `[typosquat] ${typosquatHits.length} mögliche(r) Typosquat(s)`);
            }

            // 3. KEV + 4. EPSS lookups
            const kevMapForReport = new Map<string, KevDetails>();
            const epssMapForReport = new Map<string, EpssScore>();
            for (const m of grypeMatchesForEnterprise) {
              if (!m.id) continue;
              const ke = kevEntry(m.id);
              if (ke) kevMapForReport.set(m.id.toUpperCase(), ke);
              const es = epssFor(m.id);
              if (es) epssMapForReport.set(m.id.toUpperCase(), es);
            }
            const kevCount = kevMapForReport.size;
            if (kevCount > 0) {
              this.sessions.pushLog(sess, job, 'stdout',
                `[kev] ${kevCount} CVE(s) in CISA KEV-Liste`);
            }

            // 5. Policy Evaluation
            const policyMetrics = {
              criticalCount: vr.counts['Critical'] ?? 0,
              highCount: vr.counts['High'] ?? 0,
              mediumCount: vr.counts['Medium'] ?? 0,
              lowCount: vr.counts['Low'] ?? 0,
              kevCount,
              eolCount: eolHits.length,
              typosquatCount: typosquatHits.length,
              grade: 'A', // will be filled after summary, placeholder
              score: 100,
            };
            const policyResult = evaluatePolicy(policyMetrics);
            this.sessions.pushLog(sess, job, 'stdout',
              `[policy] ${policyResult.passed ? 'bestanden' : 'NICHT bestanden'} (${policyResult.results.filter((r) => r.triggered).length} Regeln ausgelöst)`);

            // Zusätzliche Scanner: trivy + osv-scanner
            let extraScanResult: ExtraScanResult | null = null;
            try {
              extraScanResult = await runExtraScanners({
                cdxJsonPath: cdxPath,
                outDir: job.outDir,
                inputName: job.inputName,
                logger: this.logger,
                jobId: job.id,
              });
              const xSummary = [
                extraScanResult.ranTrivy ? `trivy: ${extraScanResult.counts.Critical}C/${extraScanResult.counts.High}H` : '',
                extraScanResult.ranOsv ? `osv: ${extraScanResult.findings.length} Befunde` : '',
              ].filter(Boolean).join(', ');
              this.sessions.pushLog(
                sess,
                job,
                'stdout',
                `[extra-scan] ${xSummary || 'keine zusätzlichen Scanner verfügbar'}`
              );
              if (extraScanResult.maliciousPackages.length > 0) {
                this.sessions.pushLog(
                  sess,
                  job,
                  'stdout',
                  `[extra-scan] ⚠ ${extraScanResult.maliciousPackages.length} bösartige Pakete erkannt!`
                );
              }
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'extra-scan: Fehler (nicht-fatal)');
            }

            // CBOM aus CycloneDX-Komponenten ableiten
            let cbomResult: CbomResult | null = null;
            try {
              cbomResult = await buildCbom({
                cdxJsonPath: cdxPath,
                outDir: job.outDir,
                inputName: job.inputName,
                logger: this.logger,
                jobId: job.id,
              });
              this.sessions.pushLog(
                sess,
                job,
                'stdout',
                `[cbom] ${cbomResult.components.length} Krypto-Komponenten${cbomResult.weakCount > 0 ? ` · ${cbomResult.weakCount} schwach` : ''}`
              );
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'cbom: Fehler (nicht-fatal)');
            }

            // 2. Kombinierter Gesamtübersicht-Bericht (Komponenten + CVEs +
            //    Lizenzen + Restrisiken + Extra-Sektionen in einem HTML).
            const reportMd = entries.find((n) => /\.report\.md$/i.test(n));
            const extrasForSummary: SummaryExtras = {
              extraScan: extraScanResult,
              secrets: secretScanResult,
              cbom: cbomResult,
              binary: binaryScanResult,
            };
            const summaryRes = await buildSummaryReport({
              cdxJsonPath: cdxPath,
              grypeJsonPath: vr.ranGrype ? vr.jsonPath : null,
              reportMdPath: reportMd ? path.join(job.outDir, reportMd) : null,
              outDir: job.outDir,
              inputName: job.inputName,
              jobId: job.id,
              logger: this.logger,
              kevMap: kevMapForReport,
              epssMap: epssMapForReport,
              eolHits,
              typosquatHits,
              policyResult,
              extras: extrasForSummary,
            });
            if (summaryRes.htmlPath) {
              this.sessions.pushLog(
                sess,
                job,
                'stdout',
                `[summary] Gesamtübersicht: ${summaryRes.componentCount} Komponenten, ${summaryRes.vulnTotal} CVEs → ${path.basename(summaryRes.htmlPath)}`
              );
            }

            // 3. SPDX-Export via syft convert
            try {
              const base = path.basename(cdx).replace(/\.cdx\.json$/i, '');
              const spdxPath = path.join(job.outDir, `${base}.spdx.json`);
              const sr = await runSyftConvert(cdxPath, spdxPath, 60_000);
              if (sr.code === 0) {
                this.sessions.pushLog(sess, job, 'stdout', `[spdx] spdx.json geschrieben`);
              } else {
                this.logger.warn(
                  { jobId: job.id, code: sr.code, stderr: sr.stderr.slice(0, 400) },
                  'spdx: syft convert failed (non-fatal)'
                );
              }
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'spdx: syft not available (non-fatal)');
            }

            // 4. VEX-Skelett aus grype-JSON
            if (vr.ranGrype && vr.jsonPath) {
              try {
                const vexRes = await writeVexSkeleton({
                  grypeJsonPath: vr.jsonPath,
                  outDir: job.outDir,
                  inputName: job.inputName,
                  logger: this.logger,
                  jobId: job.id,
                });
                if (vexRes.vexPath) {
                  this.sessions.pushLog(
                    sess,
                    job,
                    'stdout',
                    `[vex] vex.json Skelett mit ${vexRes.count} Einträgen`
                  );
                }
              } catch (e) {
                this.logger.warn({ jobId: job.id, err: e }, 'vex: generation failed (non-fatal)');
              }

              // 5. OpenVEX
              try {
                await writeOpenVex({
                  grypeJsonPath: vr.jsonPath,
                  outDir: job.outDir,
                  inputName: job.inputName,
                  jobId: job.id,
                  logger: this.logger,
                });
                this.sessions.pushLog(sess, job, 'stdout', '[openvex] geschrieben');
              } catch (e) {
                this.logger.warn({ jobId: job.id, err: e }, 'openvex: generation failed (non-fatal)');
              }

              // 6. CSAF
              try {
                await writeCsaf({
                  grypeJsonPath: vr.jsonPath,
                  outDir: job.outDir,
                  inputName: job.inputName,
                  jobId: job.id,
                  logger: this.logger,
                });
                this.sessions.pushLog(sess, job, 'stdout', '[csaf] geschrieben');
              } catch (e) {
                this.logger.warn({ jobId: job.id, err: e }, 'csaf: generation failed (non-fatal)');
              }
            }

            // 7. SLSA Provenance
            try {
              await writeSlsa({
                cdxJsonPath: cdxPath,
                outDir: job.outDir,
                inputName: job.inputName,
                inputSha256: job.inputSha256,
                jobId: job.id,
                logger: this.logger,
              });
              this.sessions.pushLog(sess, job, 'stdout', '[slsa] geschrieben');
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'slsa: generation failed (non-fatal)');
            }

            // 8. SIEM Export
            try {
              const siemFindings = buildFindings({
                timestamp: new Date().toISOString(),
                artifact: job.inputName,
                artifactSha256: job.inputSha256,
                jobId: job.id,
                vulnMatches: grypeMatchesForEnterprise.map((m) => ({
                  ...m,
                  isKev: isKev(m.id),
                  epss: epssFor(m.id)?.score,
                  epssPercentile: epssFor(m.id)?.percentile,
                })),
                eolHits: eolHits.map(({ name, version, info }) => ({
                  name, version, eolDate: info.eolDate, isExpired: info.isExpired,
                })),
                typosquatHits,
              });
              await writeSiemExport({
                outDir: job.outDir,
                inputName: job.inputName,
                inputSha256: job.inputSha256,
                jobId: job.id,
                findings: siemFindings,
                logger: this.logger,
              });
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'siem: export failed (non-fatal)');
            }

            // 9. Compliance Reports
            try {
              const base = path.basename(cdx).replace(/\.cdx\.json$/i, '');
              await writeComplianceReports({
                outDir: job.outDir,
                inputName: job.inputName,
                jobId: job.id,
                cdxBasename: base,
                inputSha256: job.inputSha256,
                componentCount: summaryRes.componentCount,
                vulnTotal: summaryRes.vulnTotal,
                criticalCount: vr.counts['Critical'] ?? 0,
                highCount: vr.counts['High'] ?? 0,
                kevCount,
                eolCount: eolHits.length,
                typosquatCount: typosquatHits.length,
                policyResult,
                logger: this.logger,
              });
              this.sessions.pushLog(sess, job, 'stdout', '[compliance] 4 Compliance-Vorlagen erstellt');
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'compliance: failed (non-fatal)');
            }

            // 10. VEX Merge (apply any pre-existing VEX entries into vex.json)
            try {
              const vexJsonName = entries.find((n) => /\.vex\.json$/i.test(n));
              if (vexJsonName) {
                await mergeVexIntoFile(
                  path.join(job.outDir, vexJsonName),
                  job.inputSha256,
                  job.id,
                  this.logger
                );
              }
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'vex-store: merge failed (non-fatal)');
            }

            // 11. Cosign Signing (optional, only if env keys set)
            try {
              const allEntries = await fsp.readdir(job.outDir);
              const filesToSign = allEntries
                .filter((n) => /\.(json|html)$/i.test(n))
                .map((n) => path.join(job.outDir, n));
              await signWithCosign({ filesToSign, outDir: job.outDir, logger: this.logger });
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'cosign: signing failed (non-fatal)');
            }

            // 12. Catalog Upsert
            try {
              upsertCatalog({
                jobId: job.id,
                components: cdxComponents.map((c) => ({
                  name: c.name,
                  type: c.type ?? 'unknown',
                  version: c.version,
                  purl: c.purl,
                })),
                cves: grypeMatchesForEnterprise.map((m) => ({
                  id: m.id,
                  pkgName: m.pkgName,
                  pkgVersion: m.pkgVersion,
                  pkgType: m.pkgType,
                  pkgPurl: m.pkgPurl,
                  severity: m.severity,
                })),
                logger: this.logger,
              });
            } catch (e) {
              this.logger.warn({ jobId: job.id, err: e }, 'catalog: upsert failed (non-fatal)');
            }
          }
        } catch (e) {
          this.logger.warn({ jobId: job.id, err: e }, 'vuln-report failed');
        }
      }

      // Hash-Cache: Ergebnis registrieren (nur bei erfolgreichen Jobs)
      if (job.state === 'done' && inputHash) {
        register(inputHash, job.id, job.outDir);
      }

      // Audit: job_finished
      writeAuditEntry({
        ts: new Date().toISOString(),
        event: 'job_finished',
        sid: sess.sid,
        jobId: job.id,
        inputName: job.inputName,
        inputSha256: job.inputSha256 ?? undefined,
        state: job.state,
        durationMs: job.startedAt ? Date.now() - job.startedAt : 0,
      }).catch(() => {});

      await this.sessions.refreshOutputs(sess, job);
      this.sessions.touch(sess);
      this.sessions.broadcast(sess, 'state', this.sessions.snapshot(sess));

      this.logger.info(
        { sid: sess.sid, jobId: job.id, code, signal, state: job.state },
        'job finished'
      );

      // Process next queued job, if any.
      this.runNext(sess);
    });
  }

  private async preparePasswords(
    sess: Session,
    job: Job
  ): Promise<{ passwords: string[] }> {
    // Passwords were already parsed into an array before enqueue; we stored
    // them temporarily on the job via a private trick — see enqueue().
    // Because Job doesn't carry the plaintext array past enqueue, we re-derive
    // from job.passwordCount to avoid storing them. BUT since we do need them
    // for transport selection we use the internal holder.
    // The actual passwords array is plumbed in via _pendingPasswords below.
    const passwords: string[] = (job as JobWithPending)._pendingPasswords ?? [];

    if (passwords.length === 0) {
      job.passwordTransport = 'none';
      return { passwords };
    }

    const hasComma = passwords.some((p) => p.includes(','));
    if (!hasComma) {
      job.passwordTransport = 'env';
    } else {
      const pwFile = path.join(sess.dir, `passwords-${job.id}.txt`);
      await fsp.writeFile(pwFile, passwords.join('\n') + '\n', { mode: 0o600 });
      job.passwordFile = pwFile;
      job.passwordTransport = 'file';
    }

    // Erase the in-memory plaintext copy as soon as it's no longer needed.
    delete (job as JobWithPending)._pendingPasswords;
    return { passwords };
  }

  // --------------------------------------------------------------------------
  // Cancel
  // --------------------------------------------------------------------------

  cancel(sess: Session): void {
    const job = this.sessions.runningJob(sess);
    if (!job || job.state !== 'running' || !job.child) return;
    try {
      job.child.kill('SIGTERM');
    } catch (_) {}
    const child = job.child;
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (_) {}
    }, 5000);
    // Don't keep Node alive just for the escalation timeout.
    if (t.unref) t.unref();
  }
}

// ── SPDX export via syft convert ─────────────────────────────────────────────

function runSyftConvert(
  cdxPath: string,
  spdxOutPath: string,
  timeoutMs: number
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      'syft',
      ['convert', cdxPath, '-o', `spdx-json=${spdxOutPath}`],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );
    let stderr = '';
    child.stderr?.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code: code ?? -1, stderr });
    });
    child.on('error', (e: Error) => {
      clearTimeout(t);
      resolve({ code: -1, stderr: e.message });
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────

// ── Decompression-Bomb-Schutz für den Secret-Scan-Fallback ──────────────────

// Obergrenze für die unkomprimierte Gesamtgröße eines Archivs, das wir für
// den Secret-Scan auspacken. Liegt die von `7z l` gemeldete Größe darüber,
// wird das Auspacken übersprungen (mögliche Decompression-Bomb).
const MAX_SECRET_EXTRACT_BYTES = 4 * 1024 * 1024 * 1024; // 4 GiB

// Ermittelt die unkomprimierte Gesamtgröße eines Archivs via `7z l -slt`,
// ohne es zu entpacken.
//   • exit 0          → Summe der gemeldeten Entry-Größen
//   • Listing zu groß / zu langsam (Millionen Einträge) → Number.MAX_SAFE_INTEGER,
//     damit der Aufrufer das Auspacken überspringt (Bomb-Verdacht)
//   • 7z kann nicht auflisten → null (regulärer Extraktionsversuch folgt)
function probe7zUncompressedSize(archivePath: string): Promise<number | null> {
  return new Promise((resolve) => {
    let out = '';
    let done = false;
    let aborted = false; // wegen Output-Cap oder Timeout abgebrochen
    const finish = (v: number | null) => { if (!done) { done = true; resolve(v); } };
    const child = spawn('7z', ['l', '-slt', archivePath], { stdio: ['ignore', 'pipe', 'ignore'] });
    child.stdout.on('data', (b: Buffer) => {
      out += b.toString('utf8');
      // Ausgabe begrenzen — ein Archiv mit Millionen Einträgen darf den
      // Speicher nicht sprengen und ist ohnehin Bomb-verdächtig.
      if (out.length > 32 * 1024 * 1024) { aborted = true; try { child.kill('SIGKILL'); } catch (_) {} }
    });
    const t = setTimeout(() => { aborted = true; try { child.kill('SIGKILL'); } catch (_) {} }, 60_000);
    child.on('exit', (code) => {
      clearTimeout(t);
      if (aborted) { finish(Number.MAX_SAFE_INTEGER); return; }
      if (code !== 0) { finish(null); return; }
      let total = 0;
      for (const m of out.matchAll(/^Size = (\d+)$/gm)) {
        total += Number(m[1]);
      }
      finish(total);
    });
    child.on('error', () => { clearTimeout(t); finish(null); });
  });
}

// ─────────────────────────────────────────────────────────────────────────────

// Internal helper type: jobs carry their plaintext password array only until
// the job is launched, at which point the field is deleted.
type JobWithPending = Job & { _pendingPasswords?: string[] };

