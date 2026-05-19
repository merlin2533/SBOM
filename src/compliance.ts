// ─────────────────────────────────────────────────────────────────────────────
// Compliance Report Generator
//
// Generates standalone HTML compliance reports for:
//   BSI Grundschutz, ISO 27001, NIST 800-53, EU CRA
// One file per standard: <base>.compliance-<std>.html
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';
import type { PolicyResult } from './policy';

export interface ComplianceOpts {
  outDir: string;
  inputName: string;
  jobId: string;
  cdxBasename: string;    // e.g. "myimage.cdx" (without .json)
  inputSha256: string | null;
  componentCount: number;
  vulnTotal: number;
  criticalCount: number;
  highCount: number;
  kevCount: number;
  eolCount: number;
  typosquatCount: number;
  policyResult: PolicyResult | null;
  logger: pino.Logger;
}

export interface ComplianceResult {
  paths: string[];
}

const APP_VERSION = '2.10.0';

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]!
  );
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const STYLES = `
:root{color-scheme:light dark;
--bg:#f6f7fb;--card:#fff;--fg:#0e1320;--muted:#6a7184;--border:#e3e7f1;
--accent:#002b7f;--accent-2:#1a4fb0;--accent-soft:#e6ecf6;}
@media(prefers-color-scheme:dark){:root{
--bg:#07090f;--card:#10131c;--fg:#ecf0f6;--muted:#8a93a8;--border:#232a3a;
--accent:#6c8dd9;--accent-2:#8aa9ea;--accent-soft:#0e1a35;}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem 4rem;background:var(--bg);color:var(--fg);
font-family:"Inter",ui-sans-serif,system-ui,sans-serif;line-height:1.6;font-size:15px}
main{max-width:960px;margin:0 auto;background:var(--card);border:1px solid var(--border);
border-radius:16px;padding:2rem 2.2rem;box-shadow:0 6px 24px rgba(0,43,127,.08)}
h1{color:var(--accent);font-size:1.5rem;margin-top:0;border-bottom:2px solid var(--accent);padding-bottom:.5rem}
h2{color:var(--accent);font-size:1.1rem;margin-top:0}
.standard-header{background:var(--accent-soft);border:1px solid var(--border);border-radius:10px;
padding:1rem 1.2rem;margin-bottom:1.5rem}
.standard-name{font-size:1.3rem;font-weight:800;color:var(--accent);letter-spacing:-.01em}
.standard-desc{font-size:.9rem;color:var(--muted);margin-top:.3rem}
details.control{border:1px solid var(--border);border-radius:10px;margin:.7rem 0;overflow:hidden}
details.control>summary{display:flex;align-items:center;gap:.6rem;cursor:pointer;
padding:.65rem 1rem;background:var(--accent-soft);border-bottom:1px solid var(--border);
list-style:none;user-select:none;font-weight:600}
details.control>summary::-webkit-details-marker{display:none}
details.control:not([open])>summary{border-bottom-color:transparent}
.control-id{font-family:ui-monospace,monospace;font-size:.78rem;padding:.15rem .55rem;
background:var(--accent);color:#fff;border-radius:6px;white-space:nowrap}
.control-body{padding:1rem 1.2rem;font-size:.92rem}
.evidence-block{margin-top:.8rem;padding:.8rem 1rem;background:var(--accent-soft);
border-left:3px solid var(--accent);border-radius:0 8px 8px 0;font-size:.88rem}
.evidence-label{font-weight:700;font-size:.75rem;letter-spacing:.1em;text-transform:uppercase;
color:var(--accent);margin-bottom:.4rem}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.3rem .8rem;font-size:.85rem}
.kv-k{color:var(--muted);white-space:nowrap}
.kv-v{font-weight:600;font-family:ui-monospace,monospace;word-break:break-all}
.status-ok{color:#15803d;font-weight:700}
.status-warn{color:#d97706;font-weight:700}
.status-fail{color:#b91c1c;font-weight:700}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);
color:var(--muted);font-size:.8rem;line-height:1.7}
.disclaimer{margin-top:.5rem;padding:.6rem .8rem;background:#fef9c3;color:#854d0e;
border:1px solid #d97706;border-radius:6px;font-size:.8rem}
@media(prefers-color-scheme:dark){.disclaimer{background:#2d1f00;color:#fbbf24;border-color:#92400e}}
`;

function wrapHtml(title: string, standardName: string, standardDesc: string, controls: string, generatedAt: string): string {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>${STYLES}</style>
</head>
<body>
<main>
<h1>${escapeHtml(title)}</h1>
<div class="standard-header">
<div class="standard-name">${escapeHtml(standardName)}</div>
<div class="standard-desc">${escapeHtml(standardDesc)}</div>
</div>
${controls}
<footer>
<div>Generiert am ${escapeHtml(generatedAt)} durch sbom-upload-app v${escapeHtml(APP_VERSION)}</div>
<div class="disclaimer">Maschinelle Aufbereitung auf Basis automatischer SBOM-Analyse — fachliche Prüfung durch qualifizierte Personen erforderlich. Kein Rechtsrat.</div>
</footer>
</main>
</body>
</html>`;
}

// ── Evidence block builder ────────────────────────────────────────────────────

function evidence(pairs: Array<[string, string, 'ok' | 'warn' | 'fail' | 'neutral']>): string {
  const rows = pairs.map(([k, v, status]) => {
    const cls = status === 'neutral' ? '' : ` class="status-${status}"`;
    return `<div class="kv-k">${escapeHtml(k)}</div><div class="kv-v"${cls}>${escapeHtml(v)}</div>`;
  }).join('');
  return `<div class="evidence-block"><div class="evidence-label">Nachweis (automatisch)</div><div class="kv">${rows}</div></div>`;
}

function control(id: string, title: string, desc: string, evidenceHtml: string): string {
  return `
<details class="control" open>
<summary><span class="control-id">${escapeHtml(id)}</span> ${escapeHtml(title)}</summary>
<div class="control-body">
<p>${escapeHtml(desc)}</p>
${evidenceHtml}
</div>
</details>`;
}

// ── Standard generators ───────────────────────────────────────────────────────

function genBsi(opts: ComplianceOpts, ts: string): string {
  const policyStatus = opts.policyResult
    ? (opts.policyResult.passed ? 'Bestanden' : 'NICHT bestanden')
    : 'Nicht ausgewertet';
  const policyStatusType = opts.policyResult
    ? (opts.policyResult.passed ? 'ok' : 'fail')
    : 'neutral';

  const app44 = control(
    'APP.4.4',
    'Webanwendungen und Web-Services',
    'Webanwendungen müssen regelmäßig auf bekannte Schwachstellen geprüft und die verwendeten Komponenten auf dem aktuellen Stand gehalten werden. Eine SBOM ist Grundlage für die Nachvollziehbarkeit der eingesetzten Software.',
    evidence([
      ['Artefakt', opts.inputName, 'neutral'],
      ['SHA-256', opts.inputSha256 ?? 'nicht verfügbar', 'neutral'],
      ['Komponenten im SBOM', String(opts.componentCount), opts.componentCount > 0 ? 'ok' : 'warn'],
      ['CVE gesamt', String(opts.vulnTotal), opts.vulnTotal === 0 ? 'ok' : opts.criticalCount > 0 ? 'fail' : 'warn'],
      ['Critical CVEs', String(opts.criticalCount), opts.criticalCount === 0 ? 'ok' : 'fail'],
      ['KEV-Treffer', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
    ])
  );

  const con8 = control(
    'CON.8',
    'Software-Entwicklung',
    'Im Rahmen der Software-Entwicklung müssen verwendete Drittbibliotheken und deren Lizenzen transparent dokumentiert und auf Sicherheitsprobleme geprüft werden.',
    evidence([
      ['SBOM-Datei vorhanden', opts.cdxBasename ? 'Ja' : 'Nein', opts.cdxBasename ? 'ok' : 'fail'],
      ['Abhängigkeiten EOL', String(opts.eolCount), opts.eolCount === 0 ? 'ok' : 'warn'],
      ['Mögliche Typosquats', String(opts.typosquatCount), opts.typosquatCount === 0 ? 'ok' : 'warn'],
    ])
  );

  const ops112 = control(
    'OPS.1.1.2',
    'Patch- und Änderungsmanagement',
    'Schwachstellen in eingesetzter Software müssen zeitnah identifiziert, bewertet und durch Patches oder andere Maßnahmen behoben werden.',
    evidence([
      ['Vulnerability-Scan durchgeführt', opts.vulnTotal >= 0 ? 'Ja' : 'Nein', 'ok'],
      ['High CVEs', String(opts.highCount), opts.highCount === 0 ? 'ok' : 'warn'],
      ['Policy-Evaluation', policyStatus, policyStatusType],
    ])
  );

  return [app44, con8, ops112].join('\n');
}

function genIso27001(opts: ComplianceOpts, ts: string): string {
  const a57 = control(
    'A.5.7',
    'Bedrohungsanalyse (Threat Intelligence)',
    'Die Organisation muss Informationen über Bedrohungen sammeln und analysieren, um Sicherheitsrisiken zu verstehen und angemessen zu reagieren. KEV-Daten aus der CISA stellen offizielle Bedrohungsintelligenz dar.',
    evidence([
      ['CISA KEV-Treffer', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
      ['EPSS-Daten genutzt', 'Ja (wenn verfügbar)', 'neutral'],
      ['Vulnerability-Scan-Tool', 'grype', 'neutral'],
    ])
  );

  const a523 = control(
    'A.5.23',
    'Informationssicherheit bei der Nutzung von Cloud-Diensten',
    'Cloud-basierte Softwarekomponenten müssen sicherheitsrelevant bewertet und überwacht werden. SBOM-basierte Analyse unterstützt die Bewertung von Cloud-Abhängigkeiten.',
    evidence([
      ['Komponenten-Inventar', `${opts.componentCount} Komponenten`, opts.componentCount > 0 ? 'ok' : 'warn'],
      ['Artefakt-Hash', opts.inputSha256 ? 'SHA-256 vorhanden' : 'Nicht verfügbar', opts.inputSha256 ? 'ok' : 'warn'],
    ])
  );

  const a88 = control(
    'A.8.8',
    'Management technischer Schwachstellen',
    'Technische Schwachstellen in Informationssystemen müssen zeitnah identifiziert, bewertet und adressiert werden.',
    evidence([
      ['CVE gesamt', String(opts.vulnTotal), opts.vulnTotal === 0 ? 'ok' : 'warn'],
      ['Critical CVEs', String(opts.criticalCount), opts.criticalCount === 0 ? 'ok' : 'fail'],
      ['High CVEs', String(opts.highCount), opts.highCount === 0 ? 'ok' : 'warn'],
      ['KEV-Treffer', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
      ['EOL-Komponenten', String(opts.eolCount), opts.eolCount === 0 ? 'ok' : 'warn'],
    ])
  );

  const a830 = control(
    'A.8.30',
    'Ausgelagerte Entwicklung',
    'Bei ausgelagerter Softwareentwicklung muss die Qualität und Sicherheit der gelieferten Software durch Kontrollen sichergestellt werden. Eine SBOM ist ein zentrales Nachweisdokument.',
    evidence([
      ['SBOM vorhanden', opts.cdxBasename ? 'Ja' : 'Nein', opts.cdxBasename ? 'ok' : 'fail'],
      ['Mögliche Typosquats', String(opts.typosquatCount), opts.typosquatCount === 0 ? 'ok' : 'warn'],
      ['Policy-Ergebnis', opts.policyResult ? (opts.policyResult.passed ? 'Bestanden' : 'Nicht bestanden') : 'N/A', opts.policyResult?.passed ? 'ok' : 'warn'],
    ])
  );

  return [a57, a523, a88, a830].join('\n');
}

function genNist80053(opts: ComplianceOpts, _ts: string): string {
  const sr3 = control(
    'SR-3',
    'Supply Chain Controls and Processes',
    'Die Organisation implementiert Prozesse zur Kontrolle der Supply Chain, um die Integrität und Sicherheit von Systemkomponenten sicherzustellen.',
    evidence([
      ['SBOM vorhanden', opts.cdxBasename ? 'Ja (CycloneDX)' : 'Nein', opts.cdxBasename ? 'ok' : 'fail'],
      ['Artefakt SHA-256', opts.inputSha256 ?? 'Nicht verfügbar', opts.inputSha256 ? 'ok' : 'warn'],
      ['Mögliche Typosquats', String(opts.typosquatCount), opts.typosquatCount === 0 ? 'ok' : 'warn'],
    ])
  );

  const sr4 = control(
    'SR-4',
    'Provenance',
    'Die Herkunft von Systemkomponenten und deren Entwicklungsprozess muss nachvollziehbar und dokumentiert sein.',
    evidence([
      ['Komponenten-Inventar', `${opts.componentCount} Komponenten im CycloneDX-SBOM`, opts.componentCount > 0 ? 'ok' : 'warn'],
      ['Job-ID', opts.jobId, 'neutral'],
      ['Eingabe-Artefakt', opts.inputName, 'neutral'],
    ])
  );

  const cm8 = control(
    'CM-8',
    'System Component Inventory',
    'Die Organisation führt und pflegt ein aktuelles Inventar aller Systemkomponenten.',
    evidence([
      ['Komponenten erfasst', String(opts.componentCount), opts.componentCount > 0 ? 'ok' : 'fail'],
      ['CVE-Scan', opts.vulnTotal >= 0 ? 'Durchgeführt' : 'Nicht durchgeführt', 'ok'],
      ['EOL-Komponenten', String(opts.eolCount), opts.eolCount === 0 ? 'ok' : 'warn'],
    ])
  );

  const sa11 = control(
    'SA-11',
    'Developer Testing and Evaluation',
    'Entwickler und Lieferanten müssen Sicherheitstests durchführen und die Ergebnisse dokumentieren.',
    evidence([
      ['Vulnerability-Scan durchgeführt', 'Ja (automatisch via grype)', 'ok'],
      ['Critical CVEs', String(opts.criticalCount), opts.criticalCount === 0 ? 'ok' : 'fail'],
      ['KEV-Treffer', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
      ['Policy-Evaluation', opts.policyResult ? (opts.policyResult.passed ? 'Bestanden' : 'Nicht bestanden') : 'N/A', opts.policyResult?.passed ? 'ok' : 'warn'],
    ])
  );

  return [sr3, sr4, cm8, sa11].join('\n');
}

function genEuCra(opts: ComplianceOpts, _ts: string): string {
  const art13 = control(
    'Art. 13',
    'Meldepflichten (Reporting Obligations)',
    'Hersteller von Produkten mit digitalen Elementen müssen aktiv ausgenutzte Schwachstellen und schwerwiegende Vorfälle innerhalb von 24 Stunden nach Kenntnis melden.',
    evidence([
      ['CISA KEV-Treffer (aktiv ausgenutzt)', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
      ['Critical CVEs (meldepflichtig relevant)', String(opts.criticalCount), opts.criticalCount === 0 ? 'ok' : 'warn'],
      ['Scan-Zeitpunkt', new Date().toISOString(), 'neutral'],
    ])
  );

  const art14 = control(
    'Art. 14',
    'Behandlung von Schwachstellen (Vulnerability Handling)',
    'Hersteller müssen Schwachstellen während der gesamten erwarteten Produktlebensdauer systematisch behandeln und beheben. Eine SBOM ist ein Schlüsselinstrument für effektives Schwachstellenmanagement.',
    evidence([
      ['SBOM vorhanden', opts.cdxBasename ? 'Ja (CycloneDX-Format)' : 'Nein', opts.cdxBasename ? 'ok' : 'fail'],
      ['Komponenten-Inventar', `${opts.componentCount} Komponenten`, opts.componentCount > 0 ? 'ok' : 'warn'],
      ['CVE gesamt', String(opts.vulnTotal), opts.vulnTotal === 0 ? 'ok' : 'warn'],
      ['KEV-Treffer', String(opts.kevCount), opts.kevCount === 0 ? 'ok' : 'fail'],
      ['EOL-Komponenten', String(opts.eolCount), opts.eolCount === 0 ? 'ok' : 'warn'],
    ])
  );

  const annex1 = control(
    'Annex I',
    'Wesentliche Sicherheitsanforderungen (Essential Cybersecurity Requirements)',
    'Produkte mit digitalen Elementen müssen so konzipiert, entwickelt und gewartet werden, dass sie ein angemessenes Sicherheitsniveau bieten. Sie dürfen keine bekannten ausnutzbaren Schwachstellen enthalten.',
    evidence([
      ['Artefakt-Integrität (SHA-256)', opts.inputSha256 ?? 'Nicht verfügbar', opts.inputSha256 ? 'ok' : 'warn'],
      ['Bekannte ausnutzbare Schwachstellen (KEV)', opts.kevCount === 0 ? 'Keine gefunden' : `${opts.kevCount} Treffer — Handlungsbedarf`, opts.kevCount === 0 ? 'ok' : 'fail'],
      ['Critical CVEs', String(opts.criticalCount), opts.criticalCount === 0 ? 'ok' : 'fail'],
      ['Mögliche Lieferketten-Anomalien', String(opts.typosquatCount), opts.typosquatCount === 0 ? 'ok' : 'warn'],
      ['Policy-Ergebnis', opts.policyResult ? (opts.policyResult.passed ? 'Bestanden' : 'NICHT bestanden — Anforderungen verletzt') : 'N/A', opts.policyResult?.passed ? 'ok' : 'fail'],
    ])
  );

  return [art13, art14, annex1].join('\n');
}

// ── Main export function ──────────────────────────────────────────────────────

export async function writeComplianceReports(opts: ComplianceOpts): Promise<ComplianceResult> {
  const { outDir, inputName, jobId, logger } = opts;
  const base = path.basename(inputName, path.extname(inputName));
  const ts = new Date().toISOString();
  const paths: string[] = [];

  const standards: Array<{
    id: string;
    name: string;
    desc: string;
    generator: (opts: ComplianceOpts, ts: string) => string;
  }> = [
    {
      id: 'bsi',
      name: 'BSI IT-Grundschutz',
      desc: 'Bundesamt für Sicherheit in der Informationstechnik — IT-Grundschutz-Kompendium',
      generator: genBsi,
    },
    {
      id: 'iso27001',
      name: 'ISO/IEC 27001:2022 (Annex A)',
      desc: 'Information security, cybersecurity and privacy protection — Annex A Controls',
      generator: genIso27001,
    },
    {
      id: 'nist80053',
      name: 'NIST SP 800-53 Rev. 5',
      desc: 'Security and Privacy Controls for Information Systems and Organizations',
      generator: genNist80053,
    },
    {
      id: 'eu-cra',
      name: 'EU Cyber Resilience Act (CRA)',
      desc: 'Regulation on horizontal cybersecurity requirements for products with digital elements',
      generator: genEuCra,
    },
  ];

  for (const std of standards) {
    try {
      const controls = std.generator(opts, ts);
      const title = `${std.name} — Compliance-Nachweis`;
      const html = wrapHtml(title, std.name, std.desc, controls, ts);
      const filePath = path.join(outDir, `${base}.compliance-${std.id}.html`);
      await fsp.writeFile(filePath, html, 'utf8');
      paths.push(filePath);
      logger.info({ jobId, standard: std.id, file: path.basename(filePath) }, 'compliance: written');
    } catch (e) {
      logger.warn({ jobId, standard: std.id, err: e }, 'compliance: generation failed (non-fatal)');
    }
  }

  return { paths };
}
