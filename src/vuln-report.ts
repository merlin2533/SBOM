// ─────────────────────────────────────────────────────────────────────────────
// CVE-Schwachstellen-Analyzer
//
// Nach erfolgreicher extract-sbom-Ausführung läuft `grype` auf der erzeugten
// CycloneDX-SBOM. Ergebnis:
//   <basename>.vulnerabilities.json   — Rohdaten von grype (json)
//   <basename>.vulnerabilities.html   — farbig nach Severity sortierter Bericht
//
// Severity-Ordnung:
//   Critical   #b91c1c
//   High       #dc2626
//   Medium     #d97706
//   Low        #65a30d
//   Negligible #6b7280
//   Unknown    #9ca3af
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import type pino from 'pino';

export interface VulnReportOpts {
  cdxJsonPath: string;
  outDir: string;
  inputName: string;          // Original-Artefaktname für Titel und Dateinamen
  logger: pino.Logger;
  jobId: string;
}

export interface VulnReportResult {
  ranGrype: boolean;
  jsonPath: string | null;
  htmlPath: string | null;
  csvPath: string | null;
  counts: Record<Severity, number>;
  total: number;
}

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
const SEVERITY_COLORS: Record<Severity, { fg: string; bg: string; border: string }> = {
  Critical:   { fg: '#7f1d1d', bg: '#fee2e2', border: '#b91c1c' },
  High:       { fg: '#9a3412', bg: '#ffedd5', border: '#dc2626' },
  Medium:     { fg: '#854d0e', bg: '#fef3c7', border: '#d97706' },
  Low:        { fg: '#365314', bg: '#ecfccb', border: '#65a30d' },
  Negligible: { fg: '#374151', bg: '#f3f4f6', border: '#6b7280' },
  Unknown:    { fg: '#4b5563', bg: '#f9fafb', border: '#9ca3af' },
};

interface GrypeMatch {
  vulnerability?: {
    id?: string;
    severity?: string;
    cvss?: Array<{ metrics?: { baseScore?: number } }>;
    fix?: { versions?: string[]; state?: string };
    urls?: string[];
    description?: string;
    dataSource?: string;
  };
  artifact?: {
    name?: string;
    version?: string;
    type?: string;
    purl?: string;
    locations?: Array<{ path?: string }>;
  };
  matchDetails?: Array<{ matcher?: string; type?: string }>;
}

interface GrypeOutput {
  matches?: GrypeMatch[];
  source?: { type?: string; target?: unknown };
  distro?: unknown;
  descriptor?: { name?: string; version?: string; db?: { built?: string; status?: string } };
}

/** RFC-4180 CSV field escaping. */
function csvField(s: string): string {
  if (/[,"\r\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/** Build RFC-4180 CSV (with UTF-8 BOM for Excel) from grype matches. */
function buildCsv(matches: GrypeMatch[]): string {
  const BOM = '﻿';
  const header = [
    'CVE', 'Severity', 'CVSS', 'Package', 'Version', 'Type', 'PURL',
    'Fix Versions', 'Fix State', 'Source URL', 'Description',
  ].map(csvField).join(',');

  // Sort: Severity order, then CVSS desc within same severity
  const severityRank: Record<string, number> = {
    Critical: 0, High: 1, Medium: 2, Low: 3, Negligible: 4, Unknown: 5,
  };
  const sorted = [...matches].sort((a, b) => {
    const ra = severityRank[normalizeSeverity(a.vulnerability?.severity)] ?? 5;
    const rb = severityRank[normalizeSeverity(b.vulnerability?.severity)] ?? 5;
    if (ra !== rb) return ra - rb;
    const sa = a.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
    const sb = b.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
    return sb - sa;
  });

  const rows = sorted.map((m) => {
    const v = m.vulnerability ?? {};
    const a = m.artifact ?? {};
    const sev = normalizeSeverity(v.severity);
    const cvss = v.cvss?.[0]?.metrics?.baseScore;
    const fixVersions = v.fix?.versions?.join('; ') ?? '';
    const fixState = v.fix?.state ?? '';
    const sourceUrl = (v.urls ?? [])[0] ?? (v.dataSource ?? '');
    const desc = (v.description ?? '').replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim();
    return [
      v.id ?? '',
      sev,
      cvss != null ? cvss.toFixed(1) : '',
      a.name ?? '',
      a.version ?? '',
      a.type ?? '',
      a.purl ?? '',
      fixVersions,
      fixState,
      sourceUrl,
      desc,
    ].map(csvField).join(',');
  });

  return BOM + [header, ...rows].join('\r\n') + '\r\n';
}

// CVE-Alter aus der ID (CVE-YYYY-NNNN) ableiten. Liefert ein farbiges Chip
// neben der CVE-ID, das auf einen Blick zeigt: dieses Jahr → rot, ≤2 J. →
// orange, ≤5 J. → gelb, älter → grau.
function cveAgeChip(id: string | undefined | null): string {
  if (!id) return '';
  const m = id.match(/^(?:CVE|GHSA|OSV|RUSTSEC|GLSA|DSA|USN|ALAS)-?(\d{4})[-_]/i);
  if (!m) return '';
  const year = parseInt(m[1]!, 10);
  const yearsOld = Math.max(0, new Date().getFullYear() - year);
  let bg: string, fg: string, border: string;
  if (yearsOld === 0)      { bg = '#fee2e2'; fg = '#7f1d1d'; border = '#b91c1c'; }
  else if (yearsOld <= 2)  { bg = '#ffedd5'; fg = '#9a3412'; border = '#ea580c'; }
  else if (yearsOld <= 5)  { bg = '#fef9c3'; fg = '#854d0e'; border = '#ca8a04'; }
  else                     { bg = '#f3f4f6'; fg = '#4b5563'; border = '#9ca3af'; }
  const label = yearsOld === 0 ? `${year} · neu` : `${year} · ${yearsOld} J.`;
  return `<span class="cve-age" title="CVE-Jahr: ${year}" style="background:${bg};color:${fg};border-color:${border}">${label}</span>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]!
  );
}

// Pfad(e) im hochgeladenen Artefakt, an denen das verwundbare Paket gefunden
// wurde — macht Befunde bei mehrteiligen Uploads zuordenbar.
function locationCell(locations?: Array<{ path?: string }>): string {
  if (!locations?.length) return '';
  const [first, ...rest] = [...new Set(
    locations.map((l) => l.path).filter((p): p is string => !!p && p.trim() !== '')
  )];
  if (!first) return '';
  const extra = rest.length ? ` <span class="muted">(+${rest.length})</span>` : '';
  return `<div class="loc-path mono small" title="${escapeHtml([first, ...rest].join('\n'))}">📁 ${escapeHtml(first)}${extra}</div>`;
}

function normalizeSeverity(raw: string | undefined): Severity {
  const s = (raw ?? '').toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'negligible') return 'Negligible';
  return 'Unknown';
}

function which(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn('sh', ['-c', `command -v ${cmd} >/dev/null 2>&1`], {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.on('exit', (code) => resolve(code === 0));
    child.on('error', () => resolve(false));
  });
}

function runGrype(
  cdxPath: string,
  outJsonPath: string,
  timeoutMs: number
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const outStream = fs.createWriteStream(outJsonPath);
    const child = spawn(
      'grype',
      [`sbom:${cdxPath}`, '-o', 'json', '--quiet'],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stderr = '';
    child.stdout.pipe(outStream);
    child.stderr.on('data', (b) => { stderr += b.toString('utf8'); });
    const t = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      outStream.end();
      resolve({ code: code ?? -1, stderr });
    });
    child.on('error', (e) => {
      clearTimeout(t);
      outStream.end();
      resolve({ code: -1, stderr: e.message });
    });
  });
}

/**
 * Vollständige HTML-Seite mit den Befunden, sortiert nach Severity, farblich
 * kodiert; soll auch als Standalone-Download taugen (inlined Styles).
 */
function buildHtmlReport(opts: {
  inputName: string;
  matches: GrypeMatch[];
  counts: Record<Severity, number>;
  total: number;
  grypeDescriptor?: GrypeOutput['descriptor'];
}): string {
  const { inputName, matches, counts, total, grypeDescriptor } = opts;

  // Gruppieren nach Severity, jeweils nach Score absteigend sortieren.
  const groups: Record<Severity, GrypeMatch[]> = {
    Critical: [], High: [], Medium: [], Low: [], Negligible: [], Unknown: [],
  };
  for (const m of matches) {
    groups[normalizeSeverity(m.vulnerability?.severity)].push(m);
  }
  for (const k of SEVERITY_ORDER) {
    groups[k].sort((a, b) => {
      const sa = a.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
      const sb = b.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
      return sb - sa;
    });
  }

  const cardsByGroup = SEVERITY_ORDER.map((sev) => {
    if (groups[sev].length === 0) return '';
    const c = SEVERITY_COLORS[sev];
    const rows = groups[sev].map((m) => {
      const v = m.vulnerability ?? {};
      const a = m.artifact ?? {};
      const fix = v.fix?.versions?.length
        ? v.fix.versions.join(', ')
        : (v.fix?.state === 'not-fixed' ? '— (kein Fix verfügbar)' : '—');
      const links = (v.urls ?? []).slice(0, 3).map((u) =>
        `<a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(
          u.replace(/^https?:\/\//, '').replace(/\/$/, '').slice(0, 60)
        )}</a>`
      ).join(' · ');
      const score = v.cvss?.[0]?.metrics?.baseScore;
      const scoreCell = score != null ? score.toFixed(1) : '—';
      const desc = (v.description ?? '').replace(/\s+/g, ' ').trim();
      return `
        <tr>
          <td class="cve mono">${escapeHtml(v.id ?? '?')}${cveAgeChip(v.id)}</td>
          <td class="pkg">
            <strong>${escapeHtml(a.name ?? '?')}</strong>
            <span class="muted">@</span>
            <span class="mono">${escapeHtml(a.version ?? '?')}</span>
            ${a.type ? `<div class="muted small">${escapeHtml(a.type)}</div>` : ''}
            ${locationCell(a.locations)}
          </td>
          <td class="score mono">${escapeHtml(scoreCell)}</td>
          <td class="fix mono">${escapeHtml(fix)}</td>
          <td class="desc">
            ${desc ? `<div>${escapeHtml(desc.slice(0, 240))}${desc.length > 240 ? '…' : ''}</div>` : ''}
            ${links ? `<div class="muted small">${links}</div>` : ''}
          </td>
        </tr>`;
    }).join('');
    // Critical und High klappen wir per Default aufgeklappt auf, der Rest ist
    // zugeklappt — der wichtigste Befund ist sofort sichtbar, ohne dass der
    // Bericht 50 Bildschirme hoch ist.
    const openDefault = sev === 'Critical' || sev === 'High' ? ' open' : '';
    const total = groups[sev].length;
    return `
      <details class="sev-group"${openDefault}
               style="--sev-fg:${c.fg};--sev-bg:${c.bg};--sev-border:${c.border}">
        <summary>
          <span class="caret" aria-hidden="true">▸</span>
          <span class="sev-badge">${sev}</span>
          <span class="sev-count">${total} Befunde</span>
        </summary>
        <div class="sev-table-wrap">
        <div class="filter-bar">
          <input type="search" class="tbl-filter" placeholder="Filtern …" onclick="event.stopPropagation()" data-total="${total}" />
          <span class="filter-count"></span>
        </div>
        <table>
          <thead>
            <tr><th>CVE</th><th>Paket</th><th>CVSS</th><th>Fix</th><th>Beschreibung</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        </div>
      </details>`;
  }).filter(Boolean).join('\n');

  const summaryChips = SEVERITY_ORDER.filter((s) => counts[s] > 0).map((sev) => {
    const c = SEVERITY_COLORS[sev];
    return `<span class="chip" style="background:${c.bg};color:${c.fg};border-color:${c.border}">
      ${sev}: <strong>${counts[sev]}</strong>
    </span>`;
  }).join(' ');

  const noFindings = total === 0
    ? `<div class="ok-banner">✓ Keine bekannten Schwachstellen in den katalogisierten Komponenten gefunden.</div>`
    : '';

  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Schwachstellenbericht — ${escapeHtml(inputName)}</title>
<style>
:root{color-scheme:light dark;
--bg:#f6f7fb;--card:#fff;--fg:#0e1320;--muted:#6a7184;--border:#e3e7f1;
--accent:#002b7f;--accent-2:#1a4fb0;--accent-soft:#e6ecf6;}
@media (prefers-color-scheme:dark){:root{
--bg:#07090f;--card:#10131c;--fg:#ecf0f6;--muted:#8a93a8;--border:#232a3a;
--accent:#6c8dd9;--accent-2:#8aa9ea;--accent-soft:#0e1a35;}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem 4rem;background:var(--bg);color:var(--fg);
font-family:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
line-height:1.55;font-size:15px;-webkit-font-smoothing:antialiased}
main{max-width:1240px;margin:0 auto;background:var(--card);border:1px solid var(--border);
border-radius:16px;padding:2rem 2.2rem;box-shadow:0 6px 24px rgba(0,43,127,.08)}
header.report{padding-bottom:1rem;margin-bottom:1.4rem;border-bottom:1px solid var(--border)}
h1{margin:0 0 .3em;font-size:1.5rem;letter-spacing:-.01em;color:var(--accent)}
.summary-line{color:var(--muted);font-size:.95rem;margin:.3em 0 .8em}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.6rem}
.chip{padding:.25rem .7rem;border-radius:999px;font-size:.8rem;font-weight:600;
border:1px solid var(--border);background:var(--accent-soft);color:var(--accent);
display:inline-flex;align-items:center;gap:.3rem}
.muted{color:var(--muted)}
.small{font-size:.82em}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.ok-banner{margin:1.4rem 0;padding:1rem 1.2rem;border-radius:12px;
background:#ecfccb;color:#365314;border:1px solid #65a30d;font-weight:600}
@media (prefers-color-scheme:dark){.ok-banner{background:#172d10;color:#a3e635;border-color:#4d7c0f}}
details.sev-group{margin:1.4rem 0;border:1px solid var(--sev-border);border-radius:12px;
overflow:hidden;background:var(--sev-bg);color:var(--sev-fg)}
details.sev-group > summary{display:flex;align-items:center;gap:.6rem;cursor:pointer;
padding:.7rem 1rem;background:rgba(0,0,0,.04);border-bottom:1px solid var(--sev-border);
list-style:none;user-select:none}
details.sev-group > summary::-webkit-details-marker{display:none}
details.sev-group:not([open]) > summary{border-bottom-color:transparent}
details.sev-group > summary:hover{background:rgba(0,0,0,.07)}
details.sev-group .caret{display:inline-block;transition:transform .15s ease;color:currentColor;opacity:.6}
details.sev-group[open] .caret{transform:rotate(90deg)}
.sev-badge{font-weight:700;text-transform:uppercase;letter-spacing:.08em;
font-size:.78rem;padding:.2rem .65rem;border-radius:999px;
background:var(--sev-border);color:#fff}
.sev-count{font-weight:600;font-size:.85rem;opacity:.85;margin-left:auto}
.sev-table-wrap{overflow-x:auto;background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:.9rem;color:var(--fg)}
th,td{padding:.55rem .8rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}
th{background:var(--accent-soft);color:var(--accent);font-weight:600;font-size:.78rem;
text-transform:uppercase;letter-spacing:.07em}
tr:last-child td{border-bottom:0}
td.cve{white-space:nowrap;font-size:.85rem;font-weight:600}
.cve-age{display:inline-block;margin-left:.35rem;padding:.05rem .4rem;font-size:.72rem;
font-weight:600;border-radius:999px;border:1px solid currentColor;
font-family:"Inter",ui-sans-serif,system-ui,sans-serif;vertical-align:middle;
line-height:1.4;letter-spacing:0;white-space:nowrap}
td.score{white-space:nowrap;font-variant-numeric:tabular-nums;width:60px;text-align:right}
td.fix{white-space:nowrap;font-size:.85rem}
td.pkg{min-width:160px}
.loc-path{margin-top:.2rem;color:var(--muted);word-break:break-all;opacity:.9}
td.desc{max-width:560px}
td.desc a{color:var(--accent)}
footer.report{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);
color:var(--muted);font-size:.82rem;line-height:1.6}
.tools-credit{margin-top:.6rem;font-size:.76rem;line-height:1.65}
.tools-credit a{color:var(--accent);text-decoration:none;font-weight:500}
.tools-credit a:hover{text-decoration:underline}
.filter-bar{display:flex;align-items:center;gap:.6rem;padding:.5rem .8rem;
background:var(--card);border-bottom:1px solid var(--border)}
.tbl-filter{flex:1;min-width:0;padding:.35rem .6rem;border:1px solid var(--border);
border-radius:6px;font-size:.85rem;background:var(--bg);color:var(--fg)}
.tbl-filter:focus{outline:2px solid var(--accent);outline-offset:1px}
.filter-count{white-space:nowrap;font-size:.8rem;color:var(--muted)}
.print-btn{position:fixed;bottom:1.2rem;right:1.2rem;padding:.55rem 1.1rem;
background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:.85rem;
font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.18);z-index:100}
.print-btn:hover{background:var(--accent-2)}

/* Mobile-Optimierung */
@media (max-width:720px){
  body{padding:1rem .75rem 3rem;font-size:14px;line-height:1.5}
  main{padding:1.1rem 1rem;border-radius:12px}
  h1{font-size:1.25rem}
  .summary-line{font-size:.85rem}
  .chips{gap:.3rem}
  .chip{font-size:.72rem;padding:.18rem .55rem}
  details.sev-group > summary{padding:.55rem .75rem;font-size:.9rem;flex-wrap:wrap}
  .sev-badge{flex:0 0 auto}
  .sev-count{margin-left:auto;font-size:.78rem}
  table{font-size:.8rem}
  th,td{padding:.4rem .55rem}
  th{font-size:.68rem}
  .filter-bar{flex-direction:column;align-items:stretch;gap:.35rem}
  .tbl-filter{width:100%}
  td.desc{max-width:none}
  .print-btn{width:100%;margin:.5rem 0 0}
}
@media (max-width:480px){
  body{padding:.7rem .55rem 2rem;font-size:13px}
  main{padding:.85rem .75rem;border-radius:8px}
  h1{font-size:1.1rem}
  .cve-age{font-size:.65rem;padding:.04rem .3rem;margin-left:.25rem}
  th,td{padding:.3rem .4rem}
  td{overflow-wrap:anywhere;word-break:break-word}
  td.score,td.fix{white-space:normal}
  /* Beschreibung auf engsten Geräten ausblenden — nur CVE + Pkg + CVSS + Fix */
  th:nth-child(5),td.desc{display:none}
}
@media print{
  body{padding:1cm;background:white;color:black}
  main{box-shadow:none;border:1px solid #ccc}
  details{page-break-inside:avoid}
  details > summary{cursor:default}
  details:not([open]) > *{display:block !important}
  details[open] > *{display:block !important}
  .filter-bar,.viewer-modal,.print-btn{display:none !important}
  table{font-size:9pt}
  h1,h2,.section-title,details > summary{break-after:avoid}
  section,details{page-break-before:auto}
}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">Drucken / PDF</button>
<main>
  <header class="report">
    <h1>Schwachstellenbericht</h1>
    <div class="summary-line"><span class="mono">${escapeHtml(inputName)}</span></div>
    <div class="summary-line">
      ${total === 0
        ? 'Keine Befunde.'
        : `<strong>${total}</strong> Treffer insgesamt`}
    </div>
    ${total > 0 ? `<div class="chips">${summaryChips}</div>` : ''}
  </header>
  ${noFindings}
  ${cardsByGroup}
  <footer class="report">
    <div>Scanner: ${escapeHtml(grypeDescriptor?.name ?? 'grype')}${grypeDescriptor?.version ? ` v${escapeHtml(grypeDescriptor.version)}` : ''}${grypeDescriptor?.db?.built ? ` · Vuln-DB vom ${escapeHtml(grypeDescriptor.db.built)}` : ''} · generiert ${new Date().toISOString()}</div>
    <div class="tools-credit">
      CVE-Daten: <a href="https://github.com/anchore/grype" target="_blank" rel="noopener">grype</a> (Apache-2)
      gegen NVD / GHSA / OSV.
      SBOM-Basis: <a href="https://github.com/TomTonic/extract-sbom" target="_blank" rel="noopener">extract-sbom</a> (BSD-3) +
      <a href="https://github.com/anchore/syft" target="_blank" rel="noopener">syft</a> (Apache-2).
      Aufbereitung: <a href="https://github.com/merlin2533/sbom" target="_blank" rel="noopener">sbom-upload-app</a> (MIT).
    </div>
  </footer>
</main>
<script>
(function(){
  function setupFilter(input){
    var total=parseInt(input.dataset.total||'0',10);
    var countEl=input.parentNode.querySelector('.filter-count');
    var tbody=input.closest('.sev-table-wrap').querySelector('tbody');
    var timer=null;
    function applyFilter(){
      var q=input.value.toLowerCase().trim();
      var rows=tbody.querySelectorAll('tr');
      var visible=0;
      rows.forEach(function(tr){
        var match=!q||tr.textContent.toLowerCase().indexOf(q)>=0;
        tr.style.display=match?'':'none';
        if(match)visible++;
      });
      if(countEl)countEl.textContent=q?(visible+' von '+total+' sichtbar'):'';
    }
    input.addEventListener('input',function(){
      clearTimeout(timer);
      timer=setTimeout(applyFilter,16);
    });
  }
  document.querySelectorAll('.tbl-filter').forEach(setupFilter);
})();
</script>
</body>
</html>`;
}

/**
 * Hauptfunktion: nach jedem erfolgreichen extract-sbom-Lauf aufrufen.
 * Schlägt grype fehl oder ist nicht installiert, kommt {ranGrype:false} zurück.
 */
export async function runVulnReport(opts: VulnReportOpts): Promise<VulnReportResult> {
  const { cdxJsonPath, outDir, inputName, logger, jobId } = opts;

  const empty: VulnReportResult = {
    ranGrype: false,
    jsonPath: null,
    htmlPath: null,
    csvPath: null,
    counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
    total: 0,
  };

  if (!(await which('grype'))) {
    logger.info({ jobId }, 'vuln-report: grype not installed, skipping');
    return empty;
  }

  const base = path.basename(cdxJsonPath).replace(/\.cdx\.json$/i, '').replace(/\.json$/i, '');
  const jsonPath = path.join(outDir, `${base}.vulnerabilities.json`);
  const htmlPath = path.join(outDir, `${base}.vulnerabilities.html`);
  const csvPath = path.join(outDir, `${base}.vulnerabilities.csv`);

  logger.info({ jobId, cdxJsonPath }, 'vuln-report: running grype');
  const r = await runGrype(cdxJsonPath, jsonPath, 600_000);
  if (r.code !== 0) {
    logger.warn({ jobId, code: r.code, stderr: r.stderr.slice(0, 500) }, 'vuln-report: grype failed');
    // grype hinterlässt evtl. einen Müll-File — wegräumen.
    await fsp.unlink(jsonPath).catch(() => {});
    return { ...empty };
  }

  let data: GrypeOutput;
  try {
    const txt = await fsp.readFile(jsonPath, 'utf8');
    data = JSON.parse(txt) as GrypeOutput;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'vuln-report: could not parse grype output');
    return { ...empty };
  }

  const matches = data.matches ?? [];
  const counts: Record<Severity, number> = {
    Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0,
  };
  for (const m of matches) {
    counts[normalizeSeverity(m.vulnerability?.severity)]++;
  }
  const total = matches.length;

  const html = buildHtmlReport({
    inputName,
    matches,
    counts,
    total,
    grypeDescriptor: data.descriptor,
  });
  await fsp.writeFile(htmlPath, html, 'utf8');

  // CSV export
  const csv = buildCsv(matches);
  await fsp.writeFile(csvPath, csv, 'utf8');
  const csvLineCount = matches.length; // data rows (excl. header)
  logger.info(
    { jobId, csvLines: csvLineCount, csv: path.basename(csvPath) },
    `[csv] vulnerabilities.csv geschrieben (${csvLineCount} Zeilen)`
  );

  logger.info(
    { jobId, total, counts, html: path.basename(htmlPath) },
    'vuln-report: completed'
  );

  return { ranGrype: true, jsonPath, htmlPath, csvPath, counts, total };
}
