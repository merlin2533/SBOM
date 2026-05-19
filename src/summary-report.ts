// ─────────────────────────────────────────────────────────────────────────────
// Gesamtübersicht-Bericht
//
// Fasst SBOM-Komponenten (aus extract-sbom's CycloneDX-JSON) und CVE-Befunde
// (aus grype's JSON) zu einer einzigen Standalone-HTML-Seite zusammen.
// Datei wird als <basename>.summary.html ins Output-Verzeichnis gelegt.
// ─────────────────────────────────────────────────────────────────────────────

import fsp from 'fs/promises';
import path from 'path';
import type pino from 'pino';

export interface SummaryOpts {
  cdxJsonPath: string;
  grypeJsonPath: string | null;
  reportMdPath: string | null;
  outDir: string;
  inputName: string;
  jobId: string;
  logger: pino.Logger;
}

export interface SummaryResult {
  htmlPath: string | null;
  componentCount: number;
  vulnTotal: number;
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

interface CdxComponent {
  'bom-ref'?: string;
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  group?: string;
  hashes?: Array<{ alg?: string; content?: string }>;
}

interface CdxDoc {
  components?: CdxComponent[];
  metadata?: {
    component?: {
      name?: string;
      hashes?: Array<{ alg?: string; content?: string }>;
    };
  };
}

interface GrypeMatch {
  vulnerability?: {
    id?: string;
    severity?: string;
    cvss?: Array<{ metrics?: { baseScore?: number } }>;
    fix?: { versions?: string[]; state?: string };
    urls?: string[];
    description?: string;
  };
  artifact?: { name?: string; version?: string; type?: string; purl?: string };
}

interface GrypeDoc {
  matches?: GrypeMatch[];
  descriptor?: { name?: string; version?: string; db?: { built?: string } };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]!
  );
}

function fmtBytes(n: number): string {
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(v < 10 ? 2 : 1) + ' ' + units[i];
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

// Ecosystem-Erkennung aus dem PURL — npm:..., pkg:maven:..., usw.
function ecosystemOf(c: CdxComponent): string {
  const purl = c.purl ?? '';
  const m = purl.match(/^pkg:([a-z0-9.-]+)\//i);
  if (m) return m[1]!.toLowerCase();
  return c.type ?? 'unknown';
}

function pickResidualRisk(reportMd: string): string | null {
  // Extrahiert die Markdown-Sektion „Residual Risk and Limitations" (oder
  // ähnliche), falls vorhanden — alles vom Header bis zum nächsten Header
  // oder Dateiende.
  const re = /^#{1,6}\s+(Residual Risk[^\n]*|Restrisiken[^\n]*|Limitations[^\n]*)$/im;
  const m = reportMd.match(re);
  if (!m) return null;
  const start = m.index ?? 0;
  // Nächster Header gleicher oder höherer Ebene
  const rest = reportMd.slice(start + m[0].length);
  const nextHeader = rest.search(/^#{1,6}\s+/m);
  const body = nextHeader >= 0 ? rest.slice(0, nextHeader) : rest;
  return body.trim();
}

function renderMarkdownLite(md: string): string {
  // Sehr leichter Markdown-Renderer für die Residual-Risk-Sektion. Wir wollen
  // keinen weiteren Dep-Import nur dafür — extract-sbom's Outputs nutzen ein
  // begrenztes Vokabular (Listen, fett, code).
  return escapeHtml(md)
    // fett **bold**
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    // inline `code`
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Listen
    .replace(/^[-*]\s+(.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/gs, (m) => `<ul>${m}</ul>`)
    // Absätze
    .replace(/\n\n+/g, '</p><p>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>')
    .replace(/<p><ul>/g, '<ul>')
    .replace(/<\/ul><\/p>/g, '</ul>');
}

export async function buildSummaryReport(opts: SummaryOpts): Promise<SummaryResult> {
  const { cdxJsonPath, grypeJsonPath, reportMdPath, outDir, inputName, jobId, logger } = opts;

  // CycloneDX laden
  let cdx: CdxDoc;
  try {
    cdx = JSON.parse(await fsp.readFile(cdxJsonPath, 'utf8')) as CdxDoc;
  } catch (e) {
    logger.warn({ jobId, err: e }, 'summary: could not read cdx');
    return { htmlPath: null, componentCount: 0, vulnTotal: 0 };
  }

  // grype optional
  let grype: GrypeDoc | null = null;
  if (grypeJsonPath) {
    try {
      grype = JSON.parse(await fsp.readFile(grypeJsonPath, 'utf8')) as GrypeDoc;
    } catch { /* egal */ }
  }

  // report.md optional — wir picken nur den Residual-Risk-Block raus
  let residualRisk: string | null = null;
  if (reportMdPath) {
    try {
      const md = await fsp.readFile(reportMdPath, 'utf8');
      residualRisk = pickResidualRisk(md);
    } catch { /* egal */ }
  }

  const comps = cdx.components ?? [];
  const matches = grype?.matches ?? [];

  // Komponenten nach Ecosystem gruppieren
  const byEco: Record<string, CdxComponent[]> = {};
  for (const c of comps) {
    const e = ecosystemOf(c);
    if (!byEco[e]) byEco[e] = [];
    byEco[e].push(c);
  }
  const ecoOrder = Object.keys(byEco).sort((a, b) => byEco[b]!.length - byEco[a]!.length);

  // Vulns nach Severity gruppieren
  const vulnBySev: Record<Severity, GrypeMatch[]> = {
    Critical: [], High: [], Medium: [], Low: [], Negligible: [], Unknown: [],
  };
  for (const m of matches) {
    vulnBySev[normalizeSeverity(m.vulnerability?.severity)].push(m);
  }
  for (const k of SEVERITY_ORDER) {
    vulnBySev[k].sort((a, b) => {
      const sa = a.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
      const sb = b.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
      return sb - sa;
    });
  }

  // Artefakt-Hash
  const rootHash = cdx.metadata?.component?.hashes?.find((h) => /sha-?256/i.test(h.alg ?? ''))
    ?.content ?? null;

  // Severity-Chips für den Header
  const vulnChips = SEVERITY_ORDER.filter((s) => vulnBySev[s].length > 0).map((sev) => {
    const c = SEVERITY_COLORS[sev];
    return `<span class="chip" style="background:${c.bg};color:${c.fg};border-color:${c.border}">
      ${sev}: <strong>${vulnBySev[sev].length}</strong>
    </span>`;
  }).join(' ');

  // Komponenten-Sektion
  const componentsHtml = ecoOrder.map((eco, idx) => {
    const list = byEco[eco]!;
    const openDefault = idx === 0 ? ' open' : '';
    const rows = list.slice(0, 500).map((c) => {
      const purl = c.purl ?? '';
      return `
        <tr>
          <td><strong>${escapeHtml(c.name ?? '?')}</strong></td>
          <td class="mono">${escapeHtml(c.version ?? '?')}</td>
          <td class="mono small muted" title="${escapeHtml(purl)}">${escapeHtml(purl.slice(0, 80))}</td>
        </tr>`;
    }).join('');
    const overflowHint = list.length > 500
      ? `<tr><td colspan="3" class="muted small">… ${list.length - 500} weitere ausgeblendet</td></tr>`
      : '';
    return `
      <details class="group eco-group"${openDefault}>
        <summary>
          <span class="caret" aria-hidden="true">▸</span>
          <span class="group-name">${escapeHtml(eco)}</span>
          <span class="group-count">${list.length}</span>
        </summary>
        <div class="group-body">
          <table>
            <thead><tr><th>Komponente</th><th>Version</th><th>PURL</th></tr></thead>
            <tbody>${rows}${overflowHint}</tbody>
          </table>
        </div>
      </details>`;
  }).join('\n');

  // Vulns-Sektion
  const vulnsHtml = SEVERITY_ORDER.filter((s) => vulnBySev[s].length > 0).map((sev) => {
    const c = SEVERITY_COLORS[sev];
    const openDefault = sev === 'Critical' || sev === 'High' ? ' open' : '';
    const rows = vulnBySev[sev].map((m) => {
      const v = m.vulnerability ?? {};
      const a = m.artifact ?? {};
      const fix = v.fix?.versions?.length
        ? v.fix.versions.join(', ')
        : (v.fix?.state === 'not-fixed' ? '— (kein Fix)' : '—');
      const links = (v.urls ?? []).slice(0, 2).map((u) =>
        `<a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(
          u.replace(/^https?:\/\//, '').replace(/\/$/, '').slice(0, 50)
        )}</a>`
      ).join(' · ');
      const score = v.cvss?.[0]?.metrics?.baseScore;
      const desc = (v.description ?? '').replace(/\s+/g, ' ').trim();
      return `
        <tr>
          <td class="mono small">${escapeHtml(v.id ?? '?')}</td>
          <td>
            <strong>${escapeHtml(a.name ?? '?')}</strong>
            <span class="muted small">@${escapeHtml(a.version ?? '?')}</span>
          </td>
          <td class="mono small">${score != null ? score.toFixed(1) : '—'}</td>
          <td class="mono small">${escapeHtml(fix)}</td>
          <td>
            ${desc ? `<div class="small">${escapeHtml(desc.slice(0, 180))}${desc.length > 180 ? '…' : ''}</div>` : ''}
            ${links ? `<div class="muted small">${links}</div>` : ''}
          </td>
        </tr>`;
    }).join('');
    return `
      <details class="group sev-group"${openDefault}
               style="--sev-fg:${c.fg};--sev-bg:${c.bg};--sev-border:${c.border}">
        <summary>
          <span class="caret" aria-hidden="true">▸</span>
          <span class="sev-badge">${sev}</span>
          <span class="group-count">${vulnBySev[sev].length} Befunde</span>
        </summary>
        <div class="group-body">
          <table>
            <thead>
              <tr><th>CVE</th><th>Paket</th><th>CVSS</th><th>Fix</th><th>Beschreibung</th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </details>`;
  }).join('\n');

  const residualHtml = residualRisk
    ? `
      <details class="group residual" open>
        <summary>
          <span class="caret" aria-hidden="true">▸</span>
          <span class="group-name">Restrisiken &amp; Limitationen</span>
        </summary>
        <div class="group-body markdown-body">
          ${renderMarkdownLite(residualRisk)}
        </div>
      </details>`
    : '';

  const html = `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Gesamtübersicht — ${escapeHtml(inputName)}</title>
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
header.summary{padding-bottom:1.1rem;margin-bottom:1.4rem;border-bottom:1px solid var(--border)}
h1{margin:0 0 .3em;font-size:1.6rem;letter-spacing:-.01em;color:var(--accent);display:flex;align-items:center;gap:.6rem}
h1::before{content:"";width:5px;height:22px;border-radius:2px;
background:linear-gradient(180deg,var(--accent),var(--accent-2))}
.subline{color:var(--muted);font-size:.92rem;margin:.4em 0}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.6rem 1.2rem;
margin-top:.7rem;padding:.8rem 1rem;background:var(--accent-soft);border-radius:10px;
border:1px solid var(--border)}
.kv-label{font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:600}
.kv-value{font-size:.88rem;word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:1rem}
.chip{padding:.25rem .7rem;border-radius:999px;font-size:.8rem;font-weight:600;
border:1px solid var(--border);background:var(--accent-soft);color:var(--accent);
display:inline-flex;align-items:center;gap:.3rem}
.section-title{font-size:.78rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;
color:var(--muted);margin:2rem 0 .7rem;display:flex;align-items:center;gap:.5rem}
.section-title::before{content:"";width:4px;height:14px;border-radius:2px;
background:linear-gradient(180deg,var(--accent),var(--accent-2))}
.muted{color:var(--muted)}
.small{font-size:.82em}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
details.group{margin:.6rem 0;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--card)}
details.sev-group{border-color:var(--sev-border);background:var(--sev-bg);color:var(--sev-fg)}
details.group > summary{display:flex;align-items:center;gap:.6rem;cursor:pointer;
padding:.6rem .9rem;background:var(--accent-soft);border-bottom:1px solid var(--border);
list-style:none;user-select:none;font-weight:500}
details.sev-group > summary{background:rgba(0,0,0,.04);border-bottom-color:var(--sev-border)}
details.group > summary::-webkit-details-marker{display:none}
details.group:not([open]) > summary{border-bottom-color:transparent}
details.group > summary:hover{filter:brightness(.97)}
.caret{display:inline-block;transition:transform .15s ease;color:currentColor;opacity:.6}
details[open] .caret{transform:rotate(90deg)}
.group-name{font-weight:600}
.group-count{margin-left:auto;font-weight:600;font-size:.85rem;opacity:.85}
.sev-badge{font-weight:700;text-transform:uppercase;letter-spacing:.08em;
font-size:.78rem;padding:.2rem .65rem;border-radius:999px;
background:var(--sev-border);color:#fff}
.group-body{overflow-x:auto;background:var(--card);color:var(--fg)}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:.5rem .8rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}
th{background:var(--accent-soft);color:var(--accent);font-weight:600;font-size:.74rem;
text-transform:uppercase;letter-spacing:.07em}
tr:last-child td{border-bottom:0}
.markdown-body{padding:1rem 1.1rem}
.markdown-body ul{padding-left:1.4rem}
.markdown-body li{margin:.2em 0}
.markdown-body code{background:var(--accent-soft);color:var(--accent);padding:.06em .35em;border-radius:4px;font-size:.88em}
footer.summary{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);
color:var(--muted);font-size:.82rem;line-height:1.7}
.ok-banner{margin:1rem 0;padding:.8rem 1rem;border-radius:10px;
background:#ecfccb;color:#365314;border:1px solid #65a30d;font-weight:600}
@media (prefers-color-scheme:dark){.ok-banner{background:#172d10;color:#a3e635;border-color:#4d7c0f}}
</style>
</head>
<body>
<main>
  <header class="summary">
    <h1>Gesamtübersicht</h1>
    <div class="subline mono">${escapeHtml(inputName)}</div>
    <div class="kv">
      <div>
        <div class="kv-label">Komponenten</div>
        <div class="kv-value"><strong>${comps.length}</strong> in ${ecoOrder.length} Ökosystem(en)</div>
      </div>
      <div>
        <div class="kv-label">Schwachstellen</div>
        <div class="kv-value"><strong>${matches.length}</strong> ${matches.length === 0 ? '— sauber' : 'Treffer'}</div>
      </div>
      ${rootHash ? `<div>
        <div class="kv-label">SHA-256</div>
        <div class="kv-value mono small">${escapeHtml(rootHash)}</div>
      </div>` : ''}
    </div>
    ${vulnChips ? `<div class="chips">${vulnChips}</div>` : ''}
  </header>

  <div class="section-title">Komponenten</div>
  ${comps.length === 0
    ? `<div class="muted">Keine Komponenten katalogisiert.</div>`
    : componentsHtml}

  <div class="section-title">Schwachstellen</div>
  ${matches.length === 0
    ? `<div class="ok-banner">✓ Keine bekannten Schwachstellen in den katalogisierten Komponenten.</div>`
    : vulnsHtml}

  ${residualHtml ? `<div class="section-title">Restrisiken</div>${residualHtml}` : ''}

  <footer class="summary">
    Erzeugt ${new Date().toISOString()} · extract-sbom-Output: ${escapeHtml(path.basename(cdxJsonPath))}
    ${grype ? ` · grype ${escapeHtml(grype.descriptor?.version ?? '?')}${grype.descriptor?.db?.built ? ` · DB ${escapeHtml(grype.descriptor.db.built)}` : ''}` : ''}
  </footer>
</main>
</body>
</html>`;

  const base = path.basename(cdxJsonPath).replace(/\.cdx\.json$/i, '');
  const htmlPath = path.join(outDir, `${base}.summary.html`);
  await fsp.writeFile(htmlPath, html, 'utf8');

  logger.info(
    { jobId, components: comps.length, vulns: matches.length, html: path.basename(htmlPath) },
    'summary report written'
  );

  return { htmlPath, componentCount: comps.length, vulnTotal: matches.length };
}
