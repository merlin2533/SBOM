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

// CycloneDX license shapes:
//   { license: { id?: string; name?: string } }
//   { expression: string }
type CdxLicenseEntry =
  | { license: { id?: string; name?: string } }
  | { expression: string };

interface CdxComponent {
  'bom-ref'?: string;
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  group?: string;
  hashes?: Array<{ alg?: string; content?: string }>;
  licenses?: CdxLicenseEntry[];
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

// ─────────────────────────────────────────────────────────────────────────────
// Software-Delivery-Quality-Score
// ─────────────────────────────────────────────────────────────────────────────

interface RatingInput {
  componentCount: number;
  severityCounts: { critical: number; high: number; medium: number; low: number };
  strongCopyleft: number;
  proprietary: number;
  unknownLicense: number;
  hasResidualRisk: boolean;
}

interface RatingResult {
  score: number;          // 0..100
  grade: string;          // A+, A, B, C, D, F
  label: string;          // kurze Bezeichnung
  explain: string;        // ein Satz
  color: { fg: string; bg: string; border: string };
  reasons: string[];      // Aufzählung der größten Abzüge
}

/**
 * Berechnet einen 0..100-Score und übersetzt ihn in eine Schulnote.
 * Heuristisch, ohne Anspruch auf Vollständigkeit — soll dem Reviewer
 * sofort ein „grün/gelb/rot"-Signal geben.
 */
function computeRating(r: RatingInput): RatingResult {
  let score = 100;
  const reasons: string[] = [];

  // CVE-Abzüge (capped, damit ein Riesenpaket mit 200 Low-CVEs nicht
  // dieselbe Wertung wie eines mit 5 Critical bekommt).
  const critPenalty = Math.min(r.severityCounts.critical * 10, 50);
  if (critPenalty > 0) {
    score -= critPenalty;
    reasons.push(`${r.severityCounts.critical} Critical-CVE${r.severityCounts.critical === 1 ? '' : 's'} (−${critPenalty})`);
  }
  const highPenalty = Math.min(r.severityCounts.high * 5, 30);
  if (highPenalty > 0) {
    score -= highPenalty;
    reasons.push(`${r.severityCounts.high} High-CVE${r.severityCounts.high === 1 ? '' : 's'} (−${highPenalty})`);
  }
  const medPenalty = Math.min(r.severityCounts.medium * 1, 15);
  if (medPenalty > 0) {
    score -= medPenalty;
    reasons.push(`${r.severityCounts.medium} Medium-CVE${r.severityCounts.medium === 1 ? '' : 's'} (−${medPenalty})`);
  }
  const lowPenalty = Math.min(r.severityCounts.low * 0.2, 5);
  if (lowPenalty >= 1) {
    score -= lowPenalty;
    reasons.push(`${r.severityCounts.low} Low-CVE${r.severityCounts.low === 1 ? '' : 's'} (−${lowPenalty.toFixed(1)})`);
  } else {
    score -= lowPenalty;
  }

  // Lizenz-Compliance.
  const sclPenalty = Math.min(r.strongCopyleft * 3, 15);
  if (sclPenalty > 0) {
    score -= sclPenalty;
    reasons.push(`${r.strongCopyleft} Komponente${r.strongCopyleft === 1 ? '' : 'n'} unter starker Copyleft-Lizenz (GPL/AGPL/SSPL) (−${sclPenalty})`);
  }
  const propPenalty = Math.min(r.proprietary * 2, 10);
  if (propPenalty > 0) {
    score -= propPenalty;
    reasons.push(`${r.proprietary} proprietäre Komponente${r.proprietary === 1 ? '' : 'n'} (−${propPenalty})`);
  }
  const unkPenalty = Math.min(r.unknownLicense * 0.1, 10);
  if (unkPenalty >= 1) {
    score -= unkPenalty;
    reasons.push(`${r.unknownLicense} Komponenten ohne erkannte Lizenz (−${unkPenalty.toFixed(1)})`);
  } else {
    score -= unkPenalty;
  }

  // Extraktions-Vollständigkeit.
  if (r.componentCount === 0) {
    score -= 50;
    reasons.push('Keine Komponenten katalogisiert — Extraktion vermutlich gescheitert (−50)');
  } else if (r.componentCount < 10) {
    score -= 10;
    reasons.push(`Nur ${r.componentCount} Komponente${r.componentCount === 1 ? '' : 'n'} gefunden — Extraktion möglicherweise unvollständig (−10)`);
  }

  if (r.hasResidualRisk) {
    score -= 5;
    reasons.push('Audit-Report meldet Restrisiken / übersprungene Inhalte (−5)');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  // Note + Farbe ableiten.
  let grade: string, label: string, explain: string;
  let color: { fg: string; bg: string; border: string };
  if (score >= 95) {
    grade = 'A+'; label = 'Ausgezeichnet';
    explain = 'Saubere Lieferung mit minimaler Restrisiko-Fläche.';
    color = { fg: '#14532d', bg: '#dcfce7', border: '#15803d' };
  } else if (score >= 85) {
    grade = 'A';  label = 'Sehr gut';
    explain = 'Lieferbar — kleinere Hinweise prüfen.';
    color = { fg: '#365314', bg: '#ecfccb', border: '#65a30d' };
  } else if (score >= 75) {
    grade = 'B';  label = 'Gut';
    explain = 'Akzeptabel, einige Befunde sollten gesichtet werden.';
    color = { fg: '#854d0e', bg: '#fef9c3', border: '#ca8a04' };
  } else if (score >= 65) {
    grade = 'C';  label = 'Mittelmäßig';
    explain = 'Mit Vorbehalt freigebbar — nennenswerte Befunde adressieren.';
    color = { fg: '#92400e', bg: '#fef3c7', border: '#d97706' };
  } else if (score >= 50) {
    grade = 'D';  label = 'Bedenklich';
    explain = 'Vor Freigabe nachbessern oder Risiken explizit akzeptieren.';
    color = { fg: '#9a3412', bg: '#ffedd5', border: '#ea580c' };
  } else {
    grade = 'F';  label = 'Nicht freigebbar';
    explain = 'Schwerwiegende Befunde — Lieferung nicht ohne Eingriff einsetzen.';
    color = { fg: '#7f1d1d', bg: '#fee2e2', border: '#b91c1c' };
  }

  return { score, grade, label, explain, color, reasons: reasons.slice(0, 5) };
}

// ─────────────────────────────────────────────────────────────────────────────
// CVE-Alter aus der CVE-ID ableiten
// ─────────────────────────────────────────────────────────────────────────────
function cveYear(id: string | undefined | null): number | null {
  if (!id) return null;
  const m = id.match(/^(?:CVE|GHSA|OSV|RUSTSEC|GLSA|DSA|USN|ALAS)-?(\d{4})[-_]/i);
  return m ? parseInt(m[1]!, 10) : null;
}

interface CveAge {
  year: number;
  yearsOld: number;
  // tier 0 = same year (frisch), 1 = 1-2J, 2 = 3-5J, 3 = älter
  tier: 0 | 1 | 2 | 3;
  label: string;            // z.B. "2023 · vor 2 J."
  color: { fg: string; bg: string; border: string };
}

function cveAge(id: string | undefined | null, now: Date = new Date()): CveAge | null {
  const year = cveYear(id);
  if (year === null) return null;
  const yearsOld = Math.max(0, now.getFullYear() - year);
  let tier: CveAge['tier'];
  let color: { fg: string; bg: string; border: string };
  if (yearsOld === 0) {
    tier = 0;
    color = { fg: '#7f1d1d', bg: '#fee2e2', border: '#b91c1c' };  // frisch — rot
  } else if (yearsOld <= 2) {
    tier = 1;
    color = { fg: '#9a3412', bg: '#ffedd5', border: '#ea580c' };  // orange
  } else if (yearsOld <= 5) {
    tier = 2;
    color = { fg: '#854d0e', bg: '#fef9c3', border: '#ca8a04' };  // gelb
  } else {
    tier = 3;
    color = { fg: '#4b5563', bg: '#f3f4f6', border: '#9ca3af' };  // grau (alt)
  }
  const label = yearsOld === 0
    ? `${year} · neu`
    : `${year} · ${yearsOld} J.`;
  return { year, yearsOld, tier, label, color };
}

function cveAgeChip(id: string | undefined | null): string {
  const a = cveAge(id);
  if (!a) return '';
  return `<span class="cve-age" title="CVE-Jahr: ${a.year}"
    style="background:${a.color.bg};color:${a.color.fg};border-color:${a.color.border}">${a.label}</span>`;
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

// ─── License compliance ──────────────────────────────────────────────────────

type LicenseCategory = 'permissive' | 'weak-copyleft' | 'strong-copyleft' | 'proprietary' | 'unknown';

const LICENSE_CATEGORY_META: Record<LicenseCategory, { label: string; fg: string; bg: string; border: string }> = {
  permissive:      { label: 'Permissiv',       fg: '#166534', bg: '#dcfce7', border: '#16a34a' },
  'weak-copyleft': { label: 'Schwaches Copyleft', fg: '#075985', bg: '#e0f2fe', border: '#0369a1' },
  'strong-copyleft':{ label: 'Starkes Copyleft', fg: '#9a3412', bg: '#ffedd5', border: '#ea580c' },
  proprietary:     { label: 'Proprietär',       fg: '#991b1b', bg: '#fee2e2', border: '#b91c1c' },
  unknown:         { label: 'Unbekannt',         fg: '#374151', bg: '#f3f4f6', border: '#6b7280' },
};

const LICENSE_CATEGORY_ORDER: LicenseCategory[] = [
  'permissive', 'weak-copyleft', 'strong-copyleft', 'proprietary', 'unknown',
];

function extractLicenseStrings(comp: CdxComponent): string[] {
  if (!comp.licenses || comp.licenses.length === 0) return [];
  const result: string[] = [];
  for (const entry of comp.licenses) {
    if ('expression' in entry) {
      if (entry.expression) result.push(entry.expression);
    } else if ('license' in entry) {
      const l = entry.license;
      const id = l.id?.trim();
      const name = l.name?.trim();
      if (id) result.push(id);
      else if (name) result.push(name);
    }
  }
  return result;
}

function categorizeLicense(licStr: string): LicenseCategory {
  const s = licStr.toLowerCase();
  if (/proprietary|commercial/.test(s)) return 'proprietary';
  if (/^(agpl|sspl|eupl)/.test(s) || /\bagpl\b/.test(s) || /\bsspl\b/.test(s) || /\beupl\b/.test(s)) return 'strong-copyleft';
  if (/^gpl/.test(s) || /\bgpl[-v\d]/.test(s) || /gnu general public license/.test(s)) return 'strong-copyleft';
  if (/^lgpl/.test(s) || /^mpl/.test(s) || /^epl/.test(s) || /^cddl/.test(s) || /^osl-3/.test(s)) return 'weak-copyleft';
  if (
    /^mit$/.test(s) ||
    /^bsd/.test(s) ||
    /^apache/.test(s) ||
    /^isc$/.test(s) ||
    /^zlib$/.test(s) ||
    /^bsl/.test(s) ||
    /^unlicense$/.test(s) ||
    /^cc0/.test(s)
  ) return 'permissive';
  return 'unknown';
}

function categorizeComponent(comp: CdxComponent): LicenseCategory {
  const licenses = extractLicenseStrings(comp);
  if (licenses.length === 0) return 'unknown';
  // Worst-case wins: proprietary > strong-copyleft > weak-copyleft > permissive > unknown
  const categoryRank: Record<LicenseCategory, number> = {
    unknown: 0, permissive: 1, 'weak-copyleft': 2, 'strong-copyleft': 3, proprietary: 4,
  };
  let best: LicenseCategory = 'unknown';
  for (const lic of licenses) {
    const cat = categorizeLicense(lic);
    if (categoryRank[cat] > categoryRank[best]) best = cat;
  }
  return best;
}

// ─────────────────────────────────────────────────────────────────────────────

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

  // ── Lizenzen ────────────────────────────────────────────────────────────────
  const licenseByCategory: Record<LicenseCategory, CdxComponent[]> = {
    permissive: [], 'weak-copyleft': [], 'strong-copyleft': [], proprietary: [], unknown: [],
  };
  for (const c of comps) {
    licenseByCategory[categorizeComponent(c)].push(c);
  }

  // ── Software-Delivery-Quality-Score ────────────────────────────────────────
  // Heuristisches Rating 0..100 für „wie sauber/sicher ist diese Lieferung".
  // Stellt die wichtigste Information beim Aufschlagen des Berichts dar.
  const sevCounts = {
    critical: vulnBySev.Critical.length,
    high:     vulnBySev.High.length,
    medium:   vulnBySev.Medium.length,
    low:      vulnBySev.Low.length,
  };
  const rating = computeRating({
    componentCount: comps.length,
    severityCounts: sevCounts,
    strongCopyleft: licenseByCategory['strong-copyleft'].length,
    proprietary:    licenseByCategory['proprietary'].length,
    unknownLicense: licenseByCategory['unknown'].length,
    hasResidualRisk: residualRisk != null && residualRisk.length > 50,
  });

  const licenseChips = LICENSE_CATEGORY_ORDER.map((cat) => {
    const count = licenseByCategory[cat].length;
    if (count === 0) return '';
    const m = LICENSE_CATEGORY_META[cat];
    return `<span class="chip" style="background:${m.bg};color:${m.fg};border-color:${m.border}">${escapeHtml(m.label)}: <strong>${count}</strong></span>`;
  }).filter(Boolean).join(' ');

  const strongCopyleftCount = licenseByCategory['strong-copyleft'].length;
  const proprietaryCount = licenseByCategory['proprietary'].length;
  const complianceWarning = (strongCopyleftCount > 0 || proprietaryCount > 0)
    ? `<div class="compliance-warn">⚠ ${[
        strongCopyleftCount > 0 ? `${strongCopyleftCount} Komponenten unter starker Copyleft-Lizenz` : '',
        proprietaryCount > 0 ? `${proprietaryCount} proprietäre Komponenten` : '',
      ].filter(Boolean).join(' und ')} — Prüfung empfohlen</div>`
    : '';

  const licenseGroupsHtml = LICENSE_CATEGORY_ORDER.map((cat) => {
    const list = licenseByCategory[cat];
    if (list.length === 0) return '';
    const m = LICENSE_CATEGORY_META[cat];
    const openDefault = cat === 'strong-copyleft' || cat === 'proprietary' ? ' open' : '';
    const rows = list.map((c) => {
      const lics = extractLicenseStrings(c);
      return `
        <tr>
          <td><strong>${escapeHtml(c.name ?? '?')}</strong></td>
          <td class="mono">${escapeHtml(c.version ?? '?')}</td>
          <td>${lics.length > 0 ? lics.map(escapeHtml).join(', ') : '<span class="muted">—</span>'}</td>
        </tr>`;
    }).join('');
    return `
      <details class="group lic-group"${openDefault}
               style="--lic-fg:${m.fg};--lic-bg:${m.bg};--lic-border:${m.border}">
        <summary>
          <span class="caret" aria-hidden="true">▸</span>
          <span class="lic-badge">${escapeHtml(m.label)}</span>
          <span class="group-count">${list.length}</span>
        </summary>
        <div class="group-body">
          <div class="filter-bar">
            <input type="search" class="tbl-filter" placeholder="Filtern …" onclick="event.stopPropagation()" data-total="${list.length}" />
            <span class="filter-count"></span>
          </div>
          <table>
            <thead><tr><th>Komponente</th><th>Version</th><th>Lizenz(en)</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </details>`;
  }).filter(Boolean).join('\n');

  // Komponenten-Sektion
  const componentsHtml = ecoOrder.map((eco, idx) => {
    const list = byEco[eco]!;
    const openDefault = idx === 0 ? ' open' : '';
    const visibleList = list.slice(0, 500);
    const rows = visibleList.map((c) => {
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
          <div class="filter-bar">
            <input type="search" class="tbl-filter" placeholder="Filtern …" onclick="event.stopPropagation()" data-total="${visibleList.length}" />
            <span class="filter-count"></span>
          </div>
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
    const sevCount = vulnBySev[sev].length;
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
      const cveId = escapeHtml(v.id ?? '?');
      const anchorId = `cve-${(v.id ?? 'unknown').replace(/[^a-zA-Z0-9-]/g, '-')}`;
      return `
        <tr id="${anchorId}">
          <td class="mono small">${cveId}${cveAgeChip(v.id)}</td>
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
          <span class="group-count">${sevCount} Befunde</span>
        </summary>
        <div class="group-body">
          <div class="filter-bar">
            <input type="search" class="tbl-filter" placeholder="Filtern …" onclick="event.stopPropagation()" data-total="${sevCount}" />
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
  }).join('\n');

  // ── A.1 Top-5-Risiken-Karte ─────────────────────────────────────────────────
  // Priorität: Critical+Fix > Critical ohne Fix > High+Fix > High ohne Fix > Medium
  function topRiskScore(m: GrypeMatch): number {
    const sev = normalizeSeverity(m.vulnerability?.severity);
    const hasFix = (m.vulnerability?.fix?.versions?.length ?? 0) > 0 ? 1 : 0;
    const cvss = m.vulnerability?.cvss?.[0]?.metrics?.baseScore ?? 0;
    const sevRank: Record<Severity, number> = { Critical: 1000, High: 500, Medium: 100, Low: 10, Negligible: 1, Unknown: 0 };
    return sevRank[sev] * 10 + hasFix * 5 + cvss;
  }

  const topRiskMatches = matches
    .filter((m) => {
      const s = normalizeSeverity(m.vulnerability?.severity);
      return s === 'Critical' || s === 'High' || s === 'Medium';
    })
    .sort((a, b) => topRiskScore(b) - topRiskScore(a))
    .slice(0, 5);

  const topRisksHtml = topRiskMatches.length === 0 ? '' : (() => {
    const rows = topRiskMatches.map((m) => {
      const v = m.vulnerability ?? {};
      const a = m.artifact ?? {};
      const sev = normalizeSeverity(v.severity);
      const c = SEVERITY_COLORS[sev];
      const score = v.cvss?.[0]?.metrics?.baseScore;
      const hasFix = (v.fix?.versions?.length ?? 0) > 0;
      const fixStr = hasFix ? escapeHtml(v.fix!.versions!.join(', ')) : '—';
      const desc = (v.description ?? '').replace(/\s+/g, ' ').trim();
      const cveId = v.id ?? '?';
      const anchorId = `cve-${cveId.replace(/[^a-zA-Z0-9-]/g, '-')}`;
      return `<tr style="cursor:pointer" onclick="document.getElementById('${anchorId}')&&(document.getElementById('${anchorId}').closest('details')||document.body).setAttribute('open',''),document.getElementById('${anchorId}')?.closest('details')?.setAttribute('open',''),document.getElementById('${anchorId}')?.scrollIntoView({behavior:'smooth',block:'center'})">
        <td class="mono small">
          <a href="#${anchorId}" onclick="event.stopPropagation()">${escapeHtml(cveId)}</a>
          ${cveAgeChip(cveId)}
        </td>
        <td><span class="sev-badge" style="background:${c.border};color:#fff;font-size:.72rem;padding:.15rem .5rem;border-radius:999px">${sev}</span></td>
        <td class="mono small">${escapeHtml(a.name ?? '?')}@${escapeHtml(a.version ?? '?')}</td>
        <td class="mono small">${score != null ? score.toFixed(1) : '—'}</td>
        <td class="mono small">${hasFix ? `<span style="color:#15803d;font-weight:600">✓ ${fixStr}</span>` : '<span class="muted">—</span>'}</td>
        <td class="small">${desc ? escapeHtml(desc.slice(0, 120)) + (desc.length > 120 ? '…' : '') : '<span class="muted">—</span>'}</td>
      </tr>`;
    }).join('');
    return `
    <div class="top-risks-card">
      <div class="top-risks-title">🔥 Top-Risiken — diese fünf zuerst angehen</div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr><th>CVE</th><th>Severity</th><th>Paket@Version</th><th>CVSS</th><th>Fix verfügbar</th><th>Beschreibung</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  })();

  // ── A.2 Top-Komponenten nach Risiko ─────────────────────────────────────────
  // Risiko-Score: critCount*10 + highCount*5 + medCount*2 + lowCount*0.5
  interface CompRisk {
    key: string;
    name: string;
    version: string;
    ecosystem: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
  }

  const compRiskMap = new Map<string, CompRisk>();
  for (const m of matches) {
    const a = m.artifact ?? {};
    const sev = normalizeSeverity(m.vulnerability?.severity);
    const key = `${a.name ?? '?'}@${a.version ?? '?'}`;
    if (!compRiskMap.has(key)) {
      // Find corresponding component for ecosystem
      const comp = comps.find((c) => c.name === a.name && c.version === a.version);
      compRiskMap.set(key, {
        key,
        name: a.name ?? '?',
        version: a.version ?? '?',
        ecosystem: comp ? ecosystemOf(comp) : (a as { type?: string }).type ?? 'unknown',
        critical: 0, high: 0, medium: 0, low: 0, score: 0,
      });
    }
    const cr = compRiskMap.get(key)!;
    if (sev === 'Critical') cr.critical++;
    else if (sev === 'High') cr.high++;
    else if (sev === 'Medium') cr.medium++;
    else if (sev === 'Low') cr.low++;
    cr.score = cr.critical * 10 + cr.high * 5 + cr.medium * 2 + cr.low * 0.5;
  }

  const topComps = [...compRiskMap.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  // Build __COMPONENT_CVES__ mapping
  const componentCvesMap: Record<string, Array<{ id: string; severity: string; cvss: number | null; fix: string | null }>> = {};
  for (const m of matches) {
    const a = m.artifact ?? {};
    const v = m.vulnerability ?? {};
    const key = `${a.name ?? '?'}@${a.version ?? '?'}`;
    if (!componentCvesMap[key]) componentCvesMap[key] = [];
    componentCvesMap[key].push({
      id: v.id ?? '?',
      severity: normalizeSeverity(v.severity),
      cvss: v.cvss?.[0]?.metrics?.baseScore ?? null,
      fix: v.fix?.versions?.length ? v.fix.versions.join(', ') : null,
    });
  }

  const topCompsHtml = topComps.length === 0 ? '' : (() => {
    const rows = topComps.map((cr) => {
      const dataKey = escapeHtml(JSON.stringify(cr.key));
      return `<tr class="comp-risk-row" data-comp="${escapeHtml(cr.key)}" style="cursor:pointer" title="Klicken für CVE-Details">
        <td><strong>${escapeHtml(cr.name)}</strong></td>
        <td class="mono small">${escapeHtml(cr.version)}</td>
        <td class="mono"><strong>${cr.score % 1 === 0 ? cr.score : cr.score.toFixed(1)}</strong></td>
        <td class="small">
          ${cr.critical > 0 ? `<span style="color:#b91c1c;font-weight:700">${cr.critical}C</span> ` : ''}
          ${cr.high > 0 ? `<span style="color:#dc2626">${cr.high}H</span> ` : ''}
          ${cr.medium > 0 ? `<span style="color:#d97706">${cr.medium}M</span> ` : ''}
          ${cr.low > 0 ? `<span style="color:#65a30d">${cr.low}L</span>` : ''}
        </td>
        <td class="small muted">${escapeHtml(cr.ecosystem)}</td>
      </tr>
      <tr class="comp-drill-row" id="drill-${escapeHtml(cr.key.replace(/[^a-zA-Z0-9]/g, '-'))}" style="display:none">
        <td colspan="5" class="drill-panel"></td>
      </tr>`;
    }).join('');
    return `
    <div class="top-risks-card" style="--accent-risk:#d97706;margin-top:.8rem">
      <div class="top-risks-title">⚠️ Top-Komponenten nach Risiko</div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr><th>Komponente</th><th>Version</th><th>Risiko-Score</th><th>CVE-Counts</th><th>Ecosystem</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  })();

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

  const componentCvesJson = JSON.stringify(componentCvesMap);

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
.rating-card{display:flex;gap:1.2rem;align-items:stretch;margin:1rem 0;
padding:1.1rem 1.3rem;border-radius:14px;border:1px solid var(--rating-border);
background:var(--rating-bg);color:var(--rating-fg)}
.rating-grade{display:flex;flex-direction:column;align-items:center;justify-content:center;
min-width:120px;padding:.5rem 1rem;border-right:1px solid var(--rating-border)}
.rating-letter{font-size:3.2rem;font-weight:800;line-height:1;letter-spacing:-.04em;color:var(--rating-border)}
.rating-score{font-size:.85rem;font-weight:600;opacity:.85;margin-top:.3rem;font-variant-numeric:tabular-nums}
.rating-info{flex:1;min-width:0}
.rating-headline{font-size:1.1rem;font-weight:700;margin-bottom:.2rem}
.rating-explain{font-size:.92rem;opacity:.92;margin-bottom:.6rem}
.rating-reasons{margin:.4rem 0 0;padding-left:1.2rem;font-size:.85rem;line-height:1.5}
.rating-reasons li{margin:.1rem 0}
@media (max-width:640px){.rating-card{flex-direction:column;gap:.6rem}.rating-grade{border-right:0;border-bottom:1px solid var(--rating-border);padding-bottom:.6rem;min-width:0}}
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
details.lic-group{border-color:var(--lic-border);background:var(--lic-bg);color:var(--lic-fg)}
details.lic-group > summary{background:rgba(0,0,0,.04);border-bottom-color:var(--lic-border)}
.lic-badge{font-weight:700;text-transform:uppercase;letter-spacing:.08em;
font-size:.78rem;padding:.2rem .65rem;border-radius:999px;
background:var(--lic-border);color:#fff}
.compliance-warn{margin:.7rem 0;padding:.6rem 1rem;border-radius:8px;
background:#fff7ed;color:#9a3412;border:1px solid #ea580c;font-size:.88rem;font-weight:600}
@media (prefers-color-scheme:dark){.compliance-warn{background:#2c1308;color:#fb923c;border-color:#c2410c}}
.filter-bar{display:flex;align-items:center;gap:.6rem;padding:.45rem .8rem;
background:var(--card);border-bottom:1px solid var(--border)}
.tbl-filter{flex:1;min-width:0;padding:.3rem .55rem;border:1px solid var(--border);
border-radius:6px;font-size:.83rem;background:var(--bg);color:var(--fg)}
.tbl-filter:focus{outline:2px solid var(--accent);outline-offset:1px}
.filter-count{white-space:nowrap;font-size:.78rem;color:var(--muted)}
.cve-age{display:inline-block;margin-left:.35rem;padding:.05rem .4rem;font-size:.72rem;
font-weight:600;border-radius:999px;border:1px solid currentColor;
font-family:"Inter",ui-sans-serif,system-ui,sans-serif;vertical-align:middle;
line-height:1.4;letter-spacing:0;white-space:nowrap}
.top-risks-card{border-left:4px solid #b91c1c;background:#fff5f5;border-radius:10px;
padding:1rem 1.2rem;margin:.8rem 0}
@media (prefers-color-scheme:dark){.top-risks-card{background:#1c0a0a}}
.top-risks-title{font-size:.9rem;font-weight:700;margin-bottom:.7rem;color:#b91c1c}
.top-risks-card table th{background:#fee2e2;color:#7f1d1d}
.drill-panel{background:var(--accent-soft);padding:.7rem 1rem;font-size:.85rem}
.drill-panel table{font-size:.82rem}
.drill-panel th{font-size:.72rem}
.comp-risk-row:hover{background:rgba(0,43,127,.04)}
.print-btn{position:fixed;bottom:1.2rem;right:1.2rem;padding:.55rem 1.1rem;
background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:.85rem;
font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.18);z-index:100}
.print-btn:hover{background:var(--accent-2)}
/* Mobile-Optimierung */
@media (max-width:720px){
  body{padding:1rem .75rem 3rem;font-size:14px;line-height:1.5}
  main{padding:1.1rem 1rem;border-radius:12px}
  h1{font-size:1.25rem}
  .kv{grid-template-columns:1fr;padding:.7rem .85rem;gap:.5rem 0}
  .kv-label{font-size:.65rem}
  .kv-value{font-size:.82rem}
  .chips{gap:.3rem}
  .chip{font-size:.72rem;padding:.18rem .55rem}
  .section-title{font-size:.7rem;margin-top:1.5rem}
  details.group > summary,details.sev-group > summary{padding:.55rem .75rem;font-size:.9rem;flex-wrap:wrap}
  .group-name,.sev-badge{flex:1 1 auto}
  .group-count{margin-left:auto;font-size:.78rem}
  table{font-size:.8rem}
  th,td{padding:.4rem .55rem}
  th{font-size:.68rem}
  .filter-bar{flex-direction:column;align-items:stretch;gap:.35rem}
  .tbl-filter{width:100%}
  .top-risks-card{padding:.8rem .9rem}
  .top-risks-title{font-size:.85rem}
  .top-risks-card table{font-size:.78rem}
  .print-btn{width:100%;margin:.5rem 0 0}
  /* Drill-Down Panel kompakter */
  .drill-down{font-size:.78rem;padding:.5rem}
}
@media (max-width:480px){
  body{padding:.7rem .55rem 2rem;font-size:13px}
  main{padding:.85rem .75rem;border-radius:8px}
  h1{font-size:1.1rem}
  .rating-letter{font-size:2.3rem}
  .rating-headline{font-size:.95rem}
  .rating-explain{font-size:.82rem}
  .rating-reasons{font-size:.78rem}
  .cve-age{font-size:.65rem;padding:.04rem .3rem;margin-left:.25rem}
  th,td{padding:.3rem .4rem}
  /* lange URLs/PURLs nicht aus dem Layout brechen */
  td{overflow-wrap:anywhere;word-break:break-word}
  .top-risks-card td:nth-child(6){display:none}  /* Beschreibungsspalte weg */
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
  <header class="summary">
    <h1>Gesamtübersicht</h1>
    <div class="subline mono">${escapeHtml(inputName)}</div>

    <div class="rating-card" style="--rating-fg:${rating.color.fg};--rating-bg:${rating.color.bg};--rating-border:${rating.color.border}">
      <div class="rating-grade">
        <div class="rating-letter">${rating.grade}</div>
        <div class="rating-score">${rating.score} / 100</div>
      </div>
      <div class="rating-info">
        <div class="rating-headline">${escapeHtml(rating.label)}</div>
        <div class="rating-explain">${escapeHtml(rating.explain)}</div>
        ${rating.reasons.length > 0 ? `
          <ul class="rating-reasons">
            ${rating.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>` : ''}
      </div>
    </div>

    ${topRisksHtml}
    ${topCompsHtml}

    <div class="kv">
      <div>
        <div class="kv-label">Komponenten</div>
        <div class="kv-value"><strong>${comps.length}</strong> in ${ecoOrder.length} Ökosystem(en)</div>
      </div>
      <div>
        <div class="kv-label">Schwachstellen</div>
        <div class="kv-value"><strong>${matches.length}</strong> ${matches.length === 0 ? '— sauber' : 'Treffer'}</div>
      </div>
      <div>
        <div class="kv-label">Critical / High</div>
        <div class="kv-value"><strong>${sevCounts.critical}</strong> / <strong>${sevCounts.high}</strong></div>
      </div>
      <div>
        <div class="kv-label">Strong-Copyleft / Proprietary</div>
        <div class="kv-value"><strong>${licenseByCategory['strong-copyleft'].length}</strong> / <strong>${licenseByCategory['proprietary'].length}</strong></div>
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

  <div class="section-title">Lizenzen</div>
  ${comps.length === 0
    ? `<div class="muted">Keine Komponenten — keine Lizenzdaten.</div>`
    : `<div class="chips">${licenseChips}</div>${complianceWarning}${licenseGroupsHtml}`}

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
<script>
window.__COMPONENT_CVES__ = ${componentCvesJson};
(function(){
  // Filter-Logik
  function setupFilter(input){
    var total=parseInt(input.dataset.total||'0',10);
    var countEl=input.parentNode.querySelector('.filter-count');
    var tbody=input.closest('.group-body').querySelector('tbody');
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

  // Komponenten-Drill-Down
  var SEV_COLORS={Critical:'#b91c1c',High:'#dc2626',Medium:'#d97706',Low:'#65a30d',Negligible:'#6b7280',Unknown:'#9ca3af'};
  function renderDrillPanel(compKey,panel){
    var cves=(window.__COMPONENT_CVES__||{})[compKey]||[];
    if(!cves.length){panel.innerHTML='<em>Keine CVEs gefunden.</em>';return;}
    var rows=cves.map(function(c){
      var color=SEV_COLORS[c.severity]||'#888';
      return '<tr><td class="mono small">'+escHtml(c.id)+'</td>'
        +'<td><span style="background:'+color+';color:#fff;padding:.1rem .4rem;border-radius:4px;font-size:.72rem;font-weight:700">'+escHtml(c.severity)+'</span></td>'
        +'<td class="mono small">'+(c.cvss!=null?c.cvss.toFixed(1):'—')+'</td>'
        +'<td class="mono small">'+(c.fix?escHtml(c.fix):'<span style="color:#888">—</span>')+'</td>'
        +'</tr>';
    }).join('');
    panel.innerHTML='<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Fix-Version</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }
  function escHtml(s){return String(s).replace(/[&<>"\']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]||c;});}
  document.querySelectorAll('.comp-risk-row').forEach(function(row){
    row.addEventListener('click',function(){
      var compKey=row.getAttribute('data-comp');
      var drillId='drill-'+compKey.replace(/[^a-zA-Z0-9]/g,'-');
      var drillRow=document.getElementById(drillId);
      if(!drillRow)return;
      var isOpen=drillRow.style.display!=='none';
      // Close all others
      document.querySelectorAll('.comp-drill-row').forEach(function(r){r.style.display='none';});
      if(!isOpen){
        drillRow.style.display='';
        var panel=drillRow.querySelector('.drill-panel');
        if(panel)renderDrillPanel(compKey,panel);
      }
    });
  });

  // CVE-Anker: Details aufklappen bei Navigation
  function openAnchorDetails(){
    var hash=window.location.hash;
    if(!hash)return;
    var el=document.querySelector(hash);
    if(!el)return;
    var det=el.closest('details');
    if(det&&!det.open)det.open=true;
    setTimeout(function(){el.scrollIntoView({behavior:'smooth',block:'center'});},100);
  }
  window.addEventListener('hashchange',openAnchorDetails);
  openAnchorDetails();
})();
</script>
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
