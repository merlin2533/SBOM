// ─────────────────────────────────────────────────────────────────────────────
// EOL Detection — static end-of-life data for common ecosystems
//
// No network required. Pattern-matches component name+version against the
// built-in table and returns EOL date + expiry status.
// ─────────────────────────────────────────────────────────────────────────────

export interface EolInfo {
  eolDate: string;      // ISO 8601 date e.g. "2025-04-30"
  isExpired: boolean;
  daysUntilEol?: number; // undefined when expired
}

interface EolEntry {
  /** Regex matched against the component name (case-insensitive) */
  namePattern: RegExp;
  /** Regex matched against the major[.minor] version prefix */
  versionPattern: RegExp;
  eolDate: string;
}

// ── Static data table ─────────────────────────────────────────────────────────
// Each entry has a name pattern, a version pattern, and an ISO EOL date.
// Ecosystem names vary (nodejs, node, node.js, pkg:npm, etc.) — we cast a
// wide net in the name pattern.

const EOL_TABLE: EolEntry[] = [
  // Node.js
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^12\./, eolDate: '2022-04-30' },
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^14\./, eolDate: '2023-04-30' },
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^16\./, eolDate: '2023-09-11' },
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^18\./, eolDate: '2025-04-30' },
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^20\./, eolDate: '2026-04-30' },
  { namePattern: /^node(?:js|\.js)?$/i, versionPattern: /^22\./, eolDate: '2027-04-30' },

  // Python
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^2\.7\./, eolDate: '2020-01-01' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^2\.7$/, eolDate: '2020-01-01' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^3\.6/, eolDate: '2021-12-23' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^3\.7/, eolDate: '2023-06-27' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^3\.8/, eolDate: '2024-10-14' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^3\.9/, eolDate: '2025-10-31' },
  { namePattern: /^python(?:3|2)?$/i, versionPattern: /^3\.10/, eolDate: '2026-10-31' },

  // Java (OpenJDK)
  { namePattern: /^(?:openjdk|java|jdk|jre)$/i, versionPattern: /^1\.8\.|^8\./, eolDate: '2031-12-31' },
  { namePattern: /^(?:openjdk|java|jdk|jre)$/i, versionPattern: /^11\./, eolDate: '2026-09-30' },
  { namePattern: /^(?:openjdk|java|jdk|jre)$/i, versionPattern: /^17\./, eolDate: '2029-09-30' },
  { namePattern: /^(?:openjdk|java|jdk|jre)$/i, versionPattern: /^21\./, eolDate: '2031-09-30' },

  // Ubuntu
  { namePattern: /^ubuntu$/i, versionPattern: /^18\.04/, eolDate: '2023-05-31' },
  { namePattern: /^ubuntu$/i, versionPattern: /^20\.04/, eolDate: '2025-05-29' },
  { namePattern: /^ubuntu$/i, versionPattern: /^22\.04/, eolDate: '2027-04-21' },
  { namePattern: /^ubuntu$/i, versionPattern: /^24\.04/, eolDate: '2029-04-25' },

  // Debian
  { namePattern: /^debian$/i, versionPattern: /^9\./, eolDate: '2022-06-30' },
  { namePattern: /^debian$/i, versionPattern: /^10\./, eolDate: '2024-06-30' },
  { namePattern: /^debian$/i, versionPattern: /^11\./, eolDate: '2026-06-30' },
  { namePattern: /^debian$/i, versionPattern: /^12\./, eolDate: '2028-06-30' },

  // .NET Core / 5 / 6 / 7 / 8
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^2\.1/, eolDate: '2021-08-21' },
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^3\.1/, eolDate: '2022-12-13' },
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^5\./, eolDate: '2022-05-10' },
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^6\./, eolDate: '2024-11-12' },
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^7\./, eolDate: '2024-05-14' },
  { namePattern: /^\.?net(?:core|-core|sdk|runtime)?$/i, versionPattern: /^8\./, eolDate: '2026-11-10' },

  // PHP
  { namePattern: /^php$/i, versionPattern: /^7\.2/, eolDate: '2020-11-30' },
  { namePattern: /^php$/i, versionPattern: /^7\.3/, eolDate: '2021-12-06' },
  { namePattern: /^php$/i, versionPattern: /^7\.4/, eolDate: '2022-11-28' },
  { namePattern: /^php$/i, versionPattern: /^8\.0/, eolDate: '2023-11-26' },
  { namePattern: /^php$/i, versionPattern: /^8\.1/, eolDate: '2025-12-31' },
  { namePattern: /^php$/i, versionPattern: /^8\.2/, eolDate: '2026-12-31' },
];

// ── Core lookup ───────────────────────────────────────────────────────────────

/**
 * Returns EOL info for a component, or undefined if not in the table.
 * @param name  Component name (e.g. "nodejs", "python", "ubuntu")
 * @param version  Component version string (e.g. "18.17.0", "3.9.7")
 * @param now  Reference date (defaults to today; injectable for tests)
 */
export function lookupEol(
  name: string,
  version: string,
  now: Date = new Date()
): EolInfo | undefined {
  for (const entry of EOL_TABLE) {
    if (!entry.namePattern.test(name)) continue;
    if (!entry.versionPattern.test(version)) continue;

    const eolMs = Date.parse(entry.eolDate);
    const isExpired = now.getTime() >= eolMs;
    const daysUntilEol = isExpired
      ? undefined
      : Math.ceil((eolMs - now.getTime()) / (1000 * 60 * 60 * 24));

    return {
      eolDate: entry.eolDate,
      isExpired,
      daysUntilEol,
    };
  }
  return undefined;
}

/** Expose the raw table (for introspection/tests). */
export function eolTable(): ReadonlyArray<EolEntry> {
  return EOL_TABLE;
}
