# SBOM Upload App

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream: TomTonic/extract-sbom](https://img.shields.io/badge/upstream-TomTonic%2Fextract--sbom-informational)](https://github.com/TomTonic/extract-sbom)

Selbstgehostete Node.js + TypeScript Web-App, die das Go-basierte
Supply-Chain-Inspektions-Tool
[**TomTonic/extract-sbom**](https://github.com/TomTonic/extract-sbom)
um eine moderne Browser-Oberfläche, einen Schwachstellen-Scan
([grype](https://github.com/anchore/grype)) und mehrere
Aufbereitungs-Berichte ergänzt.

Du wirfst ein Artefakt (bis 5 GB) per Drag & Drop ins Browser-Fenster.
Die App lädt es **resumable** hoch, lässt extract-sbom drüber laufen,
scannt die erzeugte CycloneDX-SBOM mit grype gegen die NVD-/GHSA-DB
und liefert dir am Ende **fünf** Output-Dateien zurück — als Original-
Download, im Browser ansehbar oder als standalone-HTML zum Speichern
und Weiterverschicken.

> Die eigentliche SBOM-Extraktion, Archive-Rekursion, das Syft-Cataloging
> und das Audit-Report-Format kommen vollständig vom Upstream-Projekt.
> Dieses Repository fügt nur die Web-Hülle, die resumable-Upload-
> Maschinerie, die CVE-Aufbereitung, die ephemere Session-Logik und die
> verschiedenen HTML-Aufbereitungen hinzu. Siehe [NOTICE](NOTICE) für
> die Attribution und [LICENSE](LICENSE) für die Lizenz-Details.

## Highlights

- **Resumable Uploads** via [tus](https://tus.io) — ein abgebrochener
  5-GB-Upload setzt automatisch fort statt neu anzufangen
- **Pre-Extraktion** für reine `.exe`-Installer (Inno Setup, NSIS): wir
  knacken das Wrapping mit `7z` bzw. `innoextract` auf und reichen
  extract-sbom ein ZIP weiter, das es kennt
- **CVE-Scan** über die CycloneDX-SBOM mit [grype](https://github.com/anchore/grype)
  plus [trivy](https://github.com/aquasecurity/trivy) und
  [osv-scanner](https://github.com/google/osv-scanner) als zweiter und
  dritter Engine — Kreuzvalidierung, mehr Abdeckung
- **KEV + EPSS Anreicherung**: aktiv ausgenutzte Schwachstellen aus der
  [CISA KEV-Liste](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  werden rot markiert; EPSS-Exploit-Wahrscheinlichkeit als Prozent angezeigt
- **Bösartige-Paket-Erkennung** via osv-scanner (MAL-* IDs) — Alarm wenn
  das Artefakt Pakete mit bestätigter Malware enthält
- **Secret-Scanner** via [gitleaks](https://github.com/gitleaks/gitleaks):
  findet versehentlich eingebettete Credentials — NIEMALS im Klartext
  (Shred + Redaction, nur maskierte Vorschau in den Reports)
- **Cryptographic Bill of Materials (CBOM)**: heuristischer Krypto-Inventar
  aus SBOM-Komponenten — erkennt bekannte Krypto-Bibliotheken, markiert
  schwache Primitive und fehlende Post-Quantum-Sicherheit
- **Binär-Analyse** via [cve-bin-tool](https://github.com/intel/cve-bin-tool):
  CVEs in eingebetteten kompilierten Bibliotheken direkt im Artefakt
- **VEX-Skelett** ([CycloneDX VEX 1.6](https://github.com/CycloneDX/bom-examples/tree/master/VEX))
  jetzt automatisch vorausgefüllt: KEV-Treffer als `exploitable`, Fixes
  als `in_triage` mit Update-Response — noch menschliche Prüfung nötig
- **Gesamtübersicht-HTML** kombiniert Komponenten, Lizenz-Compliance,
  Schwachstellen, Secrets, CBOM, Zusatz-Scanner und Binär-Analyse in einer
  standalone-Seite — alle Sektionen aufklappbar, Live-Filter über jede
  Tabelle, Software-Delivery-Quality-Score berücksichtigt KEV und Secrets
- **SPDX-Export** via `syft convert` zusätzlich zu CycloneDX für Tools
  wie FOSSology oder ORT
- **Live-Telemetrie** über Server-Sent Events: PID, Kommando, Phase mit
  Progress-Bar, Log Zeile-für-Zeile, Stop-Button
- **Per-Session-Job-Queue mit Historie**: mehrere Artefakte
  hintereinander, Downloads bleiben bis Sitzungsende erreichbar
- **Ephemere by design**: Per-Session-Scratch-Dir, Passwörter via Env-Var
  (Fallback 0600-Datei mit Shred), Auto-Cleanup bei Idle-GC, Reload,
  SIGTERM oder explizitem „Neue Sitzung"
- **Persistenter grype-DB-Cache** via Volume: 80 MB Vuln-DB
  überlebt Container-Restarts
- **Polizeiblau-Design** mit Dark-Mode-Unterstützung, vollständig auf
  Deutsch lokalisiert

## Outputs pro Job

| Datei | Format | Inhalt |
| --- | --- | --- |
| `<name>.cdx.json` | CycloneDX JSON | Rohe SBOM von extract-sbom |
| `<name>.report.md` | Markdown | Audit-Report (Extraktor-Log, Restrisiken) |
| `<name>.spdx.json` | SPDX JSON | dieselbe SBOM im SPDX-Format |
| `<name>.vulnerabilities.json` | grype JSON | CVE-Treffer in Rohform |
| `<name>.vulnerabilities.csv` | CSV | CVE-Liste für Excel/Auditoren |
| `<name>.vulnerabilities.html` | Standalone HTML | farbig kategorisiert, aufklappbar nach Severity |
| `<name>.trivy.json` | trivy JSON | CVE-Treffer von trivy (zweiter Scanner) |
| `<name>.osv.json` | osv-scanner JSON | CVE- und Malware-Treffer (osv-scanner) |
| `<name>.secrets.json` | JSON | Secret-Funde (gitleaks) — nur maskierte Vorschau |
| `<name>.cbom.json` | CycloneDX 1.6 JSON | Kryptografisches Bill of Materials |
| `<name>.binary-cve.json` | JSON | CVEs in eingebetteten Binärdateien (cve-bin-tool) |
| `<name>.vex.json` | CycloneDX VEX | Vorausgefülltes VEX-Skelett (KEV→exploitable, Fix→in_triage) |
| `<name>.summary.html` | Standalone HTML | **Gesamtübersicht**: alle Scanner, KEV/Secrets/CBOM/Binär |

In der UI-Job-Karte gibt es pro Datei drei Aktionen:

- **Ansicht** — Inline-Modal im selben Tab mit gerendertem HTML
- **Als HTML** — Standalone-HTML-Datei runterladen
- **Original** — Roh-Datei (JSON / Markdown / CSV)

## Quickstart

### Aus dem veröffentlichten Docker-Image

Ein Multi-Stage-Image wird auf jeden Commit nach `main` und jeden
`v*.*.*`-Tag gebaut und nach Docker Hub (`merlin2539/sbom`) und GHCR
(`ghcr.io/merlin2533/sbom`) gepusht.

```bash
curl -fsSL https://raw.githubusercontent.com/merlin2533/sbom/main/docker-compose.yml \
    -o docker-compose.yml
docker compose up -d
# → http://localhost:3000
```

Update-Workflow:

```bash
docker compose pull && docker compose up -d
```

Das Image bringt alles mit: `extract-sbom`, `syft`, `grype`, `trivy`,
`osv-scanner`, `gitleaks`, `cve-bin-tool`, `innoextract`, `p7zip-full`,
`unshield`, `tini`. Du brauchst nur einen Docker-Host.

Die compose-Datei legt automatisch ein **persistentes Volume**
`grype-cache` für die Vuln-DB an, damit sie Container-Restarts
überlebt.

### Lokal vom Source

Voraussetzungen: Node.js ≥ 20, Go ≥ 1.21, git mit Submodule-Support.

```bash
git clone https://github.com/merlin2533/sbom.git
cd sbom
./scripts/install.sh         # Submodule init, npm ci, Go-Build, TS-Build
npm start                    # http://localhost:3000
```

`install.sh` ist idempotent. Vor dem Start optional `./scripts/preflight.sh`
für eine Bereitschafts-Prüfung (extract-sbom, grype, syft, scratch-Dir
beschreibbar, Frontend-Build da).

## Konfiguration

| Env-Var | Default | Bedeutung |
| --- | --- | --- |
| `PORT` | `3000` | HTTP-Port |
| `HOST` | `0.0.0.0` | Bind-Adresse |
| `SCRATCH_DIR` | `$TMPDIR/sbom-upload-app` | Per-Session-Arbeitsverzeichnis. Setze `/dev/shm/...` um alles im RAM zu halten |
| `EXTRACT_SBOM_BIN` | `extract-sbom` | Pfad zum Binary (im Image bereits auf `/usr/local/bin/extract-sbom`) |
| `EXTRACT_SBOM_ARGS` | `--unsafe` | Argumente die jedem Aufruf vorgesetzt werden. `--unsafe` deaktiviert den inneren bwrap-Sandbox |
| `SANDBOX_MODE` | `none` | `auto` / `bwrap` / `firejail` / `none` für den äußeren Sandbox-Wrapper |
| `GRYPE_DB_CACHE_DIR` | `/var/cache/grype` | Wohin grype die Vuln-DB ablegt; das compose-Volume mountet hier ein named volume |
| `MAX_UPLOAD_BYTES` | `5368709120` | Upload-Cap (Default 5 GiB) |
| `SESSION_IDLE_MS` | `1800000` | Idle-GC (30 min) |
| `SHUTDOWN_GRACE_MS` | `30000` | Zeit für In-Flight-Jobs bei SIGTERM |
| `UPLOAD_RATE_PER_MIN` | `5` | Per-IP-Rate-Limit auf neue Upload-Erzeugung |
| `AUTH_USER` / `AUTH_PASS` | _(leer)_ | HTTP Basic Auth über alle Routen wenn beide gesetzt |
| `TRUST_PROXY` | `0` | Auf `1` setzen wenn hinter TLS-Proxy (Caddy/nginx/Traefik). Macht Cookie `Secure` und respektiert `X-Forwarded-*` |
| `LOG_LEVEL` | `info` | pino-Level |
| `LOG_PRETTY` | _(auto)_ | Forciert pretty-stdout |
| `BINARY_SCAN_MAX_BYTES` | `2147483648` | Max. Artefaktgröße für cve-bin-tool (2 GiB) |
| `SECRET_SCAN_MAX_BYTES` | `1073741824` | Max. Upload-Größe zum Entpacken für gitleaks (1 GiB) |

## Versionsanzeige

Topbar zeigt `vMAJOR.MINOR.<commit_count>+<short_sha>`. Beim
`docker compose pull` siehst du sofort, ob du eine neue Version hast.
Auch unter `/api/health` als JSON-Feld `version`.

## Sicherheit & Privatsphäre

Die App ist **permissive by default**, damit sie auch hinter Tunneln,
auf HTTP-IP-Adressen und mit restriktiven Browser-Konfigurationen
funktioniert. Für Single-User-Setups ist das angemessen; wer das App
öffentlich exponieren will, sollte:

- TLS-Proxy davor (`TRUST_PROXY=1` setzen)
- `AUTH_USER`/`AUTH_PASS` setzen
- `MAX_UPLOAD_BYTES` und `UPLOAD_RATE_PER_MIN` an die eigene
  Risiko-Toleranz anpassen
- SCRATCH_DIR auf eine tmpfs zeigen lassen (`/dev/shm/sbom`), damit
  Uploads und Extraktion komplett im RAM passieren

### Datenfluss

- Pro Session ein eigener Scratch-Ordner unter `SCRATCH_DIR/<sid>/`,
  mode `0700`. Beim Server-Start wird der Scratch-Root gewipped.
- Passwörter wandern bevorzugt in die `EXTRACT_SBOM_PASSWORDS`-Env-Var
  des Kind-Prozesses (kommen nie auf Disk). Fallback: 0600-Datei, die
  per `crypto.randomBytes` überschrieben und dann unlinked wird.
- Das hochgeladene Artefakt wird gelöscht, sobald extract-sbom sowie
  der Binär- und Secret-Scan darauf beendet sind. Die erzeugten Berichte
  bleiben bis zur Session-Zerstörung. gitleaks-Rohausgaben (mit echten
  Secret-Werten) werden vor der Aufbereitung per Shred gelöscht — in die
  Output-Dateien wandert ausschließlich eine maskierte Vorschau.
- Auto-Cleanup über Idle-GC (30 min), Browser-Reload, „Neue
  Sitzung"-Button, oder SIGTERM-Drain.

### CSRF / Sessions

Nach mehreren echten Bug-Reports auf HTTP-IP-Deployments läuft die
Session-Auflösung jetzt über **drei** Transporte (Cookie / `X-Session-Id`
Header / `?sid=` Query) und die App akzeptiert die erste sid, die zu
einer lebenden Session passt. Bei kompletter Miss-Resolution wird
**automatisch eine frische Session erzeugt** (Auto-Create-Fallback),
damit der Workflow trotz Tab-Discarding, stale Cookies und ähnlichem
nicht stehenbleibt.

## API

| Methode | Pfad | Zweck |
| --- | --- | --- |
| `GET` | `/` | Setzt/erneuert Session-Cookie, liefert SPA |
| `*` | `/api/tus/*` | tus 1.0 — resumable upload protocol |
| `POST` | `/api/jobs` | Body `{ passwords?: string }` — startet extract-sbom auf zuletzt hochgeladenem Artefakt |
| `GET` | `/api/state` | One-shot Snapshot der Session |
| `GET` | `/api/events` | Server-Sent Events: `state`, `log`, `outputs`, `phase`, `closed` |
| `POST` | `/api/cancel` | SIGTERM auf laufenden Job (eskaliert zu SIGKILL nach 5 s) |
| `GET` | `/api/download/:jobId/:name` | Output-Datei downloaden |
| `GET` | `/api/view/:jobId/:name` | Output als HTML rendern; `?download=1` setzt `Content-Disposition: attachment` |
| `POST` | `/api/reset` | Session sofort zerstören |
| `GET` | `/api/health` | Liveness, Session-Count, App-Version, erkannter Sandbox |

## Repository-Layout

```
src/                     Node/TypeScript-Server (kompiliert zu dist/)
src/pre-extract.ts       7z/innoextract-Vorverarbeitung für .exe-Installer
src/vuln-report.ts       grype-Aufruf + CSV/HTML-Aufbereitung der CVE-Liste
src/summary-report.ts    Gesamtübersicht: Komponenten + Lizenzen + CVEs + Restrisiken
public/src/              Browser-TypeScript-Source
public/                  index.html, styles.css, vendorter tus-Client
scripts/install.sh       Setup-Skript (Submodule + Go-Build + npm + Vendor)
scripts/preflight.sh     Bereitschafts-Prüfung
vendor/extract-sbom/     Git-Submodule auf TomTonic/extract-sbom
tests/                   vitest-Suite (85 Tests)
.github/workflows/       Docker-Build- + Publish-Pipeline
```

## Build & Tests

```bash
npm run build       # TS-Server + Frontend + vendor tus-js-client
npm test            # vitest
npm run typecheck   # tsc --noEmit für Server + Frontend
```

85 Tests decken Security-Middlewares (CSRF, Basic-Auth, Rate-Limit,
Security-Headers), Session-Lebenszyklus, Passwort-Transport (env vs.
Datei, Shred-on-exit), Step-Detector, Sandbox-Builder, Graceful-Drain,
das Job-Lifecycle sowie die Security-Scanner-Module (CBOM-Erkennung,
Secret-Redaction, KEV/EPSS-Offline-Modus, Graceful-Degradation) ab.

## Contributing

Issues und PRs willkommen. Drei Grundregeln:

1. Die Datenschutz-Garantien dürfen nicht erodieren: ephemere
   Session, keine Passwörter auf Disk per Default, keine Secrets in
   Logs. Tests in `tests/security.test.ts` halten das nach.
2. Die `extract-sbom`-Logik nicht in dieses Repo abkupfern. Bugs am
   Extraktor selbst gehören
   [upstream](https://github.com/TomTonic/extract-sbom/issues).
3. Vor jedem PR: `npm run typecheck && npm test`. Die
   `docker-publish`-CI baut das Image nur erfolgreich, wenn beides
   grün ist.

## Lizenz

MIT — siehe [LICENSE](LICENSE).

Das Submodule unter `vendor/extract-sbom/` ist BSD-3-Clause und bleibt
Eigentum des Upstream-Autors; siehe [NOTICE](NOTICE) und
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
