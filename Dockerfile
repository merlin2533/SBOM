# syntax=docker/dockerfile:1.7
#
# SBOM Upload App — multi-stage container image
# Stage 1: build the upstream Go extract-sbom binary
# Stage 2: build the Node/TypeScript server + frontend
# Stage 3: lean runtime with bwrap, syft and tini
# Published as merlin2539/sbom by .github/workflows/docker-publish.yml

ARG NODE_VERSION=20
ARG GO_VERSION=1.26
ARG SYFT_VERSION=v1.16.0
# Versionspins für die zusätzlichen Security-Scanner
ARG OSV_SCANNER_VERSION=v2.3.8
ARG GITLEAKS_VERSION=8.30.1
# Build-time override for the version string displayed in the UI and on
# /api/health. The GitHub Actions workflow computes
#   MAJOR.MINOR.<commit_count>+<short_sha>
# and passes it in; falls back to package.json's static version locally.
ARG APP_VERSION=

# ----------------------------------------------------------------------------
# Stage 1 — Go build of vendor/extract-sbom
# ----------------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS go-build

# Let Go fetch a newer toolchain on the fly if vendor/extract-sbom's go.mod
# requires one. The official `golang:` images otherwise pin GOTOOLCHAIN=local
# and the build dies with "go.mod requires go >= X.Y.Z".
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY vendor/extract-sbom ./extract-sbom

# The upstream layout typically exposes `./cmd/extract-sbom` as the main
# package; fall back to the module root if not. Try both deterministically.
RUN set -eux; \
    cd extract-sbom; \
    if [ -d ./cmd/extract-sbom ]; then PKG=./cmd/extract-sbom; \
    elif [ -f ./main.go ]; then PKG=./; \
    else PKG="$(find . -maxdepth 3 -type d -name 'extract-sbom' -path '*/cmd/*' | head -n1)"; \
         [ -n "$PKG" ] || { echo "could not locate extract-sbom main package"; exit 1; }; \
    fi; \
    echo "Building Go package: $PKG"; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/extract-sbom "$PKG"

# ----------------------------------------------------------------------------
# Stage 2 — Node/TypeScript build
# ----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS node-build

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

# Source.
COPY tsconfig.json tsconfig.frontend.json ./
COPY scripts ./scripts
COPY src ./src
COPY public ./public

RUN npm run build \
 && npm prune --omit=dev

# ----------------------------------------------------------------------------
# Stage 3 — runtime
# ----------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS runtime

ARG SYFT_VERSION
ARG OSV_SCANNER_VERSION
ARG GITLEAKS_VERSION
LABEL org.opencontainers.image.title="sbom-upload-app" \
      org.opencontainers.image.description="Ephemeral web frontend for TomTonic/extract-sbom" \
      org.opencontainers.image.source="https://github.com/merlin2533/sbom" \
      org.opencontainers.image.licenses="MIT"

# tini for proper PID-1 signal handling; bubblewrap for the optional inner
# sandbox; curl needed both for syft installer and for the HEALTHCHECK probe;
# ca-certificates for TLS to any external mirror.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl tini \
      # extract-sbom benutzt laut Source-Code (internal/extract/extract_external.go)
      # nur 7zz/7za/7z (alle Archive: ZIP, 7z, RAR, MSI, CAB) und unshield
      # (InstallShield-Cabinets). p7zip-full liefert 7z.
      #
      # bewusst NICHT installiert: bubblewrap. extract-sbom wickelt sonst
      # jede Tool-Invokation per Default in `bwrap` ein, und das schlägt
      # in vielen Container-Hosts fehl (kein unprivileged user namespace
      # → „No permissions to create new namespace"). Selbst mit globalem
      # --unsafe zieht extract-sbom den per-Tool-bwrap mit, sobald das
      # Binary auf PATH liegt. Lösung: bwrap weglassen, dann fällt
      # extract-sbom auf direkte exec.Command zurück — der Container ist
      # sowieso die einzige Sandbox-Schicht.
      p7zip-full unshield innoextract \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "$SYFT_VERSION" \
 # grype: CVE-Datenbank-Scanner. Wir nutzen ihn nach jedem extract-sbom-Lauf
 # auf der erzeugten CycloneDX-SBOM und bauen daraus einen farbig
 # kategorisierten HTML-Bericht.
 && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /usr/local/bin \
 # extract-sbom prefers den kanonischen Namen 7zz; Debian installiert 7z.
 # Symlink, damit der Report „Using 7zz" sagt statt auf den Fallback geht.
 && ln -s "$(command -v 7z)" /usr/local/bin/7zz \
 # cosign: optionales Signieren von Output-Artefakten.
 && curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
      -o /usr/local/bin/cosign \
 && chmod +x /usr/local/bin/cosign \
 && rm -rf /var/lib/apt/lists/*

# ────────────────────────────────────────────────────────────────────────────
# Zusätzliche Security-Scanner für erweiterte Bedrohungsanalyse.
#
# Bewusst in einem eigenen, NICHT-FATALEN RUN: schlägt ein Download fehl
# (neuer Release-Tag, Netzwerkpolicy, Mirror-Ausfall), bricht der Image-Build
# NICHT ab — die App überspringt den jeweiligen Scanner dank Graceful-
# Degradation zur Laufzeit einfach. Die Kern-Tools (syft/grype/cosign) oben
# bleiben dagegen strikt erforderlich.
# ────────────────────────────────────────────────────────────────────────────
RUN set -ux; \
    # trivy: umfassender SBOM-/Container-Scanner von Aqua Security — zweiter
    # CVE-Engine zur Kreuzvalidierung von grype.
    ( curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin ) \
      || echo "WARN: trivy-Installation fehlgeschlagen — Scanner wird zur Laufzeit übersprungen"; \
    # osv-scanner: Googles OSV-Scanner — erkennt zusätzlich bösartige Pakete
    # (MAL-* IDs) aus der OSV-Datenbank.
    ( curl -sSfL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
        -o /usr/local/bin/osv-scanner \
      && chmod +x /usr/local/bin/osv-scanner ) \
      || echo "WARN: osv-scanner-Installation fehlgeschlagen — Scanner wird zur Laufzeit übersprungen"; \
    # gitleaks: Secret-Scanner. WICHTIG: Die App schreibt nie den Klartext-
    # Secret in Ausgabedateien (shredUnlink + Redaction-Logik in secret-scan.ts).
    ( curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
      && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
      && chmod +x /usr/local/bin/gitleaks \
      && rm -f /tmp/gitleaks.tar.gz ) \
      || echo "WARN: gitleaks-Installation fehlgeschlagen — Scanner wird zur Laufzeit übersprungen"; \
    # cve-bin-tool: Intels CVE-Scanner für Binärdateien. In einem Python-venv
    # isoliert, damit das schlanke Node-Image nicht verschmutzt wird.
    ( apt-get update \
      && apt-get install -y --no-install-recommends python3 python3-venv \
      && python3 -m venv /opt/cve-bin-tool \
      && /opt/cve-bin-tool/bin/pip install --no-cache-dir cve-bin-tool \
      && ln -sf /opt/cve-bin-tool/bin/cve-bin-tool /usr/local/bin/cve-bin-tool ) \
      || echo "WARN: cve-bin-tool-Installation fehlgeschlagen — Scanner wird zur Laufzeit übersprungen"; \
    # clamav: Malware-Scanner. clamscan läuft als One-Shot pro Job (KEIN
    # dauerhafter clamd-Daemon). freshclam lädt die Signatur-DB einmalig zur
    # Build-Zeit nach /var/lib/clamav (Stand: Image-Build).
    ( apt-get update \
      && apt-get install -y --no-install-recommends clamav clamav-freshclam \
      && freshclam --quiet ) \
      || echo "WARN: clamav-Installation/Signatur-DB fehlgeschlagen — Scanner wird zur Laufzeit übersprungen"; \
    rm -rf /var/lib/apt/lists/*

# extract-sbom binary from stage 1.
COPY --from=go-build /out/extract-sbom /usr/local/bin/extract-sbom

# Non-root runtime user. Scratch lives outside /app so it can be a tmpfs.
# /var/cache/grype ist ein persistentes Cache-Volume — überlebt
# Container-Restarts, sodass grype's ~80 MB Vuln-DB nicht jedesmal neu
# heruntergeladen wird.
RUN useradd -r -u 10001 -m -s /sbin/nologin sbom \
 && mkdir -p /scratch /app /var/cache/grype /var/lib/clamav /var/log/clamav \
 && chown -R sbom:sbom /scratch /app /var/cache/grype /var/lib/clamav /var/log/clamav

WORKDIR /app
COPY --from=node-build --chown=sbom:sbom /app/node_modules ./node_modules
COPY --from=node-build --chown=sbom:sbom /app/dist         ./dist
COPY --from=node-build --chown=sbom:sbom /app/public       ./public
COPY --from=node-build --chown=sbom:sbom /app/package.json ./package.json

USER sbom

ENV APP_VERSION=$APP_VERSION \
    NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    SCRATCH_DIR=/scratch \
    # Container is the outer sandbox already. Users who grant CAP_SYS_ADMIN
    # can flip this to "bwrap" for a defence-in-depth inner sandbox.
    SANDBOX_MODE=none \
    # extract-sbom's own internal sandbox (bwrap) needs CAP_SYS_ADMIN, which
    # we drop in the recommended runtime. Passing --unsafe tells extract-sbom
    # to skip its inner sandbox; the container itself isolates the workload.
    # Override at runtime with `-e EXTRACT_SBOM_ARGS="..."` if you've granted
    # the capability and want the inner bwrap layer too.
    EXTRACT_SBOM_ARGS=--unsafe \
    # grype: persistente Cache-Lokation für die Vulnerability-DB, sodass
    # sie Container-Restarts überlebt (sonst ~80 MB Download bei jedem
    # Cold Start). docker-compose.yml mountet hier ein named volume.
    GRYPE_DB_CACHE_DIR=/var/cache/grype \
    LOG_LEVEL=info \
    LOG_PRETTY=0

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/index.js"]
