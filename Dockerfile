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
LABEL org.opencontainers.image.title="sbom-upload-app" \
      org.opencontainers.image.description="Ephemeral web frontend for TomTonic/extract-sbom" \
      org.opencontainers.image.source="https://github.com/merlin2533/sbom" \
      org.opencontainers.image.licenses="MIT"

# tini for proper PID-1 signal handling; bubblewrap for the optional inner
# sandbox; curl needed both for syft installer and for the HEALTHCHECK probe;
# ca-certificates for TLS to any external mirror.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bubblewrap ca-certificates curl tini \
      # Extraktor-Toolchain für extract-sbom — sonst klagt der Report
      # „7zz not found", „unshield not found", „unzip not found" usw.
      # p7zip-rar gibt's in Debian wegen Lizenz nicht mehr; RAR-Support
      # liefert unrar-free.
      p7zip-full unzip unrar-free unshield cabextract \
      tar xz-utils bzip2 zstd \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "$SYFT_VERSION" \
 # extract-sbom sucht 7zz (neuer Binary-Name), nicht 7z (alter Name).
 # p7zip-full installiert 7z; wir verlinken 7zz darauf.
 && ln -s "$(command -v 7z)" /usr/local/bin/7zz \
 && rm -rf /var/lib/apt/lists/*

# extract-sbom binary from stage 1.
COPY --from=go-build /out/extract-sbom /usr/local/bin/extract-sbom

# Non-root runtime user. Scratch lives outside /app so it can be a tmpfs.
RUN useradd -r -u 10001 -m -s /sbin/nologin sbom \
 && mkdir -p /scratch /app \
 && chown -R sbom:sbom /scratch /app

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
    LOG_LEVEL=info \
    LOG_PRETTY=0

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/index.js"]
