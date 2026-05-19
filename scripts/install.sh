#!/usr/bin/env bash
# install.sh — one-shot bootstrap for the SBOM upload app.
# Safe to re-run; all steps are idempotent.
set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────

# Resolve the repo root from the location of this script (scripts/ subdir).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colour helpers (no-op when stdout is not a TTY or tput is absent).
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
  BOLD=$(tput bold); RESET=$(tput sgr0)
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

ok()   { echo "${GREEN}✓${RESET} $*"; }
warn() { echo "${YELLOW}!${RESET} $*"; }
fail() { echo "${RED}✗${RESET} $*" >&2; exit 1; }

# Version comparison: returns 0 when $1 >= $2  (e.g. version_ge 20.1 20)
version_ge() {
  # Use sort -V; the smaller version will appear first.
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# ── 1. Require git ────────────────────────────────────────────────────────────
command -v git >/dev/null 2>&1 || fail "git is not installed. Please install git and re-run."

# ── 2. Require Node ≥ 20 ──────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || fail "node is not installed. Install Node.js ≥ 20 and re-run."
NODE_VER=$(node --version | sed 's/^v//')
version_ge "$NODE_VER" "20" || fail "Node.js ≥ 20 required, found v${NODE_VER}."

# ── 3. Initialise submodule ───────────────────────────────────────────────────
echo "${BOLD}Initialising git submodules…${RESET}"
git -C "$REPO_ROOT" submodule update --init --recursive

# ── 4. Install Node dependencies ─────────────────────────────────────────────
echo "${BOLD}Installing Node dependencies…${RESET}"
if [ -f "$REPO_ROOT/package-lock.json" ]; then
  (cd "$REPO_ROOT" && npm ci)
else
  (cd "$REPO_ROOT" && npm install)
fi

# ── 5. Build extract-sbom Go binary ──────────────────────────────────────────
EXTRACT_SBOM_BUILT=false
GO_BIN="$REPO_ROOT/bin/extract-sbom"

if command -v go >/dev/null 2>&1; then
  GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' | head -n1)
  if version_ge "$GO_VER" "1.21"; then
    echo "${BOLD}Building extract-sbom…${RESET}"

    # Discover the main package: prefer cmd/ sub-package, fall back to repo root.
    CMD_MAIN=$(find "$REPO_ROOT/vendor/extract-sbom" -name "main.go" -path "*/cmd/*" | head -n1)
    if [ -n "$CMD_MAIN" ]; then
      # Derive the package path relative to the module root (vendor/extract-sbom).
      PKG_DIR=$(dirname "$CMD_MAIN")
      PKG_REL="./${PKG_DIR#"$REPO_ROOT/vendor/extract-sbom/"}"
    else
      # Fallback: main.go at module root
      PKG_REL="."
    fi

    mkdir -p "$REPO_ROOT/bin"
    (
      cd "$REPO_ROOT/vendor/extract-sbom"
      go build -trimpath -ldflags="-s -w" -o "$GO_BIN" "$PKG_REL"
    )
    EXTRACT_SBOM_BUILT=true
    ok "extract-sbom built at bin/extract-sbom"
  else
    warn "Go ${GO_VER} found but ≥ 1.21 required — skipping Go build. Install Go ≥ 1.21 and re-run, or supply EXTRACT_SBOM_BIN."
  fi
else
  warn "go not found — skipping Go build. Install Go ≥ 1.21 from https://go.dev/dl/ and re-run, or supply EXTRACT_SBOM_BIN."
fi

# ── 6. Build TypeScript (server + frontend + vendor tus) ─────────────────────
echo "${BOLD}Running npm run build…${RESET}"
BUILD_OK=true
(cd "$REPO_ROOT" && npm run build) || {
  BUILD_OK=false
  warn "npm run build exited non-zero — see errors above."
  # Attempt the individual steps that may still succeed independently.
  echo "${BOLD}Attempting partial build: frontend + vendor:tus…${RESET}"
  (cd "$REPO_ROOT" && npm run build:frontend) || warn "build:frontend also failed."
  (cd "$REPO_ROOT" && npm run vendor:tus)     || warn "vendor:tus also failed."
}

# ── 7. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}────────────────────────── Install summary ──────────────────────────────${RESET}"

# Node
ok "node v${NODE_VER}"

# extract-sbom
SBOM_BIN_OK=false
if $EXTRACT_SBOM_BUILT && [ -x "$GO_BIN" ]; then
  ok "extract-sbom built at bin/extract-sbom"
  SBOM_BIN_OK=true
elif [ -n "${EXTRACT_SBOM_BIN:-}" ] && [ -x "${EXTRACT_SBOM_BIN}" ]; then
  ok "extract-sbom from \$EXTRACT_SBOM_BIN: $EXTRACT_SBOM_BIN"
  SBOM_BIN_OK=true
elif command -v extract-sbom >/dev/null 2>&1; then
  ok "extract-sbom found on PATH: $(command -v extract-sbom)"
  SBOM_BIN_OK=true
else
  echo "${RED}✗${RESET} extract-sbom not found (Go build skipped and no \$EXTRACT_SBOM_BIN). Install Go and re-run, or set EXTRACT_SBOM_BIN."
fi

# Vendored tus
TUS_OK=false
if [ -f "$REPO_ROOT/public/vendor/tus.min.js" ]; then
  ok "tus vendored"
  TUS_OK=true
else
  echo "${RED}✗${RESET} public/vendor/tus.min.js missing — run npm run vendor:tus (or re-run ./scripts/install.sh)"
fi

# Optional: bwrap
if command -v bwrap >/dev/null 2>&1; then
  ok "bwrap available $(command -v bwrap)"
else
  warn "bwrap missing (sandboxing disabled; set SANDBOX_MODE=none or use --unsafe to suppress errors)"
fi

# Optional: syft
if command -v syft >/dev/null 2>&1; then
  ok "syft available $(command -v syft)"
else
  warn "syft missing (extract-sbom needs it at runtime)"
fi

# Optional: grype
if command -v grype >/dev/null 2>&1; then
  ok "grype available $(command -v grype)"
else
  warn "grype missing (vuln scan disabled)"
fi

echo ""

# ── 8. Exit code ─────────────────────────────────────────────────────────────
FATAL=false

if ! $SBOM_BIN_OK; then
  echo "${RED}${BOLD}Install incomplete:${RESET} extract-sbom binary is missing."
  echo "  • Install Go ≥ 1.21 and re-run this script, OR"
  echo "  • Set EXTRACT_SBOM_BIN=/path/to/extract-sbom and re-run"
  FATAL=true
fi

if $FATAL; then
  exit 1
fi

ok "${BOLD}Done. Start the app with: npm start${RESET}"
exit 0
