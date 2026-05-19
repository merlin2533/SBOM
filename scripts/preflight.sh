#!/usr/bin/env bash
# preflight.sh — verify deployment readiness without changing anything.
# Prints ✓/✗ for each check; exits 0 only when all required checks pass.
set -uo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
  BOLD=$(tput bold); RESET=$(tput sgr0)
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

PASS=0   # count of required failures
WARNS=0  # advisory warnings (never fail)

req_ok()  { echo "${GREEN}✓${RESET} [required] $*"; }
req_fail(){ echo "${RED}✗${RESET} [required] $*"; PASS=$((PASS + 1)); }
adv_ok()  { echo "${GREEN}✓${RESET} [advisory] $*"; }
adv_warn(){ echo "${YELLOW}!${RESET} [advisory] $*"; WARNS=$((WARNS + 1)); }

version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

echo "${BOLD}═══════════════════ SBOM Upload App — Preflight Check ════════════════════${RESET}"
echo ""

# ── 1. Node ≥ 20 ──────────────────────────────────────────────────────────────
if command -v node >/dev/null 2>&1; then
  NODE_VER=$(node --version | sed 's/^v//')
  if version_ge "$NODE_VER" "20"; then
    req_ok "node v${NODE_VER}"
  else
    req_fail "node v${NODE_VER} — need ≥ 20"
  fi
else
  req_fail "node not found — install Node.js ≥ 20"
fi

# ── 2. extract-sbom binary ────────────────────────────────────────────────────
SBOM_BIN=""
if [ -n "${EXTRACT_SBOM_BIN:-}" ]; then
  if [ -x "${EXTRACT_SBOM_BIN}" ]; then
    SBOM_BIN="$EXTRACT_SBOM_BIN"
    req_ok "extract-sbom found via \$EXTRACT_SBOM_BIN: $SBOM_BIN"
  else
    req_fail "EXTRACT_SBOM_BIN is set to '${EXTRACT_SBOM_BIN}' but file is not executable/missing"
  fi
elif [ -x "$REPO_ROOT/bin/extract-sbom" ]; then
  SBOM_BIN="$REPO_ROOT/bin/extract-sbom"
  req_ok "extract-sbom found at repo bin/: $SBOM_BIN"
elif command -v extract-sbom >/dev/null 2>&1; then
  SBOM_BIN=$(command -v extract-sbom)
  req_ok "extract-sbom found on PATH: $SBOM_BIN"
else
  req_fail "extract-sbom not found — run ./scripts/install.sh or set EXTRACT_SBOM_BIN"
fi

# ── 3. bwrap (optional) ───────────────────────────────────────────────────────
if command -v bwrap >/dev/null 2>&1; then
  adv_ok "bwrap (bubblewrap) available: $(command -v bwrap)"
else
  adv_warn "bwrap not found — sandboxing disabled. Set SANDBOX_MODE=none or pass --unsafe via EXTRACT_SBOM_ARGS to suppress errors."
fi

# ── 4. firejail (optional) ────────────────────────────────────────────────────
if command -v firejail >/dev/null 2>&1; then
  adv_ok "firejail available: $(command -v firejail)"
else
  adv_warn "firejail not found (optional alternative sandbox)"
fi

# ── 5. syft (advisory) ────────────────────────────────────────────────────────
if command -v syft >/dev/null 2>&1; then
  adv_ok "syft available: $(command -v syft)"
else
  adv_warn "syft not found — extract-sbom needs syft at runtime to produce SBOMs"
fi

# ── 6. grype (advisory) ───────────────────────────────────────────────────────
if command -v grype >/dev/null 2>&1; then
  adv_ok "grype available: $(command -v grype)"
else
  adv_warn "grype not found — vulnerability scanning will be unavailable"
fi

# ── 6a. trivy (advisory) ──────────────────────────────────────────────────────
if command -v trivy >/dev/null 2>&1; then
  adv_ok "trivy available: $(command -v trivy)"
else
  adv_warn "trivy not found — supplemental CVE scanning with trivy will be unavailable"
fi

# ── 6b. osv-scanner (advisory) ────────────────────────────────────────────────
if command -v osv-scanner >/dev/null 2>&1; then
  adv_ok "osv-scanner available: $(command -v osv-scanner)"
else
  adv_warn "osv-scanner not found — OSV-based CVE/MAL scanning will be unavailable"
fi

# ── 6c. gitleaks (advisory) ───────────────────────────────────────────────────
if command -v gitleaks >/dev/null 2>&1; then
  adv_ok "gitleaks available: $(command -v gitleaks)"
else
  adv_warn "gitleaks not found — secret scanning will be unavailable"
fi

# ── 6d. cve-bin-tool (advisory) ───────────────────────────────────────────────
if command -v cve-bin-tool >/dev/null 2>&1; then
  adv_ok "cve-bin-tool available: $(command -v cve-bin-tool)"
else
  adv_warn "cve-bin-tool not found — binary CVE analysis will be unavailable"
fi

# ── 7. Scratch dir writable ───────────────────────────────────────────────────
SCRATCH="${SCRATCH_DIR:-/tmp/sbom-upload-app}"
mkdir -p "$SCRATCH" 2>/dev/null || true
PROBE="$SCRATCH/.preflight-probe-$$"
if touch "$PROBE" 2>/dev/null; then
  rm -f "$PROBE"
  req_ok "scratch dir writable: $SCRATCH"
else
  req_fail "scratch dir not writable: $SCRATCH"
fi

# ── 8. Frontend built ─────────────────────────────────────────────────────────
if [ -f "$REPO_ROOT/public/dist/app.js" ]; then
  req_ok "public/dist/app.js exists (frontend built)"
else
  req_fail "public/dist/app.js missing — run npm run build:frontend (or ./scripts/install.sh)"
fi

# ── 9. tus vendored ───────────────────────────────────────────────────────────
if [ -f "$REPO_ROOT/public/vendor/tus.min.js" ]; then
  req_ok "public/vendor/tus.min.js exists (tus vendored)"
else
  req_fail "public/vendor/tus.min.js missing — run npm run vendor:tus (or ./scripts/install.sh)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}──────────────────────────────────────────────────────────────────────────${RESET}"
if [ $PASS -eq 0 ]; then
  echo "${GREEN}${BOLD}All required checks passed.${RESET}${GREEN} ($WARNS advisory warning(s))${RESET}"
  echo "Run: npm start"
  exit 0
else
  echo "${RED}${BOLD}${PASS} required check(s) failed.${RESET} Fix the issues above before starting."
  exit 1
fi
