#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — Attack-Flow TOOL installer (idempotent, background-safe)
#  Installs every tool the "Run Full Attack" flow uses:
#    Recon : subfinder · naabu
#    Tech  : httpx · wappalyzer · webanalyze · whatweb · wafw00f
#    Crawl : katana
#    Vuln  : nuclei (+templates) · dalfox · nikto
#    Extras: jq · anew · gau · waybackurls
#  Already-installed tools are skipped. Safe to run any time.
#  Usage:  bash install-tools.sh
# ════════════════════════════════════════════════════════════════
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${DIR}/logs"; mkdir -p "${LOG_DIR}"
VENV_PIP="${DIR}/.venv/bin/pip"
export GOBIN="${HOME}/go/bin"
export PATH="${HOME}/go/bin:/usr/local/go/bin:/snap/bin:${PATH}"

say(){ echo "[tools] $*"; }

# ── 1. Go toolchain (needed for ProjectDiscovery + dalfox + webanalyze) ──
ensure_go(){
  if command -v go >/dev/null 2>&1; then say "go present: $(go version 2>/dev/null)"; return 0; fi
  say "Go not found — installing (golang-go via apt)…"
  if command -v apt-get >/dev/null 2>&1; then
    sudo -n apt-get update -q 2>/dev/null && sudo -n apt-get install -y golang-go -q 2>/dev/null \
      || say "⚠️ apt install go needs sudo password — install Go manually: https://go.dev/dl/"
  fi
  command -v go >/dev/null 2>&1
}

# ── helper: go install only if the binary is missing ──
gobin(){  # gobin <binary> <module@version>
  local bin="$1" mod="$2"
  if command -v "$bin" >/dev/null 2>&1 || [ -x "${HOME}/go/bin/${bin}" ]; then
    say "✓ already installed: $bin"; return 0
  fi
  if command -v go >/dev/null 2>&1; then
    say "installing $bin …"; GOBIN="${HOME}/go/bin" go install -v "$mod" >/dev/null 2>&1 \
      && say "✅ $bin" || say "⚠️ failed: $bin (check Go version ≥1.21)"
  else
    say "skip $bin — Go missing"
  fi
}

# ── helper: apt install if missing ──
aptbin(){  # aptbin <binary> <pkg>
  local bin="$1" pkg="$2"
  command -v "$bin" >/dev/null 2>&1 && { say "✓ already installed: $bin"; return 0; }
  if command -v apt-get >/dev/null 2>&1; then
    say "installing $bin (apt $pkg) …"
    sudo -n apt-get install -y "$pkg" -q 2>/dev/null && say "✅ $bin" \
      || say "⚠️ $bin needs: sudo apt install $pkg"
  else
    say "skip $bin — no apt"
  fi
}

say "════ AA-VAPT tool install start ($(date '+%F %T')) ════"
ensure_go

# ── 2. ProjectDiscovery + Go tools ──
gobin subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
gobin httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
gobin naabu       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
gobin katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
gobin nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
gobin dalfox      "github.com/hahwul/dalfox/v2@latest"
gobin webanalyze  "github.com/rverton/webanalyze/cmd/webanalyze@latest"
gobin anew        "github.com/tomnomnom/anew@latest"
gobin gau         "github.com/lc/gau/v2/cmd/gau@latest"
gobin waybackurls "github.com/tomnomnom/waybackurls@latest"

# ── 3. apt tools ──
aptbin whatweb whatweb
aptbin nikto   nikto
aptbin jq      jq

# ── 4. wafw00f (pip, prefer project venv) ──
if ! command -v wafw00f >/dev/null 2>&1; then
  say "installing wafw00f (pip) …"
  if [ -x "${VENV_PIP}" ]; then "${VENV_PIP}" install -q wafw00f 2>/dev/null && say "✅ wafw00f (venv)" || say "⚠️ wafw00f pip failed"; fi
  command -v wafw00f >/dev/null 2>&1 || pip install --user -q wafw00f 2>/dev/null && say "✅ wafw00f" || true
else say "✓ already installed: wafw00f"; fi

# ── 5. Wappalyzer (npm, optional — webanalyze is the Go fallback) ──
if ! command -v wappalyzer >/dev/null 2>&1; then
  if command -v npm >/dev/null 2>&1; then
    say "installing wappalyzer (npm -g) …"
    npm install -g wappalyzer >/dev/null 2>&1 && say "✅ wappalyzer" || say "⚠️ wappalyzer npm failed (webanalyze will cover tech-detect)"
  else
    say "npm not present — skipping Wappalyzer (webanalyze handles tech-detect)"
  fi
else say "✓ already installed: wappalyzer"; fi

# ── 6. nuclei templates (first run) ──
if command -v nuclei >/dev/null 2>&1 || [ -x "${HOME}/go/bin/nuclei" ]; then
  say "updating nuclei templates …"
  "${HOME}/go/bin/nuclei" -update-templates -silent >/dev/null 2>&1 \
    || nuclei -update-templates -silent >/dev/null 2>&1 || say "⚠️ nuclei template update skipped"
fi

# ── 7. webanalyze technologies.json (first run) ──
if command -v webanalyze >/dev/null 2>&1 || [ -x "${HOME}/go/bin/webanalyze" ]; then
  ( cd "${DIR}" && { "${HOME}/go/bin/webanalyze" -update >/dev/null 2>&1 || webanalyze -update >/dev/null 2>&1; } ) || true
fi

touch "${DIR}/.tools_installed"
say "════ tool install done ════"
say "Installed binaries live in: ${HOME}/go/bin (added to PATH by keepalive-247.sh)"
