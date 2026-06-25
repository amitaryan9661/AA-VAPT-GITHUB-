#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  AA-VAPT Nessus Analyzer — One-Command Installer
#  Installs: venv + Python deps, Ollama, DeepSeek, ChromaDB
#  Usage: bash install.sh
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${DIR}/.venv"

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
step() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   AA-VAPT Nessus Analyzer — Installer v2.0      ║"
echo "  ║   Ollama + DeepSeek/Gemma + ChromaDB + MCP      ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Python 3 ──────────────────────────────────────────
step "Python 3 + venv"
if ! command -v python3 &>/dev/null; then
  warn "Installing python3..."
  sudo apt-get update -q && sudo apt-get install -y python3 python3-venv python3-full -q
fi
log "Python: $(python3 --version)"

# Ensure venv module available
if ! python3 -c "import venv" 2>/dev/null; then
  info "Installing python3-venv..."
  sudo apt-get install -y python3-venv python3-full -q
fi

# ── Step 2: Create virtual environment ────────────────────────
step "Virtual Environment"
if [[ -d "${VENV_DIR}" ]]; then
  log "venv already exists at ${VENV_DIR}"
else
  info "Creating venv at ${VENV_DIR}..."
  python3 -m venv "${VENV_DIR}"
  log "venv created"
fi

# Activate
source "${VENV_DIR}/bin/activate"
log "venv activated: $(which python3)"

# Upgrade pip inside venv
python3 -m pip install --upgrade pip -q
log "pip: $(pip --version)"

# ── Step 3: Python dependencies ───────────────────────────────
step "Python Dependencies"
info "Installing: fastapi, uvicorn, ollama, chromadb, sentence-transformers..."

# Install with relaxed constraints for Python 3.14 compatibility
pip install \
  "fastapi>=0.110.0" \
  "uvicorn[standard]>=0.29.0" \
  "websockets>=12.0" \
  "pydantic>=2.0.0" \
  "python-multipart>=0.0.9" \
  "aiofiles>=23.0.0" \
  -q

log "Core FastAPI stack installed"

# Install ollama client
pip install "ollama>=0.2.0" -q
log "Ollama client installed"

# ChromaDB (may take a moment)
info "Installing ChromaDB (this may take 2-3 minutes)..."
pip install "chromadb>=0.5.0" -q
log "ChromaDB installed"

# sentence-transformers
info "Installing sentence-transformers..."
pip install "sentence-transformers>=2.7.0" -q
log "sentence-transformers installed"

# graphifyy — knowledge graph builder (71.5x token reduction)
info "Installing graphifyy (knowledge graph for VAPT findings)..."
pip install "graphifyy>=0.1.0" -q && graphify install 2>/dev/null || warn "graphify install step skipped (Claude Code not required)"
log "graphifyy installed"

# Machine Learning — FP filter + clustering + risk ranking
info "Installing scikit-learn, joblib, numpy (ML engine)..."
pip install "scikit-learn>=1.3.0" "joblib>=1.3.0" "numpy>=1.24.0" -q \
  && log "ML stack installed" \
  || warn "ML deps skipped — Risk Ranking + heuristic FP still work without them"

# ── Step 4: Ollama ────────────────────────────────────────────
step "Ollama"
if command -v ollama &>/dev/null; then
  log "Ollama already installed: $(ollama --version 2>/dev/null | head -1)"
else
  info "Installing Ollama..."
  if is_wsl; then
    warn "WSL detected — installing Ollama in Linux/WSL (CPU mode)"
    warn "For GPU acceleration, install Ollama on Windows: https://ollama.com/download"
    # BUG FIX: read -p fails silently when stdin is not a TTY (e.g. curl | bash).
    # In non-interactive mode, default to installing (Y) rather than erroring out.
    if [[ -t 0 ]]; then
      read -r -p "Install Ollama in WSL now? [Y/n]: " choice
    else
      warn "Non-interactive mode — defaulting to install Ollama"
      choice="y"
    fi
    if [[ "${choice,,}" == "n" ]]; then
      warn "Skipping Ollama — AI offline without it"
    else
      curl -fsSL https://ollama.com/install.sh | sh
      log "Ollama installed"
    fi
  else
    curl -fsSL https://ollama.com/install.sh | sh
    log "Ollama installed"
  fi
fi

# ── Step 5: Pull DeepSeek model ───────────────────────────────
step "AI Model"
if command -v ollama &>/dev/null; then
  # Start ollama if not running
  # BUG FIX: removed redundant 2>&1 after &>/dev/null
  if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    info "Starting Ollama service..."
    ollama serve &>/dev/null &
    sleep 4
  fi

  # BUG FIX: with set -e, grep returning 1 (no match) would exit the script.
  # Use || true so a no-match is handled gracefully inside the if-condition check.
  if ollama list 2>/dev/null | grep -qE "deepseek|gemma|llama" 2>/dev/null || false; then
    log "Model already available:"
    # grep -E may return 1 here too if somehow no match, protect with || true
    ollama list | grep -E "deepseek|gemma|llama" 2>/dev/null | head -3 || true
  else
    # Check free disk space
    FREE_GB=$(df -BG "${DIR}" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}')
    if [[ "${FREE_GB:-0}" -ge 5 ]]; then
      info "Pulling deepseek-r1:7b (~4.7GB, best quality)..."
      ollama pull deepseek-r1:7b
    else
      info "Low disk space (${FREE_GB:-?}GB) — pulling deepseek-r1:1.5b (~1GB, fast)..."
      ollama pull deepseek-r1:1.5b
    fi
    log "Model ready"
  fi
else
  warn "Ollama not installed — run.sh will start in offline mode"
fi

# ── Step 6: Setup dirs ────────────────────────────────────────
step "Directories"
mkdir -p "${DIR}/memory/chromadb" "${DIR}/logs"
touch "${DIR}/backend/__init__.py" "${DIR}/backend/ai/__init__.py" "${DIR}/backend/soar/__init__.py"
log "Directories ready"

# ── Step 7: Test imports ──────────────────────────────────────
step "Verification"
cd "${DIR}"
source "${VENV_DIR}/bin/activate"
python3 -c "
import sys
sys.path.insert(0,'.')
errors = []
for mod, name in [
    ('fastapi','FastAPI'),('uvicorn','Uvicorn'),
    ('ollama','Ollama client'),('chromadb','ChromaDB'),
]:
    try: __import__(mod); print(f'  OK  {name}')
    except ImportError as e: print(f'  FAIL {name}: {e}'); errors.append(name)
if errors: print(f'Missing: {errors}'); sys.exit(1)
else: print('  All imports OK')
"

# ─�