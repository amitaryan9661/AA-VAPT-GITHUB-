#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  demon.sh — AA-VAPT Full Setup + Daemon Manager
#  Usage: bash demon.sh [start|stop|restart|status|logs|setup|install]
#  - setup/install : install ALL dependencies + start
#  - start         : start backend (auto-install if missing)
#  - stop          : stop backend
#  - restart       : stop + start
#  - status        : show if running + last logs
#  - logs          : live log tail
# ═══════════════════════════════════════════════════════════════

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$DIR/logs/backend.log"
PID_FILE="/tmp/vapt.pid"
PORT=8000
VENV="$DIR/.venv"
PYTHON="$VENV/bin/python3"
UVICORN="$VENV/bin/uvicorn"
# Resolve real Python binary (venv symlink may break in nohup/setsid on WSL /mnt/c/)
PYTHON_REAL="$(readlink -f "$PYTHON" 2>/dev/null || which python3)"
# Venv site-packages path for PYTHONPATH (so system python finds venv packages)
PYVER="$("$PYTHON_REAL" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3.10")"
SITE_PKGS="$VENV/lib/python${PYVER}/site-packages"
OLLAMA_MODEL="mistral:latest"

# ── Colors ──────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
skip() { echo -e "${CYAN}⏭  $* (already done)${NC}"; }
info() { echo -e "${YELLOW}⚡ $*${NC}"; }
fail() { echo -e "${RED}❌ $*${NC}"; }

# ── Open browser (works from WSL → Windows) ─────────────────────
_open_browser() {
    local url="$1"
    # WSL: use Windows explorer/cmd to open browser
    if grep -qi microsoft /proc/version 2>/dev/null; then
        cmd.exe /c start "" "$url" 2>/dev/null || \
        powershell.exe -Command "Start-Process '$url'" 2>/dev/null || \
        explorer.exe "$url" 2>/dev/null || true
    # Native Linux
    elif command -v xdg-open > /dev/null 2>&1; then
        xdg-open "$url" 2>/dev/null &
    elif command -v sensible-browser > /dev/null 2>&1; then
        sensible-browser "$url" 2>/dev/null &
    fi
    ok "Opening → $url"
}

# ── Kill whatever is on the port ────────────────────────────────
_kill_port() {
    local pids i
    pids=$(lsof -ti:$PORT 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill -15 $pids 2>/dev/null || true
        sleep 1
        # Force-kill any survivors
        pids=$(lsof -ti:$PORT 2>/dev/null || true)
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    # Wait up to 8 seconds for port to actually be released
    for i in 1 2 3 4 5 6 7 8; do
        lsof -ti:$PORT > /dev/null 2>&1 || return 0
        sleep 1
    done
    echo "Warning: port $PORT still busy after 8s" >&2
}

# ── Check if server is running ──────────────────────────────────
_is_running() {
    lsof -ti:$PORT > /dev/null 2>&1
}

# ═══════════════════════════════════════════════════════════════
#  SETUP — install everything
# ═══════════════════════════════════════════════════════════════
setup() {
    echo -e "\n${BOLD}${CYAN}═══ AA-VAPT Setup ═══${NC}\n"
    cd "$DIR"

    # ── 1. System packages (Kali tools) ──────────────────────
    info "Checking Kali security tools..."
    TOOLS_NEEDED=""
    for tool in nmap nikto curl wget; do
        command -v "$tool" > /dev/null 2>&1 || TOOLS_NEEDED="$TOOLS_NEEDED $tool"
    done
    if [ -n "$TOOLS_NEEDED" ]; then
        info "Installing:$TOOLS_NEEDED"
        sudo apt-get install -y $TOOLS_NEEDED -q 2>/dev/null || \
            fail "apt install failed — run: sudo apt install$TOOLS_NEEDED"
    else
        skip "Core tools (nmap nikto curl) already installed"
    fi

    # Optional tools — don't fail if missing
    for tool in ffuf hydra sqlmap nuclei testssl ssh-audit smbclient; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            sudo apt-get install -y "$tool" -q 2>/dev/null || true
        fi
    done

    # ── 2. Python venv ──────────────────────────────────────
    if [ ! -f "$VENV/bin/activate" ]; then
        info "Creating Python virtual environment..."
        python3 -m venv "$VENV"
        ok "venv created"
    else
        skip "Python venv exists"
    fi

    # ── 3. Python packages ──────────────────────────────────
    info "Installing Python packages..."
    "$VENV/bin/pip" install -q --upgrade pip 2>/dev/null
    PKGS="fastapi uvicorn[standard] ollama httpx chromadb pydantic python-dotenv websockets aiohttp requests slowapi"
    for pkg in $PKGS; do
        pkg_name="${pkg%%[*}"     # strip [standard] etc.
        if "$VENV/bin/pip" show "$pkg_name" > /dev/null 2>&1; then
            skip "  $pkg_name"
        else
            info "  Installing $pkg..."
            "$VENV/bin/pip" install -q "$pkg" || fail "Failed to install $pkg"
            ok "  $pkg installed"
        fi
    done

    # ── 4. Ollama ────────────────────────────────────────────
    if ! command -v ollama > /dev/null 2>&1; then
        info "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        ok "Ollama installed"
    else
        skip "Ollama already installed ($(ollama --version 2>/dev/null | head -1))"
    fi

    # ── 5. Start Ollama serve (if not running) ───────────────
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        info "Starting Ollama server..."
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        disown $!
        sleep 3
        ok "Ollama server started"
    else
        skip "Ollama server already running"
    fi

    # ── 6. Pull LLM model ────────────────────────────────────
    if ollama list 2>/dev/null | grep -q "llama3.2"; then
        skip "llama3.2:3b already pulled"
    elif ollama list 2>/dev/null | grep -q "mistral"; then
        skip "mistral model already pulled"
    else
        info "Pulling $OLLAMA_MODEL (~4GB, may take a while)..."
        ollama pull llama3.2:3b || ollama pull mistral:latest || \
            fail "Model pull failed — run: ollama pull mistral:latest"
        ok "Model pulled"
    fi

    echo ""
    ok "Setup complete!"
    echo ""

    # ── 7. Start the backend ─────────────────────────────────
    start
}

# ═══════════════════════════════════════════════════════════════
#  START — run backend, survive terminal close
# ═══════════════════════════════════════════════════════════════
start() {
    cd "$DIR"

    if _is_running; then
        ok "Already running on http://127.0.0.1:$PORT"
        return
    fi

    # Auto-check venv
    if [ ! -f "$UVICORN" ]; then
        fail "Python env missing. Run: bash demon.sh setup"
        exit 1
    fi

    # Ensure Ollama is up
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        info "Starting Ollama..."
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        disown $!
        sleep 2
    fi

    _kill_port

    info "Starting AA-VAPT backend..."

    # Activate venv inside bash -c so python3 and packages are correct.
    # This bypasses the broken uvicorn shebang on WSL /mnt/c/ mounts.
    nohup bash -c "
        source '$VENV/bin/activate'
        cd '$DIR'
        exec python3 -m uvicorn backend.main:app \
            --host 0.0.0.0 \
            --port $PORT \
            --reload
    " > "$LOG" 2>&1 &

    echo $! > "$PID_FILE"
    disown $!

    # Wait for startup — ChromaDB + sentence-transformers can take ~60s on first load
    local waited=0
    echo -n "  Waiting for startup"
    while ! _is_running && [ $waited -lt 90 ]; do
        sleep 2
        waited=$((waited+2))
        echo -n "."
    done
    echo ""

    if _is_running; then
        ok "Backend started → http://127.0.0.1:$PORT"
        echo ""
        _open_browser "http://localhost:$PORT/nessus-analyzer.html"
        echo -e "  ${BOLD}Logs:${NC} bash demon.sh logs"
        echo ""
    else
        fail "Failed to start. Last log lines:"
        tail -n 20 "$LOG" 2>/dev/null | sed 's/^/  /'
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════
#  STOP
# ═══════════════════════════════════════════════════════════════
stop() {
    _kill_port
    ok "Stopped"
}

# ═══════════════════════════════════════════════════════════════
#  STATUS
# ═══════════════════════════════════════════════════════════════
status() {
    echo ""
    if _is_running; then
        ok "Running → http://127.0.0.1:$PORT/webapp-pt.html"
        echo ""
        echo "── Last 5 log lines ──"
        tail -5 "$LOG" 2>/dev/null || echo "(no logs yet)"
    else
        fail "Not running   →  bash demon.sh start"
    fi

    echo ""
    echo "── Ollama ──"
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        ok "Ollama running"
        ollama list 2>/dev/null | head -5
    else
        fail "Ollama not running → run: ollama serve"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════
#  LOGS — live tail
# ═══════════════════════════════════════════════════════════════
logs() {
    echo -e "${CYAN}── Live logs (Ctrl+C to exit) ──${NC}"
    tail -f "$LOG" 2>/dev/null || echo "No log file yet. Start the server first."
}

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
case "${1:-start}" in
    setup|install) setup ;;
    start)         start ;;
    stop)          stop ;;
    restart)       stop; start ;;
    status)        status ;;
    logs)          logs ;;
    *)
        echo "Usage: bash demon.sh [setup|start|stop|restart|status|logs]"
        echo ""
        echo "  setup    — Install everything + start (first time)"
        echo "  start    — Start backend in background"
        echo "  stop     — Stop backend"
        echo "  restart  — Restart backend"
        echo "  status   — Show running status + last logs"
        echo "  logs     — Live log tail"
        ;;
esac
