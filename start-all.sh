#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — ALL-IN-ONE LAUNCHER (WebApp PT)
#  Starts: Ollama (AI) + DeepSeek model + FastAPI backend (WebSocket)
#          + Frontend server + opens WebApp PT in the browser
#  Usage:  bash start-all.sh            (full stack with AI)
#          bash start-all.sh --no-ai    (skip Ollama/AI)
# ════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${DIR}/.venv"
TOOL_FILE="nessus-analyzer.html"    # <-- opens MAIN dashboard
FRONT_PORT=8181
BACK_PORT=8000
OLLAMA_MODEL="deepseek-r1:1.5b"
NO_AI=false
BACK_PID=""; FRONT_PID=""; OLLAMA_STARTED=false

for arg in "$@"; do [[ "$arg" == "--no-ai" ]] && NO_AI=true; done

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

cleanup(){
  echo ""
  [[ -n "$BACK_PID"  ]] && kill "$BACK_PID"  2>/dev/null && log "Backend stopped"
  [[ -n "$FRONT_PID" ]] && kill "$FRONT_PID" 2>/dev/null && log "Frontend stopped"
  [[ "$OLLAMA_STARTED" == "true" ]] && pkill -f "ollama serve" 2>/dev/null && log "Ollama stopped"
  echo -e "${CYAN}Goodbye!${NC}"
}
trap cleanup INT TERM EXIT

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   AA-VAPT · WebApp PT · ALL-IN-ONE LAUNCHER   ║"
echo "  ║   Ollama AI · WebSocket · Backend · Frontend  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── free busy ports from a previous run ──────────────────────────
if lsof -i:${FRONT_PORT} -t >/dev/null 2>&1 || fuser ${FRONT_PORT}/tcp >/dev/null 2>&1; then
  warn "Port ${FRONT_PORT} busy — trying to free it"
  fuser -k ${FRONT_PORT}/tcp 2>/dev/null; sleep 1
fi
if lsof -i:${FRONT_PORT} -t >/dev/null 2>&1; then FRONT_PORT=8282; warn "Using ${FRONT_PORT} instead"; fi
URL="http://localhost:${FRONT_PORT}/${TOOL_FILE}"

[[ -f "${DIR}/${TOOL_FILE}" ]] || err "${TOOL_FILE} not found in ${DIR}"
log "Found: ${TOOL_FILE}"
mkdir -p "${DIR}/logs"

# ── resolve python (prefer venv) ─────────────────────────────────
if [[ -f "${VENV_DIR}/bin/python3" ]]; then PYTHON="${VENV_DIR}/bin/python3"; log "Using venv"
elif command -v python3 &>/dev/null; then PYTHON="python3"; warn "No venv — using system python3 (run: bash install.sh)"
else err "python3 not found. Run: bash install.sh"; fi

# ── 1) Ollama (AI model) ─────────────────────────────────────────
if [[ "$NO_AI" != "true" ]] && command -v ollama &>/dev/null; then
  if curl -s http://localhost:11434/api/tags &>/dev/null; then
    log "Ollama already running"
  else
    info "Starting Ollama..."
    ollama serve >> "${DIR}/logs/ollama.log" 2>&1 &
    OLLAMA_STARTED=true
    for i in $(seq 1 10); do sleep 1; curl -s http://localhost:11434/api/tags &>/dev/null && break; done
    curl -s http://localhost:11434/api/tags &>/dev/null && log "Ollama started" || warn "Ollama not responding — AI offline"
  fi
  # ensure the model is available
  if curl -s http://localhost:11434/api/tags &>/dev/null; then
    if ! ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL%%:*}"; then
      info "Pulling AI model ${OLLAMA_MODEL} in background (AI activates when done)..."
      ollama pull "${OLLAMA_MODEL}" >> "${DIR}/logs/ollama.log" 2>&1 &
    else
      log "AI model ${OLLAMA_MODEL} ready"
    fi
  fi
elif [[ "$NO_AI" != "true" ]]; then
  warn "Ollama not installed — AI disabled (install from https://ollama.com)"
fi

# ── 2) FastAPI backend (includes WebSocket /ws) ──────────────────
if [[ "$NO_AI" != "true" ]]; then
  if curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null; then
    log "Backend already running on ${BACK_PORT}"
  else
    info "Starting backend + WebSocket (port ${BACK_PORT})..."
    cd "${DIR}"
    PYTHONPATH="${DIR}" "${PYTHON}" -m uvicorn backend.main:app \
      --host 0.0.0.0 --port "${BACK_PORT}" --log-level warning \
      >> "${DIR}/logs/backend.log" 2>&1 &
    BACK_PID=$!
    READY=false
    for i in $(seq 1 12); do sleep 1; curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null && { READY=true; break; }; done
    if [[ "$READY" == "true" ]]; then log "Backend + WebSocket running (PID ${BACK_PID})"
    else warn "Backend failed — see ${DIR}/logs/backend.log (run: bash install.sh)"; BACK_PID=""; fi
  fi
fi

# ── 3) Frontend static server ────────────────────────────────────
cd "${DIR}"
"${PYTHON}" -m http.server "${FRONT_PORT}" --bind 127.0.0.1 >> "${DIR}/logs/frontend.log" 2>&1 &
FRONT_PID=$!
sleep 1
kill -0 "$FRONT_PID" 2>/dev/null || err "Frontend failed to start"
log "Frontend running (PID ${FRONT_PID}, port ${FRONT_PORT})"

# ── 4) Open browser ──────────────────────────────────────────────
info "Opening: ${URL}"
if is_wsl; then
  cmd.exe /c start "" "${URL}" 2>/dev/null \
  || powershell.exe -NoProfile -Command "Start-Process '${URL}'" 2>/dev/null \
  || warn "Open manually: ${URL}"
else
  xdg-open "${URL}" 2>/dev/null || open "${URL}" 2>/dev/null \
  || firefox "${URL}" 2>/dev/null || google-chrome "${URL}" 2>/dev/null \
  || warn "Open manually: ${URL}"
fi

echo ""
echo -e "${BOLD}${GREEN}  ✅ Everything running${NC}"
echo -e "  ${CYAN}WebApp PT :${NC} ${URL}"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}Backend   :${NC} http://localhost:${BACK_PORT}"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}WebSocket :${NC} ws://localhost:${BACK_PORT}/ws"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}API Docs  :${NC} http://localhost:${BACK_PORT}/docs"
echo ""
echo -e "  ${YELLOW}Ctrl+C to stop everything${NC}"
echo ""
wait "$FRONT_PID" 2>/dev/null || true
