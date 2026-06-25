#!/usr/bin/env bash
# AA-VAPT Nessus Analyzer — One-Command Launcher
# Usage: bash run.sh [--no-ai]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${DIR}/.venv"
TOOL_FILE="nessus-analyzer.html"
FRONT_PORT=8181
BACK_PORT=8000
NO_AI=false
BACK_PID=""; FRONT_PID=""; OLLAMA_STARTED=false

for arg in "$@"; do [[ "$arg" == "--no-ai" ]] && NO_AI=true; done
URL="http://localhost:${FRONT_PORT}/${TOOL_FILE}"

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
# BUG FIX: err() now exits — previously it only echoed, leaving PYTHON unset
# and causing cryptic "command not found" errors later in the script
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

cleanup(){
  echo ""
  [[ -n "$BACK_PID" ]]  && kill "$BACK_PID"  2>/dev/null && log "Backend stopped"
  [[ -n "$FRONT_PID" ]] && kill "$FRONT_PID" 2>/dev/null && log "Frontend stopped"
  [[ "$OLLAMA_STARTED" == "true" ]] && pkill -f "ollama serve" 2>/dev/null && log "Ollama stopped"
  echo -e "${CYAN}Goodbye!${NC}"
}
trap cleanup INT TERM EXIT

# Auto-fallback if frontend port is busy (logging functions are defined above)
if lsof -i:${FRONT_PORT} -t >/dev/null 2>&1 || fuser ${FRONT_PORT}/tcp >/dev/null 2>&1; then
  FRONT_PORT=8282
  warn "Port 8181 busy — using ${FRONT_PORT}"
  URL="http://localhost:${FRONT_PORT}/${TOOL_FILE}"
fi

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  AA-VAPT | Nessus Analyzer + AI          ║"
echo "  ║  DeepSeek · Gemma · ChromaDB · MCP       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

[[ -f "${DIR}/${TOOL_FILE}" ]] || { err "${TOOL_FILE} not found"; }
log "Found: ${TOOL_FILE}"
mkdir -p "${DIR}/logs"

# Resolve python — prefer venv
if [[ -f "${VENV_DIR}/bin/python3" ]]; then
  PYTHON="${VENV_DIR}/bin/python3"
  log "Using venv: ${VENV_DIR}"
elif command -v python3 &>/dev/null; then
  PYTHON="python3"
  warn "No venv found — using system python3 (run bash install.sh for full setup)"
else
  # err() now exits, so PYTHON will never be empty/unset after this block
  err "python3 not found. Run: bash install.sh"
fi

# Start Ollama
# BUG FIX: removed redundant 2>&1 after &>/dev/null (already redirects both streams)
if [[ "$NO_AI" != "true" ]] && command -v ollama &>/dev/null; then
  if curl -s http://localhost:11434/api/tags &>/dev/null; then
    log "Ollama already running"
  else
    info "Starting Ollama..."
    ollama serve >> "${DIR}/logs/ollama.log" 2>&1 &
    OLLAMA_STARTED=true
    sleep 3
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
      log "Ollama started"
      MODEL_COUNT=$(ollama list 2>/dev/null | tail -n +2 | wc -l)
      if [[ "$MODEL_COUNT" -lt 1 ]]; then
        info "No models — pulling deepseek-r1:1.5b in background..."
        ollama pull deepseek-r1:1.5b >> "${DIR}/logs/ollama.log" 2>&1 &
        info "Model downloading — AI activates in a few minutes"
      fi
    else
      warn "Ollama failed to start — AI offline"
    fi
  fi
elif [[ "$NO_AI" != "true" ]]; then
  warn "Ollama not installed. Run: bash install.sh"
fi

# Start FastAPI backend
if [[ "$NO_AI" != "true" ]]; then
  if curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null; then
    log "Backend already running on port ${BACK_PORT}"
  else
    info "Starting FastAPI backend (port ${BACK_PORT})..."
    cd "${DIR}"
    PYTHONPATH="${DIR}" "${PYTHON}" -m uvicorn backend.main:app \
      --host 0.0.0.0 --port "${BACK_PORT}" --log-level warning \
      >> "${DIR}/logs/backend.log" 2>&1 &
    BACK_PID=$!
    # BUG FIX: use actual HTTP health check instead of kill -0 (process-alive check).
    # kill -0 returns true even if uvicorn is still binding or about to crash.
    # Retry HTTP /health up to 10 times (10s total) for a reliable readiness signal.
    READY=false
    for i in $(seq 1 10); do
      sleep 1
      if curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null; then
        READY=true; break
      fi
    done
    if [[ "$READY" == "true" ]]; then
      log "Backend running (PID ${BACK_PID}, port ${BACK_PORT})"
    else
      warn "Backend failed — check ${DIR}/logs/backend.log"
      warn "Run: bash install.sh  to install dependencies"
      BACK_PID=""
    fi
  fi
fi

# Start frontend
cd "${DIR}"
"${PYTHON}" -m http.server "${FRONT_PORT}" --bind 127.0.0.1 \
  >> "${DIR}/logs/frontend.log" 2>&1 &
FRONT_PID=$!
sleep 1
kill -0 "$FRONT_PID" 2>/dev/null || { err "Frontend failed to start"; }
log "Frontend running (PID ${FRONT_PID}, port ${FRONT_PORT})"

# Open browser
info "Opening: ${URL}"
if is_wsl; then
  cmd.exe /c start "" "${URL}" 2>/dev/null \
  || powershell.exe -NoProfile -Command "Start-Process '${URL}'" 2>/dev/null \
  || warn "Open manually: ${URL}"
else
  xdg-open "${URL}" 2>/dev/null \
  || open "${URL}" 2>/dev/null \
  || firefox "${URL}" 2>/dev/null \
  || chromium-browser "${URL}" 2>/dev/null \
  || google-chrome "${URL}" 2>/dev/null \
  || warn "Open manually: ${URL}"
fi

echo ""
echo -e "${BOLD}${GREEN}  Done! AA-VAPT Nessus Analyzer is running${NC}"
echo ""
echo -e "  ${CYAN}Frontend :${NC} ${URL}"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}Backend  :${NC} http://localhost:${BACK_PORT}"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}API Docs :${NC} http://localhost:${BACK_PORT}/docs"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}MCP      :${NC} http://localhost:${BACK_PORT}/mcp"
[[ -n "$BACK_PID" ]] && echo -e "  ${CYAN}Status   :${NC} http://localhost:${BACK_PORT}/api/status"
echo ""
echo -e "  ${YELLOW}Ctrl+C to stop all services${NC}"
echo ""

wait "$FRONT_PID" 2>/dev/null || true
