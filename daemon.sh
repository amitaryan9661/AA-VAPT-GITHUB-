#!/usr/bin/env bash
# AA-VAPT Daemon — 24/7 Background Service Manager
# Usage:
#   bash daemon.sh start     — Start all services in background
#   bash daemon.sh stop      — Stop all services
#   bash daemon.sh restart   — Restart all services
#   bash daemon.sh status    — Show running status
#   bash daemon.sh autostart — Register Windows startup task (WSL only)
#   bash daemon.sh logs      — Tail live logs

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${DIR}/.venv"
LOG_DIR="${DIR}/logs"
PID_FILE="${LOG_DIR}/.daemon_pids"
FRONT_PORT=8181
BACK_PORT=8000
COMMAND="${1:-status}"

mkdir -p "${LOG_DIR}"

# Make CLI security tools (installed to ~/go/bin via go install) visible to the
# uvicorn backend this script launches — so Attack-Flow shutil.which() finds them.
export PATH="${HOME}/go/bin:/usr/local/go/bin:/snap/bin:${PATH}"

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

if [[ -f "${VENV_DIR}/bin/python3" ]]; then
  PYTHON="${VENV_DIR}/bin/python3"
else
  PYTHON="$(command -v python3 || echo '')"
fi

save_pids(){
  { echo "BACK_PID=$1"; echo "FRONT_PID=$2"; echo "OLLAMA_PID=${3:-}"; } > "${PID_FILE}"
}
load_pids(){
  BACK_PID=""; FRONT_PID=""; OLLAMA_PID=""
  [[ -f "${PID_FILE}" ]] && source "${PID_FILE}" 2>/dev/null
}
pid_alive(){ [[ -n "$1" ]] && kill -0 "$1" 2>/dev/null; }

pids_on_port(){
  local port="$1" pids
  pids=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u)
  [[ -z "$pids" ]] && pids=$(fuser "${port}/tcp" 2>/dev/null)
  [[ -z "$pids" ]] && pids=$(lsof -ti "tcp:${port}" 2>/dev/null)
  echo "$pids"
}

do_start(){
  echo -e "${CYAN}"
  echo "  +==========================================+"
  echo "  |  AA-VAPT Daemon - Starting 24/7 Service  |"
  echo "  +==========================================+"
  echo -e "${NC}"

  load_pids
  if pid_alive "$BACK_PID" && pid_alive "$FRONT_PID"; then
    warn "Services already running (Backend PID: $BACK_PID, Frontend PID: $FRONT_PID)"
    do_status; return 0
  fi

  OLLAMA_PID=""
  if command -v ollama &>/dev/null; then
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
      log "Ollama already running"
    else
      info "Starting Ollama..."
      nohup ollama serve >> "${LOG_DIR}/ollama.log" 2>&1 &
      OLLAMA_PID=$!
      sleep 3
      if curl -s http://localhost:11434/api/tags &>/dev/null; then
        log "Ollama started (PID ${OLLAMA_PID})"
        MODEL_COUNT=$(ollama list 2>/dev/null | tail -n +2 | wc -l)
        if [[ "$MODEL_COUNT" -lt 1 ]]; then
          info "No models -- pulling deepseek-r1:7b in background..."
          nohup ollama pull deepseek-r1:7b >> "${LOG_DIR}/ollama.log" 2>&1 &
        fi
      else
        warn "Ollama failed -- AI will be offline"
      fi
    fi
  else
    warn "Ollama not installed -- run bash install.sh"
  fi

  BACK_PID=""
  if curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null; then
    log "Backend already running on :${BACK_PORT}"
    BACK_PID=$(pids_on_port "${BACK_PORT}" | head -1)
  else
    info "Starting FastAPI backend..."
    cd "${DIR}"
    PYTHONPATH="${DIR}" nohup "${PYTHON}" -m uvicorn backend.main:app \
      --host 0.0.0.0 --port "${BACK_PORT}" --log-level warning \
      >> "${LOG_DIR}/backend.log" 2>&1 &
    BACK_PID=$!
    info "Waiting for backend (up to 45s -- model load takes time)..."
    for i in $(seq 1 45); do
      sleep 1
      curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null && break
      [[ $((i % 10)) -eq 0 ]] && info "  still loading... ${i}s"
    done
    if pid_alive "$BACK_PID"; then
      log "Backend running (PID ${BACK_PID}, :${BACK_PORT})"
    else
      err "Backend failed -- check ${LOG_DIR}/backend.log"
      BACK_PID=""
    fi
  fi

  FRONT_PID=""
  if curl -s "http://localhost:${FRONT_PORT}" &>/dev/null; then
    log "Frontend already running on :${FRONT_PORT}"
    FRONT_PID=$(pids_on_port "${FRONT_PORT}" | head -1)
  else
    cd "${DIR}"
    nohup "${PYTHON}" -c "
import http.server, functools
class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control','no-store, no-cache, must-revalidate')
        self.send_header('Pragma','no-cache')
        self.send_header('Expires','0')
        super().end_headers()
    def log_message(self, fmt, *args): pass
port=${FRONT_PORT}
server=http.server.HTTPServer(('127.0.0.1',port),NoCacheHandler)
server.serve_forever()
" >> "${LOG_DIR}/frontend.log" 2>&1 &
    FRONT_PID=$!
    sleep 1
    if pid_alive "$FRONT_PID"; then
      log "Frontend running (PID ${FRONT_PID}, :${FRONT_PORT})"
    else
      err "Frontend failed -- check ${LOG_DIR}/frontend.log"
      FRONT_PID=""
    fi
  fi

  save_pids "$BACK_PID" "$FRONT_PID" "$OLLAMA_PID"

  URL="http://localhost:${FRONT_PORT}/nessus-analyzer.html"
  echo ""
  log "AA-VAPT is running in background 24/7"
  echo -e "  ${CYAN}Frontend :${NC} ${URL}"
  echo -e "  ${CYAN}Backend  :${NC} http://localhost:${BACK_PORT}"
  echo -e "  ${CYAN}Stop     :${NC} bash daemon.sh stop"
  echo ""

  info "Opening browser..."
  if is_wsl; then
    cmd.exe /c start "" "${URL}" 2>/dev/null \
    || powershell.exe -NoProfile -Command "Start-Process '${URL}'" 2>/dev/null \
    || warn "Open manually: ${URL}"
  else
    xdg-open "${URL}" 2>/dev/null || open "${URL}" 2>/dev/null || warn "Open manually: ${URL}"
  fi
}

do_stop(){
  load_pids
  local stopped=false
  pid_alive "$BACK_PID"  && kill "$BACK_PID"  2>/dev/null && log "Backend stopped  (PID $BACK_PID)"  && stopped=true
  pid_alive "$FRONT_PID" && kill "$FRONT_PID" 2>/dev/null && log "Frontend stopped (PID $FRONT_PID)" && stopped=true
  for port in ${BACK_PORT} ${FRONT_PORT}; do
    local pids; pids=$(pids_on_port "${port}")
    [[ -n "$pids" ]] && kill $pids 2>/dev/null && log "Killed process on port ${port}"
  done
  pid_alive "$OLLAMA_PID" && kill "$OLLAMA_PID" 2>/dev/null && log "Ollama stopped (PID $OLLAMA_PID)" && stopped=true
  rm -f "${PID_FILE}"
  [[ "$stopped" == "true" ]] && echo -e "\n${GREEN}All services stopped.${NC}" || warn "No running services found."
}

do_status(){
  load_pids
  echo ""
  echo -e "${BOLD}  AA-VAPT Service Status${NC}"
  echo    "  -------------------------------------"
  if curl -s "http://localhost:${BACK_PORT}/health" &>/dev/null; then
    echo -e "  ${GREEN}*${NC} Backend  -> ${GREEN}RUNNING${NC} :${BACK_PORT} (PID: ${BACK_PID:-?})"
    STATUS=$(curl -s "http://localhost:${BACK_PORT}/api/status" 2>/dev/null)
    if [[ -n "$STATUS" ]]; then
      OL=$(echo "$STATUS" | python3 -c "import sys,json;d=json.load(sys.stdin);print('ONLINE ('+d['ollama'].get('active','?')+')' if d['ollama']['running'] else 'OFFLINE')" 2>/dev/null)
      CH=$(echo "$STATUS" | python3 -c "import sys,json;d=json.load(sys.stdin);print('READY ('+str(d['chromadb']['total'])+' docs)' if d['chromadb']['ready'] else 'OFFLINE')" 2>/dev/null)
      echo -e "  ${GREEN}*${NC} Ollama   -> ${OL:-unknown}"
      echo -e "  ${GREEN}*${NC} ChromaDB -> ${CH:-unknown}"
    fi
  else
    echo -e "  ${RED}*${NC} Backend  -> ${RED}STOPPED${NC}"
  fi
  if curl -s "http://localhost:${FRONT_PORT}" &>/dev/null; then
    echo -e "  ${GREEN}*${NC} Frontend -> ${GREEN}RUNNING${NC} :${FRONT_PORT} (PID: ${FRONT_PID:-?})"
  else
    echo -e "  ${RED}*${NC} Frontend -> ${RED}STOPPED${NC}"
  fi
  if curl -s "http://localhost:11434/api/tags" &>/dev/null; then
    MODELS=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | paste -sd ',' -)
    echo -e "  ${GREEN}*${NC} Ollama   -> ${GREEN}RUNNING${NC} | Models: ${MODELS:-none}"
  else
    echo -e "  ${RED}*${NC} Ollama   -> ${RED}STOPPED${NC}"
  fi
  echo ""
}

do_autostart(){
  if ! is_wsl; then
    warn "Autostart is WSL-only. On native Linux: sudo systemctl enable aa-vapt"
    _create_systemd; return
  fi
  BAT_PATH="/mnt/c/Users/Amit Aryan/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/aavapt.bat"
  WIN_PATH=$(wslpath -w "${DIR}/daemon.sh" 2>/dev/null || echo "${DIR}/daemon.sh")
  printf '@echo off\r\nwsl.exe -e bash "%s" start\r\n' "${WIN_PATH}" > "${BAT_PATH}"
  if [[ -f "${BAT_PATH}" ]]; then
    log "Startup script created in Windows Startup folder!"
    WIN_BAT=$(wslpath -w "${BAT_PATH}" 2>/dev/null || echo "${BAT_PATH}")
    echo -e "${GREEN}[+]${NC} Location: ${WIN_BAT}"
    log "AA-VAPT will auto-start every time Windows boots"
  else
    warn "Startup folder write failed -- trying Task Scheduler..."
    _register_schtask
  fi
}

_register_schtask(){
  local wpath
  wpath=$(wslpath -w "${DIR}/daemon.sh" 2>/dev/null || echo "${DIR}/daemon.sh")
  schtasks.exe /Create /TN "AA-VAPT Nessus Analyzer" /SC ONLOGON /DELAY 0001:00 \
    /TR "\"wsl.exe\" -e bash \"${wpath}\" start" /RL HIGHEST /F 2>/dev/null \
    && log "Task Scheduler: AA-VAPT auto-starts 1 min after login" \
    || { err "Autostart failed. Run manually: bash daemon.sh start"; }
}

_create_systemd(){
  sudo tee /etc/systemd/system/aa-vapt.service > /dev/null << EOF
[Unit]
Description=AA-VAPT Nessus Analyzer
After=network.target
[Service]
Type=forking
User=${USER}
WorkingDirectory=${DIR}
ExecStart=/usr/bin/bash ${DIR}/daemon.sh start
ExecStop=/usr/bin/bash ${DIR}/daemon.sh stop
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload && sudo systemctl enable aa-vapt
  log "Systemd service enabled. Start: sudo systemctl start aa-vapt"
}

do_logs(){
  echo -e "${CYAN}=== Live logs (Ctrl+C to stop) ===${NC}"
  tail -f "${LOG_DIR}/backend.log" "${LOG_DIR}/frontend.log" "${LOG_DIR}/ollama.log" 2>/dev/null \
    || warn "No log files. Start first: bash daemon.sh start"
}

case "$COMMAND" in
  start)     do_start ;;
  stop)      do_stop ;;
  restart)   do_stop; sleep 2; do_start ;;
  status)    do_status ;;
  autostart) do_autostart ;;
  logs)      do_logs ;;
  *)
    echo -e "${BOLD}Usage:${NC}"
    echo "  bash daemon.sh start|stop|restart|status|autostart|logs"
    ;;
esac
