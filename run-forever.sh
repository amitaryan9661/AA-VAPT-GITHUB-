#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — RUN FOREVER (one command = everything, 24/7)
#  • backend + AI(Ollama) + WebSocket + frontend  (sab ek saath)
#  • background me chalta rahe, crash pe auto-restart
#  • GitHub pe naya update aaye to khud pull + restart (auto-update)
#
#  Start :  bash run-forever.sh
#  Stop  :  bash run-forever.sh stop
#  Status:  bash run-forever.sh status
#  Logs  :  bash run-forever.sh logs
# ════════════════════════════════════════════════════════════════

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${DIR}/logs"; mkdir -p "${LOG_DIR}"
URL="http://localhost:8181/nessus-analyzer.html"
CHECK_EVERY=120          # har 120s me services + GitHub update check
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

# Best-effort GitHub auto-update (public repo => no login needed). Safe: ff-only.
auto_update(){
  [ -d "${DIR}/.git" ] || return 0
  git -C "${DIR}" remote get-url origin >/dev/null 2>&1 || return 0
  git -C "${DIR}" fetch --quiet origin 2>/dev/null || return 0
  local LOCAL REMOTE
  LOCAL=$(git -C "${DIR}" rev-parse @ 2>/dev/null)
  REMOTE=$(git -C "${DIR}" rev-parse '@{u}' 2>/dev/null)
  [ -z "$REMOTE" ] && return 0
  if [ "$LOCAL" != "$REMOTE" ]; then
    echo "[update] GitHub pe naya code mila — pulling..."
    git -C "${DIR}" stash --quiet 2>/dev/null
    if git -C "${DIR}" pull --ff-only --quiet 2>/dev/null; then
      git -C "${DIR}" stash pop --quiet 2>/dev/null || true
      echo "[update] Updated -> restarting services"
      bash "${DIR}/daemon.sh" restart >> "${LOG_DIR}/keepalive.log" 2>&1
    else
      git -C "${DIR}" stash pop --quiet 2>/dev/null || true
      echo "[update] Pull skip (local changes/divergent) — services chalte rahenge"
    fi
  fi
}

# First-run setup: jo bhi missing ho (Ollama / Python / backend deps) khud install karta hai
SUDO=""; [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
ensure_setup(){
  # 1) Ollama (AI) — auto install agar nahi hai
  if ! command -v ollama >/dev/null 2>&1; then
    echo "[setup] Ollama install nahi hai — auto-install kar raha hu..."
    curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -2 \
      || echo "[setup] ⚠️ Ollama auto-install fail — net check karo (AI offline rahega, baaki sab chalega)"
  fi

  # 2) Python3 + venv + pip — auto install (apt) agar nahi hai
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[setup] python3 install kar raha hu..."
    $SUDO apt-get update -y >/dev/null 2>&1
    $SUDO apt-get install -y python3 python3-venv python3-pip >/dev/null 2>&1 \
      || echo "[setup] ⚠️ python3 manually install karo"
  fi
  command -v git >/dev/null 2>&1 || $SUDO apt-get install -y git >/dev/null 2>&1
  command -v rsync >/dev/null 2>&1 || $SUDO apt-get install -y rsync >/dev/null 2>&1

  # 3) Backend dependencies / venv — install.sh ya direct pip
  local PY="${DIR}/.venv/bin/python3"
  if [ ! -x "$PY" ] || ! "$PY" -c "import uvicorn, fastapi" >/dev/null 2>&1; then
    echo "[setup] Backend dependencies install kar raha hu (pehli baar — thoda time lagega)..."
    if [ -f "${DIR}/install.sh" ]; then
      bash "${DIR}/install.sh"
    else
      python3 -m venv "${DIR}/.venv" 2>/dev/null
      "${DIR}/.venv/bin/pip" install --upgrade pip >/dev/null 2>&1
      "${DIR}/.venv/bin/pip" install -r "${DIR}/backend/requirements.txt"
    fi
  fi
  # 4) Machine Learning deps (FP filter + clustering + risk ranking) — lightweight, only if missing
  if [ -x "$PY" ] && ! "$PY" -c "import sklearn, joblib, numpy" >/dev/null 2>&1; then
    echo "[setup] ML libs install kar raha hu (scikit-learn / joblib / numpy)..."
    "${DIR}/.venv/bin/pip" install scikit-learn joblib numpy -q 2>/dev/null \
      || echo "[setup] ⚠️ ML deps skip — Risk Ranking + heuristic FP phir bhi chalenge"
  fi
  echo "[setup] ✅ Setup ready"
}

case "${1:-start}" in

  __loop)
    while true; do
      bash "${DIR}/daemon.sh" start >> "${LOG_DIR}/keepalive.log" 2>&1   # keep alive
      auto_update                                                        # auto-update
      sleep "${CHECK_EVERY}"
    done
    ;;

  stop)
    pkill -f "run-forever.sh __loop" 2>/dev/null && echo "[+] Supervisor stopped"
    bash "${DIR}/daemon.sh" stop
    ;;

  status)
    if pgrep -f "run-forever.sh __loop" >/dev/null 2>&1; then echo "[+] 24/7 supervisor: RUNNING (auto-restart + auto-update)"; else echo "[!] supervisor: stopped"; fi
    bash "${DIR}/daemon.sh" status
    ;;

  logs)
    tail -f "${LOG_DIR}/keepalive.log"
    ;;

  start|*)
    if pgrep -f "run-forever.sh __loop" >/dev/null 2>&1; then
      echo "[i] Already running 24/7."
    else
      ensure_setup           # pehli baar deps install (backend ke liye)
      if command -v setsid >/dev/null 2>&1; then
        setsid bash "${DIR}/run-forever.sh" __loop < /dev/null >> "${LOG_DIR}/keepalive.log" 2>&1 &
      else
        nohup bash "${DIR}/run-forever.sh" __loop < /dev/null >> "${LOG_DIR}/keepalive.log" 2>&1 &
      fi
      disown 2>/dev/null || true
      echo "[+] START 24/7: backend + AI + WebSocket + frontend"
      echo "    (background, crash pe auto-restart, GitHub se auto-update)"
      if is_wsl; then cmd.exe /c start "" "${URL}" 2>/dev/null || true; else xdg-open "${URL}" 2>/dev/null || true; fi
    fi
    echo "    Open : ${URL}"
    echo "    Stop : bash ${DIR}/run-forever.sh stop"
    echo "    Logs : bash ${DIR}/run-forever.sh logs"
    ;;
esac
