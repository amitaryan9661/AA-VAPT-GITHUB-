#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — ONE COMMAND: install everything + run.
#
#    bash keepalive-247.sh           → install + start (all-in-one)
#    bash keepalive-247.sh stop      → stop
#    bash keepalive-247.sh logs      → live backend logs
#    bash keepalive-247.sh status    → pm2 status
#
#  What it sets up (skips anything already done):
#    • Ollama (AI) + a model           (background download if missing)
#    • Pentest tools (nuclei/httpx/…)  (background, via install-tools.sh)
#    • Python venv + deps + pm2        (daemon.sh)
#    • Backend on :8000 via pm2        (pm2 keeps it alive 24/7)
#
#  NOTE: the old version looped daemon.sh every 30s, which restarted the
#  backend constantly so it never finished loading (AI showed "offline").
#  pm2 already self-heals, so there is NO loop here.
# ════════════════════════════════════════════════════════════════
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="${HOME}/.npm-global/bin:${HOME}/go/bin:/usr/local/go/bin:/snap/bin:${PATH}"
mkdir -p "${DIR}/logs"

case "${1:-start}" in
  start|"")
    echo "════ AA-VAPT — install everything + run ════"

    # 1) Ollama (AI) — install if missing, ensure running, pull a model in background
    if ! command -v ollama >/dev/null 2>&1; then
      echo "[ai] Ollama install (one-time)…"
      curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null || echo "[ai] ⚠️ Ollama install skipped (install manually: https://ollama.com)"
    fi
    if command -v ollama >/dev/null 2>&1; then
      pgrep -x ollama >/dev/null 2>&1 || { nohup ollama serve >/dev/null 2>&1 & sleep 3; }
      if ! ollama list 2>/dev/null | grep -qiE 'deepseek|qwen|mistral|llama'; then
        echo "[ai] no model found — pulling deepseek-r1:1.5b in background (logs/models.log)…"
        nohup ollama pull deepseek-r1:1.5b >> "${DIR}/logs/models.log" 2>&1 &
      else
        echo "[ai] Ollama ready, model present ✓"
      fi
    fi

    # 2) Pentest tools (one-time, background)
    if [ -f "${DIR}/install-tools.sh" ] && [ ! -f "${DIR}/.tools_installed" ]; then
      echo "[tools] installing pentest tools in background (logs/tools.log)…"
      nohup bash "${DIR}/install-tools.sh" >> "${DIR}/logs/tools.log" 2>&1 &
    fi

    # 3) Backend — venv + deps + pm2 + start (daemon.sh does all of this)
    echo "[backend] venv + deps + pm2 + start…"
    bash "${DIR}/daemon.sh"

    echo ""
    echo "[+] AA-VAPT is running — pm2 keeps it alive 24/7 (no restart loop)."
    echo "    Open  : http://localhost:8000/"
    echo "    Logs  : bash ${DIR}/keepalive-247.sh logs   (backend)"
    echo "    Models: tail -f ${DIR}/logs/models.log      (AI download)"
    echo "    Tools : tail -f ${DIR}/logs/tools.log        (tool install)"
    echo "    Stop  : bash ${DIR}/keepalive-247.sh stop"
    ;;

  stop)
    pm2 stop aa-vapt 2>/dev/null
    pm2 delete aa-vapt 2>/dev/null
    lsof -ti:8000 2>/dev/null | xargs -r kill -9 2>/dev/null
    pkill -f "keepalive-247.sh __loop" 2>/dev/null
    echo "[+] AA-VAPT stopped."
    ;;

  restart)
    pm2 restart aa-vapt 2>/dev/null || bash "${DIR}/daemon.sh"
    echo "[+] Restarted."
    ;;

  status)
    pm2 status 2>/dev/null || echo "pm2 not running — start with: bash ${DIR}/keepalive-247.sh"
    ;;

  logs)
    pm2 logs aa-vapt
    ;;

  *)
    echo "Usage: bash ${DIR}/keepalive-247.sh [start|stop|restart|status|logs]"
    ;;
esac
