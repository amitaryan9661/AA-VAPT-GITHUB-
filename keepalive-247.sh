#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — 24/7 KEEPALIVE (one command, background, self-healing)
#  Start :  bash keepalive-247.sh
#  Stop  :  bash keepalive-247.sh stop
#  Status:  bash keepalive-247.sh status
#  It supervises daemon.sh and restarts any crashed service.
# ════════════════════════════════════════════════════════════════

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${DIR}/logs"
URL="http://localhost:8181/nessus-analyzer.html"
mkdir -p "${LOG_DIR}"
is_wsl(){ grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; }

# Security CLI tools install to ~/go/bin — put it on PATH so the backend finds them.
export PATH="${HOME}/go/bin:/usr/local/go/bin:/snap/bin:${PATH}"

case "${1:-start}" in

  __loop)
    # Internal supervised loop — keeps services alive forever
    while true; do
      bash "${DIR}/daemon.sh" start >> "${LOG_DIR}/keepalive.log" 2>&1
      sleep 30
    done
    ;;

  stop)
    pkill -f "keepalive-247.sh __loop" 2>/dev/null && echo "[+] Keepalive stopped"
    bash "${DIR}/daemon.sh" stop
    ;;

  status)
    if pgrep -f "keepalive-247.sh __loop" >/dev/null 2>&1; then
      echo "[+] Keepalive: RUNNING (auto-restart active)"
    else
      echo "[!] Keepalive: stopped"
    fi
    bash "${DIR}/daemon.sh" status
    ;;

  logs)
    tail -f "${LOG_DIR}/keepalive.log"
    ;;

  start|*)
    # ── FULL BOOTSTRAP: pehli baar — venv + backend Python deps + Ollama install karo ──
    PY="${DIR}/.venv/bin/python3"
    if [ ! -x "$PY" ] || ! "$PY" -c "import fastapi, uvicorn, chromadb" >/dev/null 2>&1; then
      echo "[setup] Pehli baar setup — backend install kar raha hu (venv + Python deps + Ollama). Time lagega, ek baar..."
      if [ -f "${DIR}/install.sh" ]; then
        bash "${DIR}/install.sh" || echo "[setup] ⚠️ install.sh me kuch warning aaye — logs dekho; phir bhi start try kar raha hu."
        PY="${DIR}/.venv/bin/python3"
      else
        echo "[setup] ❌ install.sh nahi mila — backend offline reh sakta hai."
      fi
    fi

    # First-run: ensure ML deps (FP filter + clustering + risk ranking). One-time, fast if already present.
    if [ -x "$PY" ] && ! "$PY" -c "import sklearn, joblib, numpy" >/dev/null 2>&1; then
      echo "[setup] ML libs install kar raha hu (scikit-learn / joblib / numpy)... (ek baar)"
      "${DIR}/.venv/bin/pip" install scikit-learn joblib numpy -q 2>/dev/null \
        && echo "[setup] ✅ ML ready" \
        || echo "[setup] ⚠️ ML deps skip — Risk Ranking + heuristic FP phir bhi chalenge"
    fi

    # First-run: pull recommended AI models in the BACKGROUND (large downloads — non-blocking).
    # Auto model-picker: fast chat = qwen2.5/mistral, reasoning = deepseek-r1. Edit AA_MODELS to change.
    AA_MODELS="${AA_MODELS:-deepseek-r1:1.5b qwen2.5 mistral}"
    if command -v ollama >/dev/null 2>&1 && [ ! -f "${DIR}/.models_pulled" ]; then
      echo "[setup] AI models background me pull ho rahe hain (${AA_MODELS}) — pehli baar GB-size, logs me progress. Tool isi beech chalu rahega."
      (
        for m in ${AA_MODELS}; do
          # tag-aware: exact name match (untagged like "qwen2.5" matches "qwen2.5:latest")
          if ollama list 2>/dev/null | awk '{print $1}' | grep -qiF "$m"; then
            echo "[models] already present, skipping: $m"
          else
            echo "[models] pulling: $m"; ollama pull "$m" || echo "[models] ⚠️ pull fail: $m"
          fi
        done
        touch "${DIR}/.models_pulled"
        echo "[models] ✅ AI models setup done"
      ) >> "${LOG_DIR}/models.log" 2>&1 &
      disown 2>/dev/null || true
    fi

    # First-run: install ALL Attack-Flow pentest tools in the BACKGROUND (non-blocking).
    # subfinder/httpx/naabu/katana/nuclei/dalfox/webanalyze/whatweb/wafw00f/nikto/wappalyzer.
    if [ -f "${DIR}/install-tools.sh" ] && [ ! -f "${DIR}/.tools_installed" ]; then
      echo "[setup] Attack-Flow tools background me install ho rahe hain (subfinder/httpx/nuclei/katana/dalfox/wappalyzer…) — logs: tools.log. Tool isi beech chalu rahega."
      ( bash "${DIR}/install-tools.sh" ) >> "${LOG_DIR}/tools.log" 2>&1 &
      disown 2>/dev/null || true
    fi

    if pgrep -f "keepalive-247.sh __loop" >/dev/null 2>&1; then
      echo "[i] Already running 24/7."
    else
      if command -v setsid >/dev/null 2>&1; then
        setsid bash "${DIR}/keepalive-247.sh" __loop < /dev/null >> "${LOG_DIR}/keepalive.log" 2>&1 &
      else
        nohup bash "${DIR}/keepalive-247.sh" __loop < /dev/null >> "${LOG_DIR}/keepalive.log" 2>&1 &
      fi
      disown 2>/dev/null || true
      echo "[+] AA-VAPT started 24/7 in background (self-healing, survives terminal close)."
      # open the MAIN dashboard once
      if is_wsl; then
        cmd.exe /c start "" "${URL}" 2>/dev/null || true
      else
        xdg-open "${URL}" 2>/dev/null || true
      fi
    fi
    echo "    Open  : ${URL}"
    echo "    Logs  : bash ${DIR}/keepalive-247.sh logs"
    echo "    Models: tail -f ${LOG_DIR}/models.log   (AI model download progress)"
    echo "    Tools : tail -f ${LOG_DIR}/tools.log    (pentest tool install progress)"
    echo "    Stop  : bash ${DIR}/keepalive-247.sh stop"

    # Self-check: confirm the new Attack-Flow API route is live (waits up to ~50s for backend).
    ( for i in $(seq 1 25); do
        if curl -s "http://localhost:8000/api/webapp-pt/tools/available" 2>/dev/null | grep -q '"ok"'; then
          echo "[check] ✅ Attack-Flow API live — 🚀 Run Full Attack ready (hard-refresh the page: Ctrl+Shift+R)."
          exit 0
        fi
        sleep 2
      done
      echo "[check] ⚠️ Attack-Flow API not responding yet — check: tail -n 40 ${LOG_DIR}/backend.log" ) &
    disown 2>/dev/null || true
    ;;
esac
