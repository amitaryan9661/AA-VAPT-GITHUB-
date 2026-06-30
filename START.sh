#!/bin/bash
echo ""
echo " ========================================"
echo "  AA-VAPT AI Agent - Starting All Services"
echo " ========================================"
echo ""

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# ── Ollama ────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
    if ! pgrep -x ollama &>/dev/null; then
        echo "[1/3] Starting Ollama..."
        ollama serve &>/dev/null &
        sleep 2
        echo "      Ollama started."
    else
        echo "[1/3] Ollama already running."
    fi
else
    echo "[1/3] Ollama not found — AI features limited."
fi

# ── Dependencies ──────────────────────────────────────────────
if [ ! -f ".deps_installed" ]; then
    echo "[2/3] Installing dependencies..."
    pip install -r backend/requirements.txt -q && touch .deps_installed
else
    echo "[2/3] Dependencies OK."
fi

# ── Backend ───────────────────────────────────────────────────
echo "[3/3] Starting backend..."
echo ""
echo "  Agent UI : http://localhost:8000/agent.html"
echo "  Main UI  : http://localhost:8000/index.html"
echo "  API Docs : http://localhost:8000/docs"
echo ""
echo "  Ctrl+C to stop."
echo " ========================================"
echo ""

python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
