#!/bin/bash
# AA-VAPT 24/7 Daemon — smart installer, skip if installed
set -e
PROJ="$(cd "$(dirname "$0")" && pwd -P)"  # -P resolves symlinks to real path
cd "$PROJ"
mkdir -p logs

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   AA-VAPT Agent — 24/7 Daemon       ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Symlink trick: eliminate spaces from ALL paths ────────────
# $PROJ contains "Amit Aryan" (space) which breaks venv shebangs,
# pm2 exec, and uvicorn binary. We symlink to a space-free path.
LINK="$HOME/aa-vapt"          # e.g. /home/amit_aryan/aa-vapt — no spaces
ln -sfn "$PROJ" "$LINK"
echo "  Project link: $LINK -> $PROJ"
echo ""

# ── 1. Python venv (built via symlink — no spaces) ────────────
if [ ! -d "$LINK/.venv" ]; then
    echo "[1/4] Creating Python venv..."
    python3 -m venv "$LINK/.venv"
else
    echo "[1/4] Python venv OK — skipping."
fi
source "$LINK/.venv/bin/activate"

# ── 2. Python packages ─────────────────────────────────────────
echo "[2/4] Checking Python packages..."
pip install -r "$LINK/backend/requirements.txt" -q --disable-pip-version-check

# ── 3. pm2 via local npm prefix (no sudo) ─────────────────────
export NPM_GLOBAL="$HOME/.npm-global"
export PATH="$NPM_GLOBAL/bin:$PATH"
mkdir -p "$NPM_GLOBAL"
npm config set prefix "$NPM_GLOBAL" 2>/dev/null || true

if ! command -v pm2 &>/dev/null; then
    echo "[3/4] Installing pm2..."
    npm install -g pm2 -q
else
    echo "[3/4] pm2 OK — skipping."
fi

# ── 4. Kill old process on port 8000 if any ──────────────────
OLD_PID=$(lsof -ti:8000 2>/dev/null || true)
if [ -n "$OLD_PID" ]; then
    echo "[4/4] Killing old process on port 8000 (PID $OLD_PID)..."
    kill -9 $OLD_PID 2>/dev/null || true
    sleep 1
fi

# ── Resolve venv python3 — it's a symlink to system python (no spaces) ──
VENV_PY="$LINK/.venv/bin/python3"

# ── Write ecosystem.config.js — use python3 directly, no wrapper ──
cat > "$LINK/ecosystem.config.js" << EOF
module.exports = {
  apps: [
    {
      name: "aa-vapt",
      script: "$VENV_PY",
      args: "-m uvicorn backend.main:app --host 0.0.0.0 --port 8000",
      interpreter: "none",
      cwd: "$LINK",
      autorestart: true,
      watch: false,
      max_memory_restart: "2G",
      env: {
        PYTHONUNBUFFERED: "1",
        VIRTUAL_ENV: "$LINK/.venv",
        PATH: "$LINK/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      },
      error_file: "$LINK/logs/error.log",
      out_file: "$LINK/logs/out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss"
    }
  ]
}
EOF

# ── Delete old crashed pm2 instance, start fresh ─────────────
pm2 delete aa-vapt 2>/dev/null || true
pm2 start "$LINK/ecosystem.config.js"
pm2 save --force

echo ""
echo "  ✅ AA-VAPT running 24/7 in background!"
echo ""
echo "  Agent UI : http://localhost:8000/agent.html"
echo "  API Docs : http://localhost:8000/docs"
echo ""
echo "  pm2 logs        — live log stream"
echo "  pm2 restart all — restart"
echo "  pm2 stop all    — stop"
echo ""

# ── Wait for server then open browser ────────────────────────
echo "  Waiting for server (first load takes ~2 min — loading AI models)..."
for i in $(seq 1 150); do
    if curl -sf http://localhost:8000/docs > /dev/null 2>&1; then
        echo "  Server ready! Opening browser..."
        cmd.exe /c start http://localhost:8000/agent.html 2>/dev/null || \
        explorer.exe "http://localhost:8000/agent.html" 2>/dev/null || true
        echo "  Done! Browser opened."
        break
    fi
    printf "."
    sleep 1
done
echo ""
