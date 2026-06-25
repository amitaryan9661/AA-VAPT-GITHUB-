#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  ONE-COMMAND GITHUB UPDATER
#  Working folder ke changes -> GitHub clone -> commit -> push
#  Usage:  bash update-github.sh
#          bash update-github.sh "apna commit message"
# ════════════════════════════════════════════════════════════════

# Source = ye script jis folder me hai (tumhara working folder)
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Destination = GitHub Desktop ka repo clone. Khaali chhodo to khud dhoond lega.
DST=""

MSG="${1:-update $(date '+%Y-%m-%d %H:%M')}"

# Auto-detect the AA-VAPT-GITHUB clone if DST not set / wrong
if [ -z "$DST" ] || [ ! -d "$DST/.git" ]; then
  echo "[i] Repo clone dhoond raha hu..."
  for base in "/mnt/c/Users/Amit Aryan/Documents/GitHub" "/mnt/c/Users/Amit Aryan/source/repos" "/mnt/c/Users/Amit Aryan/Desktop" "/mnt/c/Users/Amit Aryan"; do
    cand=$(find "$base" -maxdepth 4 -type d -name "AA-VAPT-GITHUB" 2>/dev/null | while read -r d; do [ -d "$d/.git" ] && { echo "$d"; break; }; done | head -1)
    [ -n "$cand" ] && { DST="$cand"; break; }
  done
fi

if [ -z "$DST" ] || [ ! -d "$DST/.git" ]; then
  echo "❌ AA-VAPT-GITHUB clone nahi mila."
  echo "   WSL me ye chala ke path nikalo:  find /mnt/c/Users -maxdepth 5 -type d -name AA-VAPT-GITHUB 2>/dev/null"
  echo "   Phir is file me DST=\"wo-path\" set kar do."
  exit 1
fi
echo "[i] Repo: $DST"

echo "[1/3] 📂 Files sync kar raha hu (venv/logs/scan-data chhod ke)..."
rsync -a --delete \
  --exclude='.git' --exclude='.venv' --exclude='logs' --exclude='memory' \
  --exclude='__pycache__' --exclude='vapt_results_*.txt' --exclude='.installed' --exclude='.models_pulled' \
  --exclude='*.xml' --exclude='*.bak' --exclude='*.bak2' --exclude='*.docx' \
  --exclude='TAFE-*' --exclude='FABLE_*' \
  "$SRC/" "$DST/"

echo "[2/3] 📝 Commit kar raha hu..."
cd "$DST" || { echo "❌ cd fail"; exit 1; }
git add -A
if git diff --cached --quiet; then
  echo "✅ Koi naya change nahi — kuch karne ki zaroorat nahi."
  exit 0
fi
git commit -m "$MSG"

echo "[3/3] 🚀 GitHub pe push kar raha hu..."
if git push origin HEAD; then
  echo "✅ GitHub update ho gaya!"
else
  echo "⚠️  Push fail hua (shayad pehli baar login/PAT maang raha hai)."
  echo "   Aasan fix: GitHub Desktop kholo → niche 'Push origin' dabao (wo already logged-in hai)."
fi
