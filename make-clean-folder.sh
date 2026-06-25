#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — build a CLEAN, GitHub-ready copy (no client data, no
#  git history, no venv/logs/backups). Run in WSL:
#       bash make-clean-folder.sh
#  Optional custom destination:
#       bash make-clean-folder.sh /path/to/new-folder
# ════════════════════════════════════════════════════════════════
set -e
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DST="${1:-$(dirname "$SRC")/AA-VAPT-PUBLIC}"

echo "[i] Source : $SRC"
echo "[i] Clean  : $DST"

# remove the earlier broken/truncated attempt + any old target
rm -rf "$(dirname "$SRC")/AA-VAPT-UPLOAD" 2>/dev/null || true
rm -rf "$DST"; mkdir -p "$DST"

echo "[1/3] copying code only (excluding sensitive + junk)…"
rsync -a \
  --exclude='.git' --exclude='.venv' --exclude='venv' --exclude='env' \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' --exclude='*.egg-info' \
  --exclude='logs' --exclude='memory' --exclude='_backups' --exclude='node_modules' \
  --exclude='*.bak' --exclude='*.bak*' --exclude='*.zip' \
  --exclude='TAFE-*' --exclude='FABLE_*' \
  --exclude='vapt_results_*' --exclude='vapt_output' --exclude='poc_organized.zip' \
  --exclude='*.xml' --exclude='*.nessus' --exclude='*-extracted.xml' \
  --exclude='*.docx' --exclude='*.tmp' \
  --exclude='.installed' --exclude='.models_pulled' --exclude='.tools_installed' \
  --exclude='DELETED_FILES_BACKUP_*' \
  --exclude='.idea' --exclude='.vscode' --exclude='.DS_Store' --exclude='Thumbs.db' \
  --exclude='sanitize-git.sh' --exclude='make-clean-folder.sh' \
  "$SRC/" "$DST/"

echo ""
echo "[2/3] SAFETY CHECK — sensitive files in clean copy (must be EMPTY):"
HITS=$(find "$DST" \( -iname 'TAFE-*' -o -iname 'FABLE_*' -o -iname 'vapt_results_*' \
   -o -iname '*.xml' -o -iname '*.nessus' -o -iname '*.docx' -o -iname '*.env' \
   -o -iname '*.pem' -o -iname '*.key' -o -name '.git' \) 2>/dev/null)
if [ -n "$HITS" ]; then echo "🔴 FOUND:"; echo "$HITS"; echo "Aborting."; exit 1; fi
echo "🟢 clean — no sensitive files."

echo ""
echo "[3/3] integrity — key files present + backend syntax:"
for f in webapp-pt.html nessus-analyzer.html backend/main.py \
         backend/webapp_pt/tool_runner.py install-tools.sh keepalive-247.sh daemon.sh .gitignore; do
  if [ -f "$DST/$f" ]; then echo "  OK  $f ($(wc -l < "$DST/$f") lines)"; else echo "  ❌ MISSING $f"; fi
done
python3 -m py_compile "$DST/backend/main.py" "$DST/backend/webapp_pt/tool_runner.py" 2>&1 \
  && echo "  ✅ backend syntax OK" || echo "  ⚠️ backend syntax issue"

echo ""
echo "✅ Clean folder ready: $DST"
echo ""
echo "Upload to a NEW GitHub repo:"
echo "   cd \"$DST\""
echo "   git init && git add -A && git commit -m \"AA-VAPT initial (sanitized)\""
echo "   git branch -M main"
echo "   git remote add origin https://github.com/<your-username>/<new-repo>.git"
echo "   git push -u origin main"
