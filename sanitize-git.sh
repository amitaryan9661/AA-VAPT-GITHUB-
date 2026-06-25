#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — sanitize git, then push the ORIGINAL folder cleanly.
#  Run in WSL:  bash sanitize-git.sh
#  Removes client data + ChromaDB + backup/junk from the commit,
#  keeps only code. Does NOT push (you review, then push).
# ════════════════════════════════════════════════════════════════
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"

echo "[1/5] clearing stale git locks…"
rm -f .git/index.lock .git/HEAD.lock 2>/dev/null || true

echo "[2/5] base = origin/main (the clean, already-pushed state)…"
git fetch origin 2>/dev/null || echo "    (fetch skipped — using local origin/main ref)"
git reset --soft origin/main
git reset >/dev/null 2>&1            # unstage; index now = clean origin tree

echo "[3/5] untracking client data + ChromaDB + backups/junk…"
git rm -r --cached --ignore-unmatch \
  memory _backups \
  TAFE-WEB-extracted.xml FABLE_AUDIT_LOG.md FABLE_MASTER_PROMPT.md \
  vapt_results_20260612_163127.txt vapt_results_20260612_163138.txt \
  >/dev/null 2>&1 || true
# drop any other tracked junk (backup zips / .bak / scan xml / nessus / docx)
git ls-files 2>/dev/null \
  | grep -iE '(^_backups/|^memory/|\.zip$|\.bak([0-9]*|_.*)?$|\.nessus$|-extracted\.xml$|\.docx$|nessus-analyzer\.html\.bak)' \
  | while read -r f; do git rm --cached --ignore-unmatch "$f" >/dev/null 2>&1 || true; done

echo "[4/5] staging only safe files (.gitignore excludes the rest)…"
git add -A

echo ""
echo "[5/5] SAFETY CHECK — sensitive/junk being ADDED to the commit (must be EMPTY):"
if git diff --cached --name-only --diff-filter=AM \
   | grep -iE 'FABLE_|TAFE-|vapt_results_|-extracted\.xml|\.nessus$|memory/chromadb|chroma\.sqlite3|^_backups/|\.zip$|\.env$|\.pem$|\.key$'; then
  echo "🔴 STOP — a sensitive/junk file is staged for ADD. Aborting WITHOUT commit."
  exit 1
fi
echo "🟢 clean — only code is being committed (deletions of memory/junk are expected & good)."
echo ""

git commit -q -m "AA-VAPT V3: WebApp PT Attack Flow + tool runner + launchers (sanitized, no client data)"
echo "✅ Clean commit created (fast-forward on origin/main — no force-push needed)."
echo ""
echo "Review the commit:   git show --stat HEAD"
echo ""
echo "PUSH (auth: GitHub no longer accepts passwords):"
echo "  - Easiest: open GitHub Desktop, it shows this commit, click the Push origin button."
echo "  • CLI with a token — git push origin main"
echo "       username = amitaryan9661   (your GitHub USERNAME, not email)"
echo "       password = a Personal Access Token from github.com/settings/tokens"
echo ""
echo "Your real client data stays safe in _backups/ (gitignored — never uploaded)."
