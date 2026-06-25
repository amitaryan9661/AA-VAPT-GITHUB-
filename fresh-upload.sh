#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — FRESH single-commit upload.
#  Makes the repo ONE clean commit (timestamp = NOW) so every file
#  shows the current time on GitHub. Wipes ALL old history (and with
#  it any old junk / possibly-sensitive backup commits).
#  Run in WSL:  bash fresh-upload.sh
#  It does NOT push — you review, then force-push (command shown).
# ════════════════════════════════════════════════════════════════
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"

echo "[1/4] clearing stale git locks…"
rm -f .git/index.lock .git/HEAD.lock 2>/dev/null || true

echo "[2/4] creating a fresh history (orphan branch, no old commits)…"
git checkout --orphan _fresh_main 2>/dev/null || { git branch -D _fresh_main 2>/dev/null || true; git checkout --orphan _fresh_main; }
git reset >/dev/null 2>&1            # unstage everything
git add -A                          # stage ALL current files; .gitignore drops sensitive + junk

# DEFENSIVE: force-unstage ChromaDB / backups / client data even if .gitignore missed them
git rm -r --cached --ignore-unmatch \
  memory _backups vapt_output \
  TAFE-WEB-extracted.xml FABLE_AUDIT_LOG.md FABLE_MASTER_PROMPT.md >/dev/null 2>&1 || true
git diff --cached --name-only \
  | grep -iE '(^memory/|^_backups/|chroma\.sqlite3|\.bin$|\.zip$|\.bak|\.nessus$|-extracted\.xml$|\.docx$|TAFE-|FABLE_|vapt_results_)' \
  | while read -r f; do git rm --cached --ignore-unmatch "$f" >/dev/null 2>&1 || true; done

echo ""
echo "[3/4] SAFETY CHECK — sensitive/junk staged (must be EMPTY):"
if git diff --cached --name-only \
   | grep -iE 'FABLE_|TAFE-|vapt_results_|-extracted\.xml|\.nessus$|memory/chromadb|chroma\.sqlite3|^_backups/|\.zip$|\.env$|\.pem$|\.key$'; then
  echo "🔴 STOP — a sensitive/junk file is staged. Aborting WITHOUT commit."
  echo "   (fix .gitignore, then re-run)"
  git checkout - 2>/dev/null || true
  exit 1
fi
echo "🟢 clean — only code is staged."

echo ""
echo "[4/4] creating ONE fresh commit (timestamp = now)…"
git commit -q -m "AA-VAPT: WebApp PT Attack Flow + tool runner + launchers (clean upload)"
git branch -M _fresh_main main      # this fresh history becomes 'main'
echo "✅ Done — repo is now ONE clean commit dated now."
echo ""
echo "Files in this commit:   git show --stat HEAD | head -40"
echo ""
echo "PUBLISH (replaces the GitHub history so every file shows the current time):"
echo "  - GitHub Desktop: Repository menu → Push (it will offer a force-push) — easiest, handles login."
echo "  - CLI with a token:   git push origin main --force"
echo "       username = amitaryan9661   (GitHub USERNAME, not email)"
echo "       password = a Personal Access Token (github.com/settings/tokens, 'repo' scope)"
echo ""
echo "Your real client data stays safe in _backups/ (gitignored — never uploaded)."
