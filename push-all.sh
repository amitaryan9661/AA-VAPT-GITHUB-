#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — ONE command: clean commit + push to GitHub.
#  Login is browser-based (GitHub CLI) — NO token copy-paste needed.
#  Run in WSL:  bash push-all.sh
# ════════════════════════════════════════════════════════════════
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"

echo "════════ STEP 1 / 2 — building one clean commit ════════"
bash "$DIR/fresh-upload.sh"

echo ""
echo "════════ STEP 2 / 2 — pushing to GitHub ════════"

# --- ensure GitHub CLI (gh) ---
if ! command -v gh >/dev/null 2>&1; then
  echo "[i] installing GitHub CLI (gh)… (sudo password maang sakta hai)"
  (sudo apt-get update -q && sudo apt-get install -y gh -q) 2>/dev/null \
    || (type -p curl >/dev/null && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
        && echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null \
        && sudo apt-get update -q && sudo apt-get install -y gh -q) 2>/dev/null || true
fi

# --- preferred: gh browser login (no token) ---
if command -v gh >/dev/null 2>&1; then
  if ! gh auth status >/dev/null 2>&1; then
    echo "[i] EK BAAR login — browser khulega, 'Authorize' dabao (token nahi banana)."
    gh auth login --hostname github.com --git-protocol https --web || true
  fi
  gh auth setup-git 2>/dev/null || true
  if git push origin main --force; then
    echo ""; echo "✅ Push ho gaya! GitHub refresh karo — har file abhi ke time pe."
    exit 0
  fi
  echo "[!] gh se push nahi hua — token method try kar rahe hain…"
fi

# --- fallback: save token once, never asked again ---
echo ""
echo "[i] Token method (sirf EK BAAR — phir kabhi nahi poochega):"
echo "    1) Token banao: https://github.com/settings/tokens/new  → 'repo' tick → Generate → copy"
echo "    2) Niche jab pooche:  Username = amitaryan9661   Password = wo token (paste)"
git config --global credential.helper store
git push origin main --force
echo ""
echo "✅ Push ho gaya! GitHub refresh karo — har file abhi ke time pe."
