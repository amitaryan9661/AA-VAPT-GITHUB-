#!/usr/bin/env bash
# ==============================================================
# AA-VAPT :: Install Kali-style pentest toolset into Ubuntu / WSL
# Safe approach: uses Ubuntu's own repos (NO Kali repo mixing, so
# Ubuntu won't break) + the official Rapid7 installer for Metasploit.
# Re-runnable (idempotent) — already-installed tools are skipped.
# ==============================================================
set -uo pipefail

echo "==> [1/4] Updating package lists..."
sudo apt-get update -y

# Tools available straight from Ubuntu (universe) repos
APT_TOOLS=(
  nmap masscan arp-scan netdiscover
  dnsutils dnsrecon whatweb wafw00f
  nikto sqlmap gobuster dirb wfuzz
  hydra john hashcat medusa
  smbclient nbtscan enum4linux
  netcat-openbsd socat proxychains4 tcpdump net-tools
  exploitdb seclists wordlists
  python3-pip pipx git curl wget jq
)

echo "==> [2/4] Installing tools (any not in your repo are skipped)..."
ok=0; skip=0
for t in "${APT_TOOLS[@]}"; do
  if sudo apt-get install -y "$t" >/dev/null 2>&1; then
    echo "    [ok]   $t"; ok=$((ok+1))
  else
    echo "    [skip] $t (not in this repo)"; skip=$((skip+1))
  fi
done
echo "    -> installed/ok: $ok, skipped: $skip"

echo "==> [3/4] pipx tools (smbmap)..."
if command -v pipx >/dev/null 2>&1; then
  pipx ensurepath >/dev/null 2>&1 || true
  pipx install smbmap >/dev/null 2>&1 && echo "    [ok] smbmap" || echo "    [skip] smbmap"
fi

echo "==> [4/4] Metasploit Framework (official Rapid7 installer)..."
if command -v msfconsole >/dev/null 2>&1; then
  echo "    [ok] metasploit already installed"
else
  if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall 2>/dev/null; then
    chmod +x /tmp/msfinstall
    sudo /tmp/msfinstall && echo "    [ok] metasploit" || echo "    [skip] metasploit (run /tmp/msfinstall manually)"
  else
    echo "    [skip] metasploit (could not download installer — check internet)"
  fi
fi

echo ""
echo "============================================================"
echo " DONE. Quick check:"
echo "   nmap --version   |  sqlmap --version  |  searchsploit -h"
echo "   nikto -Version   |  hydra -h          |  msfconsole -q"
echo "   Wordlists: /usr/share/seclists  &  /usr/share/wordlists"
echo "============================================================"
