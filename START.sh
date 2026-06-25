#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
#  AA-VAPT — One command to rule them all
#  Usage:  bash START.sh
#  - First run : installs dependencies, then starts in background
#  - Next runs : just starts (or restarts) in background
#  Tool: http://localhost:8181/nessus-analyzer.html
# ════════════════════════════════════════════════════════════════
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Install only once (marker file keeps subsequent runs instant)
if [ ! -f "${DIR}/.installed" ]; then
  echo -e "${CYAN}[i] First run — installing dependencies...${NC}"
  if [ -f "${DIR}/install.sh" ]; then
    bash "${DIR}/install.sh" && touch "${DIR}/.installed" \
      || echo -e "${YELLOW}[!] install.sh had issues — continuing anyway${NC}"
  fi
fi

# Start everything in the background (survives terminal close)
bash "${DIR}/daemon.sh" restart

echo -e "${GREEN}[+] AA-VAPT is running in the background.${NC}"
echo -e "    Open : ${CYAN}http://localhost:8181/nessus-analyzer.html${NC}"
echo -e "    Stop : bash daemon.sh stop   |   Status: bash daemon.sh status"
