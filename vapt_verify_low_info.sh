#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  AA-VAPT — Low & Info Level Vulnerability Verifier
#  Usage: bash vapt_verify_low_info.sh -t <target> [-f findings.json]
#
#  Covers: Low + Info severity findings
#  Same interactive flow as vapt_verify.sh:
#    → Runs appropriate tool per finding
#    → Asks: [c]onfirmed / [f]alse-positive / [s]kip / [q]uit
#    → Saves full report to vapt_low_info_<date>.txt
# ═══════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TARGET=""
FINDINGS_FILE=""
REPORT_FILE="vapt_low_info_results_$(date +%Y%m%d_%H%M%S).txt"
CONFIRMED=0; FP=0; SKIPPED=0; TOTAL=0

log()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$REPORT_FILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$REPORT_FILE"; }
err()    { echo -e "${RED}[x]${NC} $1" | tee -a "$REPORT_FILE"; }
info()   { echo -e "${BLUE}[i]${NC} $1" | tee -a "$REPORT_FILE"; }
section(){ echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}" | tee -a "$REPORT_FILE"; }

# ── Parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET="$2"; shift 2 ;;
    -f|--file)   FINDINGS_FILE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash vapt_verify_low_info.sh -t <target-ip> [-f findings.json]"
      echo "  -t  Target IP or hostname"
      echo "  -f  Findings JSON (exported from AA-VAPT tool)"
      exit 0 ;;
    *) shift ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   AA-VAPT — Low & Info Vulnerability Verifier       ║"
echo "  ║   nmap · curl · openssl · dig · snmpwalk · nc       ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Get target ────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
  read -r -p "$(echo -e "${BOLD}Target IP/hostname:${NC} ")" TARGET
fi
[[ -z "$TARGET" ]] && { err "No target specified."; exit 1; }

{
echo "═══════════════════════════════════════════════════════"
echo "  AA-VAPT Low/Info Verification Report"
echo "  Target : $TARGET"
echo "  Date   : $(date)"
echo "═══════════════════════════════════════════════════════"
echo ""
} | tee "$REPORT_FILE" | cat

log "Target  : ${BOLD}$TARGET${NC}"
log "Report  : $REPORT_FILE"

# ── Tool checker ──────────────────────────────────────────────────
has(){ command -v "$1" &>/dev/null; }

section "Tool Availability"
for tool in nmap curl openssl dig nc ncat telnet snmpwalk whois traceroute; do
  if has "$tool"; then
    echo -e "  ${GREEN}✓${NC} $tool"
  else
    echo -e "  ${RED}✗${NC} $tool ${DIM}(not installed)${NC}"
  fi
done

# ── Tool selector for Low/Info findings ──────────────────────────
get_commands(){
  local name="$1" port="${2:-}" service="${3:-}"
  local nl="${name,,}" sl="${service,,}"
  local cmds=()

  # ── Always: banner grab / service info ──────────────────────
  if [[ -n "$port" && "$port" != "0" ]]; then
    cmds+=("nmap:nmap -sV -sC --open -p ${port} ${TARGET}:Service version + default scripts on port ${port}")
  fi

  # ── SSL/TLS Info ─────────────────────────────────────────────
  if echo "$nl" | grep -qE "ssl|tls|certif|cipher|https|transport"; then
    local p="${port:-443}"
    cmds+=("openssl:echo Q | openssl s_client -connect ${TARGET}:${p} -servername ${TARGET} 2>/dev/null | openssl x509 -noout -text -dates 2>/dev/null | head -40:Certificate details")
    cmds+=("nmap:nmap -p ${p} --script ssl-cert,ssl-enum-ciphers ${TARGET}:SSL certificate + cipher enumeration")
  fi

  # ── HTTP Info / Banner ───────────────────────────────────────
  if echo "$nl" | grep -qE "http|web|banner|server|version.*disclos|header|content.type|x-powered"; then
    local p="${port:-80}"
    local proto="http"; [[ "$p" == "443" || "$p" == "8443" ]] && proto="https"
    cmds+=("curl:curl -skiI --max-time 10 ${proto}://${TARGET}:${p}/ 2>&1 | head -30:HTTP headers — check Server/X-Powered-By")
    cmds+=("nmap:nmap -p ${p} --script http-headers,http-title,http-server-header,http-methods ${TARGET}:HTTP info scripts")
  fi

  # ── ICMP / Ping ──────────────────────────────────────────────
  if echo "$nl" | grep -qE "icmp|ping|timestamp|traceroute"; then
    cmds+=("nmap:nmap -sn --traceroute ${TARGET}:ICMP ping + traceroute")
    cmds+=("nmap:nmap -sV --script icmp-timestamp ${TARGET}:ICMP timestamp request")
  fi

  # ── DNS Info ─────────────────────────────────────────────────
  if echo "$nl" | grep -qE "dns|resolver|reverse.*dns|ptr.*record|hostname"; then
    has dig && cmds+=("dig:dig -x ${TARGET} +short 2>&1:Reverse DNS lookup")
    has dig && cmds+=("dig:dig @${TARGET} version.bind chaos txt +short 2>&1:DNS server version")
    cmds+=("nmap:nmap -p 53 --script dns-service-discovery,dns-recursion ${TARGET}:DNS service info")
  fi

  # ── SNMP Info ────────────────────────────────────────────────
  if echo "$nl" | grep -qE "snmp|community|mib|oid"; then
    cmds+=("nmap:nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-interfaces ${TARGET}:SNMP system info")
    has snmpwalk && cmds+=("snmpwalk:snmpwalk -v2c -c public ${TARGET} system 2>&1 | head -20:SNMP public community walk (system OID)")
  fi

  # ── Open Port / Service Detection ───────────────────────────
  if echo "$nl" | grep -qE "open port|service detect|service running|listen|tcp.*open"; then
    local p="${port:-0}"
    if [[ -n "$port" && "$port" != "0" ]]; then
      cmds+=("nmap:nmap -sV --open -p ${p} ${TARGET}:Confirm service on port ${p}")
      has nc && cmds+=("nc:echo '' | nc -w 3 -v ${TARGET} ${p} 2>&1 | head -10:Banner grab via netcat")
    else
      cmds+=("nmap:nmap -sV --open --top-ports 50 ${TARGET}:Top 50 open ports service scan")
    fi
  fi

  # ── SSH Info ─────────────────────────────────────────────────
  if echo "$nl" | grep -qE "ssh|openssh|host.key|ssh.*algorithm"; then
    local p="${port:-22}"
    cmds+=("nmap:nmap -p ${p} --script ssh-hostkey,ssh2-enum-algos,sshv1 ${TARGET}:SSH host key + algorithms")
    cmds+=("openssl:ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -v ${TARGET} 2>&1 | grep -E 'kex|cipher|mac|Host' | head -15:SSH negotiation details")
  fi

  # ── FTP Info ─────────────────────────────────────────────────
  if echo "$nl" | grep -qE "ftp|file transfer"; then
    local p="${port:-21}"
    cmds+=("nmap:nmap -p ${p} --script ftp-syst,ftp-anon,ftp-bounce ${TARGET}:FTP system info + anonymous check")
    has curl && cmds+=("curl:curl -v --max-time 8 ftp://${TARGET}:${p}/ 2>&1 | head -15:FTP banner grab")
  fi

  # ── SMTP Info ────────────────────────────────────────────────
  if echo "$nl" | grep -qE "smtp|mail|email.*server"; then
    local p="${port:-25}"
    cmds+=("nmap:nmap -p ${p} --script smtp-commands,smtp-ntlm-info ${TARGET}:SMTP commands + info")
    has curl && cmds+=("curl:curl -v --max-time 10 smtp://${TARGET}:${p} 2>&1 | head -15:SMTP banner")
  fi

  # ── Traceroute / Network Info ────────────────────────────────
  if echo "$nl" | grep -qE "traceroute|ttl|hop|network.*path"; then
    cmds+=("nmap:nmap --traceroute -sn ${TARGET}:Network path / traceroute")
  fi

  # ── OS / Version Info ────────────────────────────────────────
  if echo "$nl" | grep -qE "os.*detect|os.*fingerprint|tcp.*fingerprint|os.*disclos"; then
    cmds+=("nmap:nmap -O --osscan-guess ${TARGET}:OS detection + fingerprint")
  fi

  # ── Fallback: generic nmap if nothing matched ────────────────
  if [[ ${#cmds[@]} -eq 0 ]]; then
    if [[ -n "$port" && "$port" != "0" ]]; then
      cmds+=("nmap:nmap -sV -sC --open -p ${port} ${TARGET}:Generic service version + default scripts")
    else
      cmds+=("nmap:nmap -sV --open --top-ports 100 ${TARGET}:Generic top-100 port scan")
    fi
  fi

  printf '%s\n' "${cmds[@]}"
}

# ── Verdict prompt ────────────────────────────────────────────────
ask_verdict(){
  local finding="$1"
  echo ""
  echo -e "${BOLD}  Result for: ${CYAN}${finding}${NC}"
  echo -e "  ${GREEN}[c]${NC} Confirmed (real info/issue)"
  echo -e "  ${YELLOW}[f]${NC} False positive"
  echo -e "  ${BLUE}[s]${NC} Skip"
  echo -e "  ${RED}[q]${NC} Quit"
  echo ""
  while true; do
    read -r -p "  Verdict [c/f/s/q]: " v
    case "${v,,}" in
      c|confirmed) echo "CONFIRMED";      return ;;
      f|fp|false)  echo "FALSE_POSITIVE"; return ;;
      s|skip)      echo "SKIPPED";        return ;;
      q|quit|exit) echo "QUIT";           return ;;
      *) echo -e "  ${RED}Enter c, f, s or q${NC}" ;;
    esac
  done
}

# ── Run one finding ───────────────────────────────────────────────
run_finding(){
  local idx="$1" total="$2" name="$3" severity="$4" port="${5:-}" service="${6:-}" synopsis="${7:-}"

  echo "" | tee -a "$REPORT_FILE"

  # Severity colour: low=blue, info=grey
  local sc="$BLUE"
  [[ "${severity,,}" == "info" ]] && sc="$DIM"

  echo -e "${BOLD}${sc}╔══════════════════════════════════════════════════════════╗${NC}" | tee -a "$REPORT_FILE"
  printf "${BOLD}${sc}║${NC}  [%d/%d] %-52s ${BOLD}${sc}║${NC}\n" "$idx" "$total" "$name" | tee -a "$REPORT_FILE"
  echo -e "  Severity : ${sc}${BOLD}${severity^^}${NC}" | tee -a "$REPORT_FILE"
  [[ -n "$port" && "$port" != "0" ]] && echo -e "  Port     : $port/$service" | tee -a "$REPORT_FILE"
  [[ -n "$synopsis" ]] && echo -e "  Synopsis : ${DIM}${synopsis:0:120}${NC}" | tee -a "$REPORT_FILE"
  echo -e "${BOLD}${sc}╚══════════════════════════════════════════════════════════╝${NC}" | tee -a "$REPORT_FILE"

  # Get commands
  local cmds_raw
  mapfile -t cmds_raw < <(get_commands "$name" "$port" "$service")

  # Run each command
  for entry in "${cmds_raw[@]}"; do
    local tool="${entry%%:*}"
    local rest="${entry#*:}"
    local cmd="${rest%%:*}"
    local purpose="${rest#*:}"

    if ! has "$tool"; then
      warn "Tool '${tool}' not installed — skipping: $purpose"
      echo "[SKIPPED - tool missing: $tool] $purpose" >> "$REPORT_FILE"
      continue
    fi

    section "Running: $purpose"
    echo -e "  ${DIM}\$ ${cmd}${NC}" | tee -a "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    local output
    output=$(timeout 90 bash -c "$cmd" 2>&1) || true
    echo "$output" | tee -a "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
  done

  # Verdict
  local verdict
  verdict=$(ask_verdict "$name")
  echo "VERDICT: $verdict — $name" >> "$REPORT_FILE"

  case "$verdict" in
    CONFIRMED)
      CONFIRMED=$((CONFIRMED+1))
      log "✓ CONFIRMED: $name" ;;
    FALSE_POSITIVE)
      FP=$((FP+1))
      warn "✗ FALSE POSITIVE: $name" ;;
    SKIPPED)
      SKIPPED=$((SKIPPED+1))
      info "→ SKIPPED: $name" ;;
    QUIT)
      section "Summary (interrupted)"
      print_summary
      exit 0 ;;
  esac
}

print_summary(){
  echo "" | tee -a "$REPORT_FILE"
  section "Verification Summary"
  echo -e "  Total tested   : ${BOLD}$TOTAL${NC}"   | tee -a "$REPORT_FILE"
  echo -e "  ${GREEN}Confirmed      : $CONFIRMED${NC}" | tee -a "$REPORT_FILE"
  echo -e "  ${YELLOW}False positives: $FP${NC}"       | tee -a "$REPORT_FILE"
  echo -e "  ${BLUE}Skipped        : $SKIPPED${NC}"    | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"
  log "Report saved: ${BOLD}$(pwd)/$REPORT_FILE${NC}"
}

# ── Load findings ─────────────────────────────────────────────────
section "Loading Low/Info Findings"

declare -a F_NAMES F_SEVERITIES F_PORTS F_SERVICES F_SYNOPSES

if [[ -n "$FINDINGS_FILE" && -f "$FINDINGS_FILE" ]]; then
  info "Parsing: $FINDINGS_FILE"

  eval "$(python3 - << PYEOF
import json, sys

try:
    data = json.load(open('${FINDINGS_FILE}'))
except Exception as e:
    print(f'echo "JSON error: {e}"; exit 1')
    sys.exit(1)

issues = data if isinstance(data, list) else data.get('issues', data.get('findings', []))

# ONLY low and info
target_sevs = {'low', 'info'}
filtered = [i for i in issues if str(i.get('severity','')).lower() in target_sevs]
filtered.sort(key=lambda x: {'low':0,'info':1}.get(x.get('severity','').lower(), 2))

print(f'TOTAL={len(filtered)}')
for i, f in enumerate(filtered):
    name     = str(f.get('name', f.get('pluginName','Unknown'))).replace("'", "\\'")
    sev      = str(f.get('severity','info'))
    port     = str(f.get('port',''))
    service  = str(f.get('service',''))
    synopsis = str(f.get('synopsis','')).replace("'","\\'")\[:100\]
    print(f"F_NAMES[{i}]='{name}'")
    print(f"F_SEVERITIES[{i}]='{sev}'")
    print(f"F_PORTS[{i}]='{port}'")
    print(f"F_SERVICES[{i}]='{service}'")
    print(f"F_SYNOPSES[{i}]='{synopsis}'")
PYEOF
)"

  log "Loaded $TOTAL Low/Info findings"

else
  warn "No findings file — manual mode"
  echo ""
  TOTAL=0
  while true; do
    read -r -p "$(echo -e "${BOLD}Finding name (ENTER to finish):${NC} ")" fname
    [[ -z "$fname" ]] && break
    read -r -p "Severity [low/info]: " fsev
    read -r -p "Port (ENTER to skip): " fport
    read -r -p "Service (ENTER to skip): " fservice
    F_NAMES[$TOTAL]="$fname"
    F_SEVERITIES[$TOTAL]="${fsev:-info}"
    F_PORTS[$TOTAL]="${fport:-}"
    F_SERVICES[$TOTAL]="${fservice:-}"
    F_SYNOPSES[$TOTAL]=""
    TOTAL=$((TOTAL+1))
    echo ""
  done
  log "Loaded $TOTAL findings manually"
fi

if [[ "$TOTAL" -eq 0 ]]; then
  warn "No Low/Info findings to process. Exiting."
  exit 0
fi

echo ""
echo -e "  ${BOLD}Found ${CYAN}$TOTAL${NC}${BOLD} Low/Info findings on ${CYAN}$TARGET${NC}"
echo -e "  ${DIM}Ctrl+C to stop anytime. Results saved continuously.${NC}"
echo ""
read -r -p "$(echo -e "${BOLD}Press ENTER to begin...${NC}")" _

# ── Main loop ─────────────────────────────────────────────────────
for (( i=0; i<TOTAL; i++ )); do
  run_finding \
    "$((i+1))" "$TOTAL" \
    "${F_NAMES[$i]}" \
    "${F_SEVERITIES[$i]}" \
    "${F_PORTS[$i]:-}" \
    "${F_SERVICES[$i]:-}" \
    "${F_SYNOPSES[$i]:-}"
done

print_summary
