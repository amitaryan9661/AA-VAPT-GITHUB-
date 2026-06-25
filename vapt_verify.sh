#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  AA-VAPT — Interactive Vulnerability Verifier
#  Usage: bash vapt_verify.sh -t <target-ip> -f <findings.json>
#         bash vapt_verify.sh -t 192.168.1.1 -f scan_export.json
#         bash vapt_verify.sh -t 192.168.1.1  (manual finding entry)
#
#  For each High/Critical/Medium finding:
#    → Picks best tool (nmap/testssl/nikto/curl/smbclient/etc.)
#    → Runs verification command
#    → Asks: [c]onfirmed / [f]alse-positive / [s]kip / [n]ext
#    → Saves full report to vapt_results_<date>.txt
# ═══════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TARGET=""
FINDINGS_FILE=""
REPORT_FILE="vapt_results_$(date +%Y%m%d_%H%M%S).txt"
CONFIRMED=0; FP=0; SKIPPED=0; TOTAL=0

# FIX B7: Strip ANSI codes when writing to report file
log()    { echo -e "${GREEN}[+]${NC} $1" | tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"); }
warn()   { echo -e "${YELLOW}[!]${NC} $1" | tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"); }
err()    { echo -e "${RED}[x]${NC} $1" | tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"); }
info()   { echo -e "${BLUE}[i]${NC} $1" | tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"); }
section(){ echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}" | tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"); }

# ── Parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET="$2"; shift 2 ;;
    -f|--file)   FINDINGS_FILE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash vapt_verify.sh -t <target-ip> [-f findings.json]"
      echo "  -t  Target IP or hostname"
      echo "  -f  Findings JSON file (exported from AA-VAPT tool)"
      exit 0 ;;
    *) shift ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   AA-VAPT — Interactive Vulnerability Verifier       ║"
echo "  ║   nmap · testssl · nikto · curl · smbclient · more   ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Get target ────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
  read -r -p "$(echo -e "${BOLD}Target IP/hostname:${NC} ")" TARGET
fi
[[ -z "$TARGET" ]] && { err "No target specified. Exiting."; exit 1; }

echo "" >> "$REPORT_FILE"
echo "═══════════════════════════════════════════════════════" >> "$REPORT_FILE"
echo "  AA-VAPT Verification Report" >> "$REPORT_FILE"
echo "  Target : $TARGET" >> "$REPORT_FILE"
echo "  Date   : $(date)" >> "$REPORT_FILE"
echo "═══════════════════════════════════════════════════════" >> "$REPORT_FILE"
log "Target: ${BOLD}$TARGET${NC}"
log "Report: $REPORT_FILE"

# ── Tool checker ──────────────────────────────────────────────────
has(){ command -v "$1" &>/dev/null; }

check_tools(){
  section "Tool Availability"
  for tool in nmap testssl.sh testssl sslscan openssl nikto curl wget smbclient enum4linux smbmap ssh-audit whatweb dig; do
    if has "$tool"; then
      echo -e "  ${GREEN}✓${NC} $tool"
    else
      echo -e "  ${RED}✗${NC} $tool ${DIM}(not installed — some checks may be skipped)${NC}"
    fi
  done
}
check_tools

# ── Tool selector based on finding keywords ───────────────────────
get_commands(){
  local name="$1" port="${2:-}" service="${3:-}"
  local nl="${name,,}" sl="${service,,}"
  local cmds=()

  # Always run nmap service version scan
  if [[ -n "$port" && "$port" != "0" ]]; then
    cmds+=("nmap:nmap -sV -sC --open -p ${port} ${TARGET}:Service version + default scripts on port ${port}")
  else
    cmds+=("nmap:nmap -sV --open -F ${TARGET}:Fast service scan")
  fi

  # SSL/TLS
  if echo "$nl" | grep -qE "ssl|tls|certif|cipher|protocol|transport|https|starttls|poodle|beast|lucky13|heartbleed|freak|logjam|drown|sweet32|robot|ticketbleed|ccs|renegotiation|weak.*crypt|crypto"; then
    local p="${port:-443}"
    # testssl FIRST (PRIMARY) — certificate validity / expiry, like the PoC
    if has testssl.sh; then
      cmds+=("testssl:testssl.sh -S --color 0 --warnings off ${TARGET}:${p}:Certificate validity / expiry (PRIMARY)")
    elif has testssl; then
      cmds+=("testssl:testssl -S --color 0 --warnings off ${TARGET}:${p}:Certificate validity / expiry (PRIMARY)")
    fi
    # nmap ssl-cert as FALLBACK — SHA-1 signature + dates when testssl fails
    cmds+=("nmap:nmap -Pn --script ssl-cert -p ${p} ${TARGET}:Certificate details fallback (SHA-1 + validity dates)")
    has sslscan && cmds+=("sslscan:sslscan --no-colour ${TARGET}:${p}:SSL/TLS cipher & protocol enumeration")
    cmds+=("openssl:openssl s_client -connect ${TARGET}:${p} -tls1 </dev/null 2>&1 | head -30:Check TLS 1.0 support")
    cmds+=("openssl:openssl s_client -connect ${TARGET}:${p} </dev/null 2>&1 | openssl x509 -noout -dates -subject -issuer 2>/dev/null:Certificate info")
  fi

  # HTTP/Web
  if echo "$nl" | grep -qE "http|web|apache|nginx|iis|php|cms|wordpress|joomla|xss|sql.inj|csrf|lfi|rfi|direct|trav|upload"; then
    local p="${port:-80}"
    [[ "$p" == "443" ]] && local proto="https" || local proto="http"
    has nikto  && cmds+=("nikto:nikto -h ${proto}://${TARGET}:${p} -maxtime 300:Web vulnerability scan (nikto)")
    has curl   && cmds+=("curl:curl -skiI --max-time 15 ${proto}://${TARGET}:${p}/ 2>&1 | head -30:HTTP headers check")
    has whatweb && cmds+=("whatweb:whatweb -v ${proto}://${TARGET}:${p}:Web technology fingerprint")
    cmds+=("nmap:nmap -p ${p} --script http-methods,http-headers,http-title,http-server-header ${TARGET}:HTTP enumeration scripts")
  fi

  # SMB/Windows
  if echo "$nl" | grep -qE "smb|netbios|ms17|eternalblue|ms08|cifs|samba|windows.*share|null.*session"; then
    # FIX B5: quoted glob to prevent shell expansion
    cmds+=("nmap:nmap -p 445,139 --script 'smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb-enum-shares,smb2-security-mode' ${TARGET}:SMB vulnerability scripts")
    has smbmap     && cmds+=("smbmap:smbmap -H ${TARGET}:SMB share enumeration")
    has enum4linux && cmds+=("enum4linux:enum4linux -a ${TARGET}:Full SMB/NetBIOS enumeration")
    has smbclient  && cmds+=("smbclient:smbclient -L //${TARGET} -N 2>&1:SMB null session share list")
  fi

  # SSH
  if echo "$nl" | grep -qE "ssh|weak.*key|diffie|cbc.*mode|weak.*mac|openssh"; then
    local p="${port:-22}"
    cmds+=("nmap:nmap -p ${p} --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos ${TARGET}:SSH algorithm enumeration")
    has ssh-audit && cmds+=("ssh-audit:ssh-audit ${TARGET}:Comprehensive SSH audit")
    cmds+=("ssh:ssh -vvv -o BatchMode=yes -o StrictHostKeyChecking=no -p ${p} testuser@${TARGET} 2>&1 | grep -E 'kex|cipher|mac|Host' | head -20:SSH key exchange & cipher negotiation")
  fi

  # DNS
  if echo "$nl" | grep -qE "dns|zone.transfer|cache.poison|dnssec|resolver"; then
    has dig && cmds+=("dig:dig @${TARGET} version.bind chaos txt +short 2>&1:DNS version disclosure")
    has dig && cmds+=("dig:DOMAIN=\$(dig @${TARGET} +short -t NS . 2>/dev/null | head -1); dig @${TARGET} axfr \${DOMAIN:-.} 2>&1 | head -30:DNS zone transfer attempt")
    cmds+=("nmap:nmap -p 53 --script dns-recursion,dns-service-discovery,dns-zone-transfer ${TARGET}:DNS vulnerability scripts")
  fi

  # SMTP/Mail
  if echo "$nl" | grep -qE "smtp|mail|open.relay|vrfy|expn"; then
    local p="${port:-25}"
    cmds+=("nmap:nmap -p ${p} --script smtp-open-relay,smtp-commands,smtp-enum-users ${TARGET}:SMTP relay & enumeration")
    has curl && cmds+=("curl:curl -v --max-time 15 smtp://${TARGET}:${p} 2>&1 | head -20:SMTP banner grab")
  fi

  # FTP
  if echo "$nl" | grep -qE "ftp|anonymous.*ftp|ftp.*anon"; then
    local p="${port:-21}"
    cmds+=("nmap:nmap -p ${p} --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor ${TARGET}:FTP vulnerability scripts")
    has curl && cmds+=("curl:curl -v --max-time 10 ftp://${TARGET}:${p}/ --user anonymous:test 2>&1 | head -20:FTP anonymous login test")
  fi

  # RDP
  if echo "$nl" | grep -qE "rdp|remote.desktop|ms12-020|bluekeep|ms19"; then
    local p="${port:-3389}"
    cmds+=("nmap:nmap -p ${p} --script rdp-vuln-ms12-020,rdp-enum-encryption ${TARGET}:RDP vulnerability scan")
  fi

  # Database — FIX B5: quoted nmap script glob
  if echo "$nl" | grep -qE "mysql|mssql|sql.server|oracle|postgresql|mongodb|redis|memcache"; then
    local dbport="${port:-3306}"
    echo "$nl" | grep -q "mssql\|sql.server" && dbport="${port:-1433}"
    echo "$nl" | grep -q "oracle"             && dbport="${port:-1521}"
    echo "$nl" | grep -q "postgresql"         && dbport="${port:-5432}"
    echo "$nl" | grep -q "redis"              && dbport="${port:-6379}"
    cmds+=("nmap:nmap -p ${dbport} --script '*-info,*-empty-password,*-brute' ${TARGET} 2>/dev/null | head -40:Database enumeration")
  fi

  # SNMP
  if echo "$nl" | grep -qE "snmp|community.string|public.*community"; then
    cmds+=("nmap:nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-brute ${TARGET}:SNMP community string & info")
    has snmpwalk && cmds+=("snmpwalk:snmpwalk -v2c -c public ${TARGET} 2>&1 | head -30:SNMP public community walk")
  fi

  printf '%s\n' "${cmds[@]}"
}

# ── Ask confirmation ──────────────────────────────────────────────
# FIX B3: verdict options printed to stderr so they don't pollute stdout capture
ask_verdict(){
  local finding="$1"
  echo "" >&2
  echo -e "${BOLD}  Result for: ${CYAN}${finding}${NC}" >&2
  echo -e "  ${GREEN}[c]${NC} Confirmed vulnerability" >&2
  echo -e "  ${YELLOW}[f]${NC} False positive" >&2
  echo -e "  ${BLUE}[s]${NC} Skip (decide later)" >&2
  echo -e "  ${RED}[q]${NC} Quit script" >&2
  echo "" >&2
  while true; do
    read -r -p "  Your verdict [c/f/s/q]: " v <&2
    case "${v,,}" in
      c|confirmed) echo "CONFIRMED" ; return ;;
      f|fp|false)  echo "FALSE_POSITIVE" ; return ;;
      s|skip)      echo "SKIPPED" ; return ;;
      q|quit|exit) echo "QUIT" ; return ;;
      *) echo -e "  ${RED}Invalid — enter c, f, s, or q${NC}" >&2 ;;
    esac
  done
}

# ── Run one finding ───────────────────────────────────────────────
run_finding(){
  local idx="$1" total="$2" name="$3" severity="$4" port="${5:-}" service="${6:-}" synopsis="${7:-}"

  echo "" | tee -a "$REPORT_FILE"
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════╗${NC}" | tee -a "$REPORT_FILE"
  printf "${BOLD}${MAGENTA}║${NC}  [%d/%d] %-52s ${BOLD}${MAGENTA}║${NC}\n" "$idx" "$total" "$name" | tee -a "$REPORT_FILE"

  local sev_color="$YELLOW"
  [[ "${severity,,}" == "critical" ]] && sev_color="$RED"
  [[ "${severity,,}" == "high" ]]     && sev_color="${RED}"
  [[ "${severity,,}" == "medium" ]]   && sev_color="$YELLOW"

  echo -e "  Severity : ${sev_color}${BOLD}${severity^^}${NC}" | tee -a "$REPORT_FILE"
  [[ -n "$port" && "$port" != "0" ]] && echo -e "  Port     : $port/$service" | tee -a "$REPORT_FILE"
  [[ -n "$synopsis" ]] && echo -e "  Synopsis : ${DIM}${synopsis:0:120}${NC}" | tee -a "$REPORT_FILE"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════╝${NC}" | tee -a "$REPORT_FILE"

  # Get commands for this finding
  local cmds_raw
  mapfile -t cmds_raw < <(get_commands "$name" "$port" "$service")

  if [[ ${#cmds_raw[@]} -eq 0 ]]; then
    warn "No specific tool commands for this finding — running generic nmap scan"
    cmds_raw=("nmap:nmap -sV -sC --top-ports 100 ${TARGET}:Generic service scan")
  fi

  # Run each command
  for entry in "${cmds_raw[@]}"; do
    local tool="${entry%%:*}"
    local rest="${entry#*:}"
    local cmd="${rest%%:*}"
    local purpose="${rest#*:}"

    if ! has "$tool"; then
      warn "Tool '${tool}' not installed — skipping: $purpose"
      echo "[SKIPPED - tool not found: $tool] $purpose" >> "$REPORT_FILE"
      continue
    fi

    section "Running: $purpose"
    echo -e "  ${DIM}\$ ${cmd}${NC}"
    echo "  \$ ${cmd}" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"

    # FIX B6: Per-tool timeout — testssl/nikto get 600s, others 120s
    local tool_timeout=120
    case "$tool" in
      testssl*|nikto) tool_timeout=600 ;;
      enum4linux)     tool_timeout=300 ;;
    esac

    local output
    output=$(timeout "$tool_timeout" bash -c "$cmd" 2>&1) || true
    echo "$output" | tee -a "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
  done

  # Ask verdict — FIX B3: stdout only gets the verdict token
  local verdict
  verdict=$(ask_verdict "$name")
  echo "VERDICT: $verdict — $name" >> "$REPORT_FILE"

  case "$verdict" in
    CONFIRMED)     CONFIRMED=$((CONFIRMED+1)); log "✓ CONFIRMED: $name" ;;
    FALSE_POSITIVE)FP=$((FP+1));        warn "✗ FALSE POSITIVE: $name" ;;
    SKIPPED)       SKIPPED=$((SKIPPED+1));   info "→ SKIPPED: $name" ;;
    QUIT)
      section "Final Summary (interrupted)"
      print_summary
      exit 0 ;;
  esac
}

print_summary(){
  echo "" | tee -a "$REPORT_FILE"
  section "Verification Summary"
  echo -e "  Total tested   : ${BOLD}$TOTAL${NC}" | tee -a "$REPORT_FILE"
  echo -e "  ${RED}Confirmed vulns : $CONFIRMED${NC}" | tee -a "$REPORT_FILE"
  echo -e "  ${YELLOW}False positives : $FP${NC}" | tee -a "$REPORT_FILE"
  echo -e "  ${BLUE}Skipped        : $SKIPPED${NC}" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"
  log "Full report saved: ${BOLD}$(pwd)/$REPORT_FILE${NC}"
}

# ── Load findings ─────────────────────────────────────────────────
section "Loading Findings"

declare -a F_NAMES F_SEVERITIES F_PORTS F_SERVICES F_SYNOPSES

if [[ -n "$FINDINGS_FILE" && -f "$FINDINGS_FILE" ]]; then
  info "Parsing findings from: $FINDINGS_FILE"

  # FIX B1 + B2: Use a temp file instead of eval to avoid injection
  local_tmpfile=$(mktemp /tmp/vapt_findings_XXXXXX.sh)

  python3 - "$FINDINGS_FILE" > "$local_tmpfile" << 'PYEOF'
import json, sys

findings_path = sys.argv[1]
try:
    with open(findings_path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)
except Exception as e:
    print(f'echo "JSON parse error: {e}"; exit 1', file=sys.stderr)
    sys.exit(1)

issues = data if isinstance(data, list) else data.get('issues', data.get('findings', []))
target_sevs = {'critical', 'high', 'medium'}
filtered = [i for i in issues if str(i.get('severity', '')).lower() in target_sevs]
filtered.sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2}.get(x.get('severity', '').lower(), 3))

print(f'TOTAL={len(filtered)}')
for i, f in enumerate(filtered):
    # FIX B1: Truncate synopsis in Python (not shell), safe quoting via printf-style
    name     = str(f.get('name', f.get('pluginName', 'Unknown')))[:120]
    sev      = str(f.get('severity', 'medium'))[:20]
    port     = str(f.get('port', ''))[:10]
    service  = str(f.get('service', ''))[:30]
    synopsis = str(f.get('synopsis', ''))[:100]

    # Escape for bash single-quote safety: replace ' with '"'"'
    def sq(s):
        return s.replace("'", "'\"'\"'")

    print(f"F_NAMES[{i}]='{sq(name)}'")
    print(f"F_SEVERITIES[{i}]='{sq(sev)}'")
    print(f"F_PORTS[{i}]='{sq(port)}'")
    print(f"F_SERVICES[{i}]='{sq(service)}'")
    print(f"F_SYNOPSES[{i}]='{sq(synopsis)}'")
PYEOF

  py_exit=$?
  if [[ $py_exit -ne 0 ]]; then
    err "Python failed to parse findings file. Check JSON format."
    rm -f "$local_tmpfile"
    exit 1
  fi

  # Source the safe generated file instead of eval
  # shellcheck source=/dev/null
  source "$local_tmpfile"
  rm -f "$local_tmpfile"

  # FIX B4: Validate TOTAL was actually set
  if [[ -z "$TOTAL" || ! "$TOTAL" =~ ^[0-9]+$ ]]; then
    err "Failed to load findings — TOTAL not set. Check JSON format."
    exit 1
  fi

  log "Loaded $TOTAL findings (Critical/High/Medium)"

else
  warn "No findings file provided — entering manual mode"
  echo ""
  info "Enter findings manually. Press ENTER with empty name when done."
  echo ""
  TOTAL=0
  while true; do
    read -r -p "$(echo -e "${BOLD}Finding name (or ENTER to finish):${NC} ")" fname
    [[ -z "$fname" ]] && break
    read -r -p "Severity [critical/high/medium]: " fsev
    read -r -p "Port (or ENTER to skip): " fport
    read -r -p "Service (or ENTER to skip): " fservice
    F_NAMES[$TOTAL]="$fname"
    F_SEVERITIES[$TOTAL]="${fsev:-medium}"
    F_PORTS[$TOTAL]="${fport:-}"
    F_SERVICES[$TOTAL]="${fservice:-}"
    F_SYNOPSES[$TOTAL]=""
    TOTAL=$((TOTAL+1))
    echo ""
  done
  log "Loaded $TOTAL findings manually"
fi

if [[ "$TOTAL" -eq 0 ]]; then
  warn "No findings to process. Exiting."
  exit 0
fi

echo ""
echo -e "  ${BOLD}Found ${CYAN}$TOTAL${NC}${BOLD} findings to verify on target ${CYAN}$TARGET${NC}"
echo -e "  ${DIM}Press Ctrl+C at any time to stop. Results saved continuously.${NC}"
echo ""
read -r -p "$(echo -e "${BOLD}Press ENTER to begin verification...${NC}")" _

# ── Main loop ─────────────────────────────────────────────────────
for (( i=0; i<TOTAL; i++ )); do
  name="${F_NAMES[$i]}"
  sev="${F_SEVERITIES[$i]}"
  port="${F_PORTS[$i]:-}"
  service="${F_SERVICES[$i]:-}"
  synopsis="${F_SYNOPSES[$i]:-}"

  run_finding "$((i+1))" "$TOTAL" "$name" "$sev" "$port" "$service" "$synopsis"
done

# ── Final summary ─────────────────────────────────────────────────
print_summary
