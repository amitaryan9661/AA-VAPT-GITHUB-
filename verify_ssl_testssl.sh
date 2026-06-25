#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  AA-VAPT — SSL Certificate Checker  (testssl-first → nmap fallback)
#
#  Detection flow per target (testssl is the PRIMARY tool):
#     1. testssl -S         → "Certificate Validity" / expiry  (PRIMARY)
#     2. nmap ssl-cert      → used ONLY if testssl fails        (FALLBACK)
#     3. openssl            → last resort
#
#  Reports ONLY these issues (trust / self-signed / hostname IGNORED):
#     • EXPIRED                      → RED
#     • EXPIRING within 30 days      → YELLOW
#     • WEAK SHA-1 signature         → RED
#
#  All output is printed to THIS terminal and saved to ./aa-vapt-logs/
# ══════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

LOG_DIR="$(pwd)/aa-vapt-logs"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="${LOG_DIR}/ssl_cert_report_${STAMP}.txt"
RAW_LOG="${LOG_DIR}/ssl_cert_raw_${STAMP}.log"
TESTSSL_TIMEOUT=60      # testssl is primary; give it room
TIMEOUT=30

EXPIRED_COUNT=0; SHA1_COUNT=0; EXPIRING_COUNT=0
OK_COUNT=0; FAIL_COUNT=0; TOTAL=0

# ── Resolve tools (testssl is the primary) ─────────────────────────
TESTSSL=$(command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null)
[ -z "$TESTSSL" ] && [ -x "./testssl.sh/testssl.sh" ] && TESTSSL="./testssl.sh/testssl.sh"
NMAP=$(command -v nmap 2>/dev/null)
OPENSSL=$(command -v openssl 2>/dev/null)

if [ -z "$TESTSSL" ] && [ -z "$NMAP" ] && [ -z "$OPENSSL" ]; then
  echo -e "${RED}[x]${NC} No usable tool found. Install testssl.sh (primary) or nmap."
  exit 1
fi

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   AA-VAPT — SSL Certificate Checker              ║"
echo "  ║   testssl → nmap fallback   (SHA-1 · expiry)    ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
[ -n "$TESTSSL" ] && echo -e "  ${GREEN}✓${NC} testssl : $TESTSSL ${DIM}(primary)${NC}" || echo -e "  ${YELLOW}!${NC} testssl not found — will use nmap"
[ -n "$NMAP" ]    && echo -e "  ${GREEN}✓${NC} nmap    : $NMAP ${DIM}(fallback)${NC}"
[ -n "$OPENSSL" ] && echo -e "  ${GREEN}✓${NC} openssl : $OPENSSL"
echo ""

{
  echo "════════════════════════════════════════════════════════"
  echo "  AA-VAPT SSL Certificate Report"
  echo "  Date   : $(date)"
  echo "  Engine : testssl (primary) -> nmap ssl-cert (fallback)"
  echo "  Note   : trust / self-signed / hostname issues are ignored"
  echo "════════════════════════════════════════════════════════"
  echo ""
} | tee "$REPORT"

to_epoch(){
  local d="$1"
  [ -z "$d" ] && { echo 0; return; }
  date -d "$d" +%s 2>/dev/null \
    || date -j -f "%b %d %H:%M:%S %Y %Z" "$d" +%s 2>/dev/null \
    || date -j -f "%Y-%m-%dT%H:%M:%S" "$d" +%s 2>/dev/null \
    || echo 0
}

fmt_date(){
  local d="$1"
  [ -z "$d" ] && { echo "?"; return; }
  date -d "$d" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "$d"
}

check_ssl(){
  local HOST="$1" PORT="$2"
  TOTAL=$((TOTAL+1))

  local NOT_BEFORE="" NOT_AFTER="" SIG_ALG="" SRC="" EXPIRED_FLAG=false
  local TOUT="" NOUT="" VLINE=""

  # ── STEP 1 — testssl (PRIMARY: certificate validity / expiry) ────
  if [ -n "$TESTSSL" ]; then
    TOUT=$(timeout "$TESTSSL_TIMEOUT" "$TESTSSL" -S --color 0 --warnings off "${HOST}:${PORT}" 2>/dev/null)
    VLINE=$(echo "$TOUT" | grep -i "Certificate Validity")
    if [ -n "$VLINE" ]; then
      NOT_BEFORE=$(echo "$VLINE" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}" | head -1)
      NOT_AFTER=$(echo  "$VLINE" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}" | tail -1)
      echo "$VLINE" | grep -qi "expired" && EXPIRED_FLAG=true
      SRC="testssl"
    fi
    SIG_ALG=$(echo "$TOUT" | grep -i "Signature Algorithm" | head -1 | sed -E 's/.*Signature Algorithm[[:space:]]*//I')
  fi

  # ── STEP 2 — nmap ssl-cert (FALLBACK only if testssl failed) ─────
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ] && [ -n "$NMAP" ]; then
    NOUT=$(timeout "$TIMEOUT" "$NMAP" -Pn --script ssl-cert -p "$PORT" "$HOST" 2>/dev/null)
    NOT_BEFORE=$(echo "$NOUT" | grep -i "Not valid before:" | head -1 | sed -E 's/.*Not valid before:[[:space:]]*//I')
    NOT_AFTER=$(echo "$NOUT"  | grep -i "Not valid after:"  | head -1 | sed -E 's/.*Not valid after:[[:space:]]*//I')
    [ -z "$SIG_ALG" ] && SIG_ALG=$(echo "$NOUT" | grep -i "Signature Algorithm:" | head -1 | sed -E 's/.*Signature Algorithm:[[:space:]]*//I')
    [ -n "$NOT_AFTER" ] && SRC="nmap"
  fi

  # ── STEP 3 — openssl (last resort) ───────────────────────────────
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ] && [ -n "$OPENSSL" ]; then
    local RAW CX
    RAW=$(echo Q | timeout 12 "$OPENSSL" s_client -connect "${HOST}:${PORT}" -servername "$HOST" 2>/dev/null)
    if [ -n "$RAW" ]; then
      CX=$(echo "$RAW" | "$OPENSSL" x509 -noout -dates -text 2>/dev/null)
      NOT_BEFORE=$(echo "$CX" | grep "notBefore" | cut -d= -f2-)
      NOT_AFTER=$(echo  "$CX" | grep "notAfter"  | cut -d= -f2-)
      [ -z "$SIG_ALG" ] && SIG_ALG=$(echo "$CX" | grep -i "Signature Algorithm" | head -1 | awk -F': ' '{print $2}')
      [ -n "$NOT_AFTER" ] && SRC="openssl"
    fi
  fi

  # ── Save full raw evidence ───────────────────────────────────────
  {
    echo "######## ${HOST}:${PORT}  ($(date '+%F %T')) ########"
    [ -n "$TOUT" ] && { echo "----- testssl -S -----"; echo "$TOUT" | grep -iE "Certificate Validity|Signature Algorithm|Chain of trust|expired"; }
    [ -n "$NOUT" ] && { echo "----- nmap ssl-cert (fallback) -----"; echo "$NOUT"; }
    echo ""
  } >> "$RAW_LOG"

  # ── No certificate retrieved at all → FAIL ───────────────────────
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ]; then
    echo -e "  ${RED}✗ ${BOLD}${HOST}:${PORT}${NC} — ${RED}NO RESPONSE / NO CERT${NC}"
    echo ""
    { printf "  [%-13s] %s:%s\n\n" "NO RESPONSE" "$HOST" "$PORT"; } >> "$REPORT"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  # ── Expiry calculation ───────────────────────────────────────────
  local EXP_TS NOW_TS DAYS_LEFT=9999 EXPIRED=false EXPIRING=false
  if [ -n "$NOT_AFTER" ]; then
    EXP_TS=$(to_epoch "$NOT_AFTER"); NOW_TS=$(date +%s)
    DAYS_LEFT=$(( (EXP_TS - NOW_TS) / 86400 ))
    [ $DAYS_LEFT -lt 0 ] && EXPIRED=true
    [ $DAYS_LEFT -ge 0 ] && [ $DAYS_LEFT -lt 30 ] && EXPIRING=true
  fi
  # testssl's explicit "expired" verdict always wins
  if [ "$EXPIRED_FLAG" = true ]; then EXPIRED=true; EXPIRING=false; fi

  # ── SHA-1 detection ──────────────────────────────────────────────
  local IS_SHA1=false
  echo "$SIG_ALG" | grep -qiE "sha1|sha-1" && IS_SHA1=true

  # ── Status + issue list (trust/self-signed/hostname IGNORED) ─────
  local SC="$GREEN" SI="✓" ST="VALID"
  local ISSUES=()
  if $EXPIRED; then
    SC="$RED"; SI="✗"; ST="EXPIRED"
    if [ -n "$NOT_AFTER" ] && [ "$DAYS_LEFT" != "9999" ]; then
      ISSUES+=("EXPIRED (${DAYS_LEFT#-} days ago)")
    else
      ISSUES+=("EXPIRED (per testssl)")
    fi
    EXPIRED_COUNT=$((EXPIRED_COUNT+1))
  elif $EXPIRING; then
    SC="$YELLOW"; SI="!"; ST="EXPIRING SOON"
    ISSUES+=("EXPIRING in ${DAYS_LEFT} days")
    EXPIRING_COUNT=$((EXPIRING_COUNT+1))
  else
    OK_COUNT=$((OK_COUNT+1))
  fi
  if $IS_SHA1; then
    ISSUES+=("WEAK SHA-1 signature (${SIG_ALG})")
    SHA1_COUNT=$((SHA1_COUNT+1))
    [ "$ST" = "VALID" ] && { SC="$RED"; SI="!"; ST="WEAK SHA-1"; }
  fi

  # ── Screen output ────────────────────────────────────────────────
  echo -e "  ${SC}${SI} ${BOLD}${HOST}:${PORT}${NC} — ${SC}${BOLD}${ST}${NC} ${DIM}(via ${SRC})${NC}"
  echo -e "    Signature : ${SIG_ALG:-unknown}"
  echo -e "    Valid From: $(fmt_date "$NOT_BEFORE")"
  echo -e "    Valid To  : $(fmt_date "$NOT_AFTER")"
  for issue in "${ISSUES[@]}"; do
    echo -e "    ${SC}▲ ${issue}${NC}"
  done
  echo ""

  # ── Plain report file ────────────────────────────────────────────
  {
    printf "  [%-13s] %s:%s   (via %s)\n" "$ST" "$HOST" "$PORT" "$SRC"
    echo   "    Signature : ${SIG_ALG:-unknown}"
    echo   "    Valid From: $(fmt_date "$NOT_BEFORE")"
    echo   "    Valid To  : $(fmt_date "$NOT_AFTER")"
    echo   "    Days Left : ${DAYS_LEFT}"
    for issue in "${ISSUES[@]}"; do echo "    ISSUE     : ${issue}"; done
    echo ""
  } >> "$REPORT"
}

section(){ echo -e "${BOLD}${CYAN}━━━ $1 ━━━${NC}" | tee -a "$REPORT"; echo ""; }

# ══════════════════════════════════════════════════════════════════
#  TARGETS  (replace with your own, or feed a list to the loop)
# ══════════════════════════════════════════════════════════════════
section "SECTION 1 — EXPIRED SSL CERTIFICATES"
check_ssl "172.22.100.138" "443"
check_ssl "172.22.100.140" "443"
check_ssl "172.22.100.88"  "8089"

section "SECTION 2 — EXPIRING SOON"
check_ssl "172.16.100.90"  "7551"
check_ssl "172.16.101.164" "7551"
check_ssl "172.16.101.32"  "7551"
check_ssl "172.16.101.7"   "7551"
check_ssl "172.16.101.88"  "7551"
check_ssl "172.17.100.24"  "7551"
check_ssl "172.17.150.10"  "7551"
check_ssl "172.21.100.101" "7552"
check_ssl "172.21.100.104" "7552"
check_ssl "172.21.100.72"  "7552"
check_ssl "172.21.100.81"  "7552"
check_ssl "172.22.100.25"  "7552"

section "SECTION 3 — WEAK SHA-1 HASHING"
check_ssl "172.17.99.19"   "443"
check_ssl "172.17.99.22"   "443"
check_ssl "172.22.100.21"  "443"
check_ssl "172.22.100.25"  "443"
check_ssl "172.22.100.28"  "443"
check_ssl "172.22.100.36"  "443"
check_ssl "172.22.100.4"   "443"
check_ssl "172.22.100.44"  "17781"
check_ssl "172.22.100.44"  "17784"
check_ssl "172.22.100.44"  "443"
check_ssl "172.22.100.45"  "443"
check_ssl "172.22.100.55"  "443"
check_ssl "172.22.100.70"  "443"
check_ssl "172.22.100.78"  "443"
check_ssl "172.22.100.85"  "443"

# ── Summary ────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  SSL Certificate Summary${NC}"
echo -e "  Total checked : ${BOLD}${TOTAL}${NC}"
echo -e "  ${RED}Expired       : ${EXPIRED_COUNT}${NC}"
echo -e "  ${YELLOW}Expiring <30d : ${EXPIRING_COUNT}${NC}"
echo -e "  ${RED}Weak SHA-1    : ${SHA1_COUNT}${NC}"
echo -e "  ${GREEN}OK            : ${OK_COUNT}${NC}"
echo -e "  ${RED}No response   : ${FAIL_COUNT}${NC}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Report : ${BOLD}${REPORT}${NC}"
echo -e "${GREEN}[+]${NC} Raw log: ${BOLD}${RAW_LOG}${NC}"

{
  echo "════════════════════════════════════════════════════════"
  echo "  SUMMARY"
  echo "  Total: $TOTAL | Expired: $EXPIRED_COUNT | Expiring: $EXPIRING_COUNT | SHA-1: $SHA1_COUNT | OK: $OK_COUNT | No resp: $FAIL_COUNT"
  echo "════════════════════════════════════════════════════════"
} >> "$REPORT"
