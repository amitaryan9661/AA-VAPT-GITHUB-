"""
AA-VAPT Script Generator
Parses Nessus findings and auto-generates verification bash scripts.

All generated scripts share the same conventions:
  * nmap is ALWAYS the primary tool, a second tool confirms.
  * One blank line is printed between targets (clear separation).
  * Full evidence is saved to ./aa-vapt-logs/ next to where the script runs.
  * A short, accurate summary is printed at the end.

Scripts produced:
  - verify_ssl.sh             -> nmap ssl-cert (SHA-1 + dates) -> testssl
                                 (trust / self-signed / hostname issues IGNORED)
  - verify_server_versions.sh -> nmap http-server-header -> curl (banner leak)
  - verify_ssh_weak.sh        -> nmap ssh2-enum-algos -> ssh-audit (weak crypto)

Templates use simple __TOKEN__ placeholders (no str.format brace escaping),
so the embedded bash is valid, copy-paste-ready shell as-is.
"""
from datetime import datetime
from collections import defaultdict

SSL_PLUGIN_IDS = {
    "10863", "56984", "42873", "57582", "51192", "83875", "65821",
    "94437", "104743", "135511", "121010", "78479", "20007",
    "15901", "26928", "57041", "66334", "70544", "73459", "81606",
    "84821", "84822", "69551", "149233", "156899", "138330",
}
SSL_KEYWORDS = {
    "ssl", "tls", "certificate", "cipher", "sha-1", "sha1", "expired",
    "self-signed", "transport layer", "weak cipher", "poodle", "beast",
    "heartbleed", "drown", "freak", "logjam", "rc4", "lucky13",
}
SERVER_VERSION_PLUGIN_IDS = {"10107", "48204", "11213", "10386"}
SERVER_VERSION_KEYWORDS = {
    "server version", "http server", "server header", "version disclosure",
    "banner", "server banner", "information disclosure",
}
SSH_PLUGIN_IDS = {
    "70658", "90317", "153953", "71049", "153954",
    "10881", "157188", "146919",
}
SSH_KEYWORDS = {
    "ssh weak", "cbc mode cipher", "weak mac", "weak key exchange",
    "terrapin", "diffie-hellman group1", "ssh server cbc",
    "ssh weak algorithm", "ssh protocol version 1", "weak ssh",
}
HIGH_CRIT_SEVERITIES = {"critical", "high", "medium"}


def _is_ssl_finding(f):
    pid = str(f.get("pluginId", f.get("plugin_id", "")))
    name = f.get("name", f.get("pluginName", "")).lower()
    svc = f.get("service", f.get("svc_name", "")).lower()
    # Never treat an SSH finding as SSL (the word "cipher" appears in both)
    if "ssh" in name or "ssh" in svc or pid in SSH_PLUGIN_IDS:
        return False
    return (pid in SSL_PLUGIN_IDS
            or any(k in name for k in SSL_KEYWORDS)
            or any(k in svc for k in ("https", "ssl", "tls")))


def _is_server_version_finding(f):
    pid = str(f.get("pluginId", f.get("plugin_id", "")))
    name = f.get("name", f.get("pluginName", "")).lower()
    return (pid in SERVER_VERSION_PLUGIN_IDS
            or any(k in name for k in SERVER_VERSION_KEYWORDS))


def _is_ssh_finding(f):
    pid = str(f.get("pluginId", f.get("plugin_id", "")))
    name = f.get("name", f.get("pluginName", "")).lower()
    svc = f.get("service", f.get("svc_name", "")).lower()
    return (pid in SSH_PLUGIN_IDS
            or any(k in name for k in SSH_KEYWORDS)
            or "ssh" in svc)


def _extract_ssl_hosts(findings):
    seen, hosts = set(), []
    for f in findings:
        host = f.get("host", f.get("ip", ""))
        port = str(f.get("port", "443") or "443")
        if not host or port in ("0", ""):
            continue
        if _is_ssl_finding(f):
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                hosts.append((host, port))
    return hosts


def _extract_http_hosts(findings):
    seen, hosts = set(), []
    for f in findings:
        host = f.get("host", f.get("ip", ""))
        port = str(f.get("port", "80") or "80")
        if not host or port in ("0", ""):
            continue
        if _is_server_version_finding(f):
            name = f.get("name", "")
            stype = "unknown"
            for kw in ("IIS/10", "IIS/8", "IIS/7", "IIS/6", "Apache",
                       "nginx", "HTTPAPI", "Tomcat", "lighttpd"):
                if kw.lower() in name.lower():
                    stype = kw
                    break
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                hosts.append((host, port, stype))
    return hosts


def _extract_ssh_hosts(findings):
    seen, hosts = set(), []
    for f in findings:
        host = f.get("host", f.get("ip", ""))
        port = str(f.get("port", "22") or "22")
        if not host or port in ("0", ""):
            continue
        if _is_ssh_finding(f):
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                name = f.get("name", f.get("pluginName", "Weak SSH"))
                hosts.append((host, port, name))
    return hosts


def _safe(s, n=60):
    return str(s).replace("'", "").replace('"', "")[:n]


# ======================================================================
#  SSL SCRIPT
#  Flow per target: nmap ssl-cert (PRIMARY) -> testssl --full (SECONDARY)
#                   -> openssl s_client (LAST RESORT)
#
#  Sections printed AFTER all targets run:
#    A) EXPIRED certs   — IP:port, valid-from, valid-to, days-ago
#    B) VALID certs     — IP:port, valid-from, valid-to, days-left
#    C) WEAK SHA-1      — all SSL-checked IPs in one separate block
#  IGNORED: trust errors, self-signed, hostname mismatch
# ======================================================================
_SSL_HEADER = r'''#!/usr/bin/env bash
# ================================================================
#  AA-VAPT -- SSL Certificate Checker  (Auto-generated)
#  Source scan : __SCAN__
#  Generated   : __TS__
#  Targets     : __TOTAL__
#
#  Flow per target:
#    1. nmap ssl-cert    PRIMARY    (fast, always available)
#    2. testssl --full   SECONDARY  (only if nmap gives no dates; raw log saved)
#    3. openssl s_client LAST RESORT (only if both above fail)
#
#  End-of-run sections: [A] EXPIRED  [B] VALID  [C] WEAK SHA-1
#  IGNORED: trust / self-signed / hostname mismatch
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/aa-vapt-logs"
TESTSSL_RAW_DIR="${LOG_DIR}/testssl_raw"
mkdir -p "$LOG_DIR" "$TESTSSL_RAW_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="${LOG_DIR}/ssl_cert_report_${STAMP}.txt"
TESTSSL_TIMEOUT=90
NMAP_TIMEOUT=30
OPENSSL_TIMEOUT=12

EXPIRED_COUNT=0; EXPIRING_COUNT=0; OK_COUNT=0; FAIL_COUNT=0; SHA1_COUNT=0; TOTAL=0

declare -a RES_EXPIRED=()
declare -a RES_VALID=()
declare -a RES_SHA1=()

TESTSSL=$(command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null)
[ -z "$TESTSSL" ] && [ -x "./testssl.sh/testssl.sh" ] && TESTSSL="./testssl.sh/testssl.sh"
NMAP=$(command -v nmap 2>/dev/null)
OPENSSL=$(command -v openssl 2>/dev/null)
if [ -z "$TESTSSL" ] && [ -z "$NMAP" ] && [ -z "$OPENSSL" ]; then
  echo -e "${RED}[x]${NC} No tool found. Install testssl.sh, nmap, or openssl."; exit 1
fi

echo -e "${CYAN}"
echo "  +======================================================+"
echo "  |  AA-VAPT -- SSL Certificate Checker                  |"
echo "  |  nmap (primary) -> testssl -> openssl (last resort)   |"
echo "  +======================================================+"
echo -e "${NC}"
[ -n "$NMAP" ]    && echo -e "  ${GREEN}+${NC} nmap    : $NMAP ${DIM}(primary)${NC}"
[ -n "$TESTSSL" ] && echo -e "  ${GREEN}+${NC} testssl : $TESTSSL ${DIM}(secondary)${NC}"
[ -n "$OPENSSL" ] && echo -e "  ${GREEN}+${NC} openssl : $OPENSSL ${DIM}(last resort)${NC}"
echo -e "  Targets  : ${BOLD}__TOTAL__${NC}"
echo ""

to_epoch(){
  local d="$1"; [ -z "$d" ] && { echo 0; return; }
  date -d "$d" +%s 2>/dev/null \
    || date -j -f "%b %d %H:%M:%S %Y %Z" "$d" +%s 2>/dev/null \
    || date -j -f "%Y-%m-%dT%H:%M:%S" "$d" +%s 2>/dev/null \
    || echo 0
}

fmt_date(){
  [ -z "$1" ] && { echo "unknown"; return; }
  date -d "$1" "+%Y-%m-%d" 2>/dev/null || echo "$1"
}

check_ssl(){
  local HOST="$1" PORT="$2"
  TOTAL=$((TOTAL+1))
  local NOT_BEFORE="" NOT_AFTER="" SIG_ALG="" CN="" SRC=""
  local NOUT="" TOUT="" EXPIRED_FLAG=false

  echo -e "${CYAN}${BOLD}━━━ ${HOST}:${PORT} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  # ── STEP 1: nmap ssl-cert (PRIMARY — fast, no rate limits) ───────────
  if [ -n "$NMAP" ]; then
    echo -e "  ${DIM}[1/3] nmap ssl-cert running...${NC}"
    NOUT=$(timeout "$NMAP_TIMEOUT" "$NMAP" -Pn --script ssl-cert,ssl-enum-ciphers \
           -p "$PORT" "$HOST" 2>/dev/null)
    if echo "$NOUT" | grep -q "ssl-cert:"; then
      NOT_BEFORE=$(echo "$NOUT" | grep -i "Not valid before:" | head -1 \
                   | sed -E 's/.*Not valid before:[[:space:]]*//' )
      NOT_AFTER=$(echo  "$NOUT" | grep -i "Not valid after:"  | head -1 \
                  | sed -E 's/.*Not valid after:[[:space:]]*//' )
      SIG_ALG=$(echo "$NOUT" | grep -i "Signature Algorithm:" | head -1 \
                | sed -E 's/.*Signature Algorithm:[[:space:]]*//' )
      CN=$(echo "$NOUT" | grep -oE "CN=[^,/]+" | head -1 | sed 's/CN=//' )
      if [ -n "$NOT_AFTER" ]; then
        SRC="nmap"
        echo -e "  ${DIM}    -> certificate dates found via nmap${NC}"
      else
        echo -e "  ${DIM}    -> nmap ssl-cert ran but no dates parsed${NC}"
      fi
    else
      echo -e "  ${DIM}    -> nmap: no ssl-cert output (port closed or not SSL)${NC}"
    fi
  else
    echo -e "  ${DIM}[1/3] nmap not found, skipping${NC}"
  fi

  # ── STEP 2: testssl --full (SECONDARY — only if nmap gave no dates) ──
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ]; then
    if [ -n "$TESTSSL" ]; then
      echo -e "  ${DIM}[2/3] nmap gave no dates — trying testssl...${NC}"
      local TRAW="${TESTSSL_RAW_DIR}/testssl_${HOST}_${PORT}_${STAMP}.log"
      TOUT=$(timeout "$TESTSSL_TIMEOUT" "$TESTSSL" --full --color 0 --warnings off \
             "${HOST}:${PORT}" 2>/dev/null | tee "$TRAW")
      if [ -n "$TOUT" ]; then
        local VLINE
        VLINE=$(echo "$TOUT" | grep -i "Certificate Validity")
        if [ -n "$VLINE" ]; then
          NOT_BEFORE=$(echo "$VLINE" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2})?" | head -1)
          NOT_AFTER=$(echo  "$VLINE" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2})?" | tail -1)
          echo "$VLINE" | grep -qi "expired" && EXPIRED_FLAG=true
          SRC="testssl"
          echo -e "  ${DIM}    -> certificate validity found via testssl${NC}"
        else
          echo -e "  ${DIM}    -> testssl ran but no Certificate Validity line found${NC}"
        fi
        [ -z "$SIG_ALG" ] && SIG_ALG=$(echo "$TOUT" | grep -i "Signature Algorithm" | head -1 \
                  | sed -E 's/.*Signature Algorithm[[:space:]]*//' )
        [ -z "$CN" ] && CN=$(echo "$TOUT" | grep -iE "CN=" | grep -v "Issuer" | head -1 \
             | grep -oE "CN=[^,/]+" | head -1 | sed 's/CN=//' )
      else
        echo -e "  ${DIM}    -> testssl returned no output${NC}"
      fi
    else
      echo -e "  ${DIM}[2/3] testssl not found, skipping${NC}"
    fi
  fi

  # ── STEP 3: openssl s_client (LAST RESORT — only if both above failed) ─
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ]; then
    if [ -n "$OPENSSL" ]; then
      echo -e "  ${DIM}[3/3] testssl also failed — trying openssl s_client...${NC}"
      local ORAW CX
      ORAW=$(echo Q | timeout "$OPENSSL_TIMEOUT" "$OPENSSL" s_client \
             -connect "${HOST}:${PORT}" -servername "$HOST" 2>/dev/null)
      if [ -n "$ORAW" ]; then
        CX=$(echo "$ORAW" | "$OPENSSL" x509 -noout -dates -subject -text 2>/dev/null)
        NOT_BEFORE=$(echo "$CX" | grep "notBefore" | cut -d= -f2-)
        NOT_AFTER=$(echo  "$CX" | grep "notAfter"  | cut -d= -f2-)
        [ -z "$SIG_ALG" ] && SIG_ALG=$(echo "$CX" | grep -i "Signature Algorithm" | head -1 \
                                       | awk -F': ' '{print $2}' )
        [ -z "$CN" ] && CN=$(echo "$CX" | grep "subject" | grep -oE "CN=[^,/]+" \
                             | head -1 | sed 's/CN=//' )
        if [ -n "$NOT_AFTER" ]; then
          SRC="openssl"
          echo -e "  ${DIM}    -> certificate dates found via openssl${NC}"
        else
          echo -e "  ${DIM}    -> openssl: no certificate data${NC}"
        fi
      else
        echo -e "  ${DIM}    -> openssl: no response from ${HOST}:${PORT}${NC}"
      fi
    else
      echo -e "  ${DIM}[3/3] openssl not found, skipping${NC}"
    fi
  fi

  # ── No response at all ────────────────────────────────────────────────
  if [ -z "$NOT_AFTER" ] && [ "$EXPIRED_FLAG" = false ]; then
    echo -e "  ${RED}✗ NO RESPONSE / NO CERT${NC}"
    echo ""
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  # ── Classify ──────────────────────────────────────────────────────────
  local EXP_TS NOW_TS DAYS_LEFT=9999
  local IS_EXPIRED=false IS_EXPIRING=false
  if [ -n "$NOT_AFTER" ]; then
    EXP_TS=$(to_epoch "$NOT_AFTER"); NOW_TS=$(date +%s)
    DAYS_LEFT=$(( (EXP_TS - NOW_TS) / 86400 ))
    [ $DAYS_LEFT -lt 0 ] && IS_EXPIRED=true
    [ $DAYS_LEFT -ge 0 ] && [ $DAYS_LEFT -lt 30 ] && IS_EXPIRING=true
  fi
  [ "$EXPIRED_FLAG" = true ] && IS_EXPIRED=true && IS_EXPIRING=false

  local IS_SHA1=false
  echo "$SIG_ALG" | grep -qiE "sha1|sha-1" && IS_SHA1=true

  local NB_FMT NA_FMT
  NB_FMT=$(fmt_date "$NOT_BEFORE")
  NA_FMT=$(fmt_date "$NOT_AFTER")

  # ── Live per-target terminal output ───────────────────────────────────
  if $IS_EXPIRED; then
    local DAYS_AGO="${DAYS_LEFT#-}"
    echo -e "  ${RED}✗ ${BOLD}EXPIRED${NC}  ${DIM}(via ${SRC})${NC}"
    echo -e "    Valid From : ${NB_FMT}"
    echo -e "    Valid To   : ${RED}${NA_FMT}${NC}  ${RED}(expired ${DAYS_AGO} days ago)${NC}"
    [ -n "$CN" ] && echo -e "    Subject    : CN=${CN}"
    $IS_SHA1 && echo -e "    ${YELLOW}! Weak SHA-1 signature also present${NC}"
    EXPIRED_COUNT=$((EXPIRED_COUNT+1))
    RES_EXPIRED+=("${HOST}:${PORT}|${NB_FMT}|${NA_FMT}|${DAYS_AGO}|${CN:-?}|${SRC}")
  elif $IS_EXPIRING; then
    echo -e "  ${YELLOW}! ${BOLD}EXPIRING SOON${NC}  ${DIM}(via ${SRC})${NC}"
    echo -e "    Valid From : ${NB_FMT}"
    echo -e "    Valid To   : ${YELLOW}${NA_FMT}${NC}  ${YELLOW}(${DAYS_LEFT} days left)${NC}"
    [ -n "$CN" ] && echo -e "    Subject    : CN=${CN}"
    $IS_SHA1 && echo -e "    ${YELLOW}! Weak SHA-1 also present${NC}"
    EXPIRING_COUNT=$((EXPIRING_COUNT+1))
    RES_VALID+=("${HOST}:${PORT}|${NB_FMT}|${NA_FMT}|${DAYS_LEFT}|${CN:-?}|${SRC}|EXPIRING")
  else
    echo -e "  ${GREEN}✓ ${BOLD}VALID${NC}  ${DIM}(via ${SRC})${NC}"
    echo -e "    Valid From : ${NB_FMT}"
    echo -e "    Valid To   : ${GREEN}${NA_FMT}${NC}  ${DIM}(${DAYS_LEFT} days left)${NC}"
    [ -n "$CN" ] && echo -e "    Subject    : CN=${CN}"
    $IS_SHA1 && echo -e "    ${YELLOW}! Weak SHA-1 also present${NC}"
    OK_COUNT=$((OK_COUNT+1))
    RES_VALID+=("${HOST}:${PORT}|${NB_FMT}|${NA_FMT}|${DAYS_LEFT}|${CN:-?}|${SRC}|VALID")
  fi

  if $IS_SHA1; then
    SHA1_COUNT=$((SHA1_COUNT+1))
    RES_SHA1+=("${HOST}:${PORT}|${SIG_ALG}|${CN:-?}")
  fi

  echo ""
}

'''

_SSL_FOOTER = r'''

# ══════════════════════════════════════════════════════════════════════════
#  [A] EXPIRED CERTIFICATES
# ══════════════════════════════════════════════════════════════════════════
{
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
printf "${RED}${BOLD}║  [A] EXPIRED CERTIFICATES  (%d found)%-24s║${NC}\n" "$EXPIRED_COUNT" ""
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [ ${#RES_EXPIRED[@]} -eq 0 ]; then
  echo -e "  ${GREEN}No expired certificates found.${NC}"
  echo ""
else
  for entry in "${RES_EXPIRED[@]}"; do
    IFS="|" read -r EP_HOST EP_FROM EP_TO EP_DAYS EP_CN EP_SRC <<< "$entry"
    echo -e "  ${RED}✗${NC} ${BOLD}${EP_HOST}${NC}"
    echo    "    Valid From : ${EP_FROM}"
    echo -e "    Valid To   : ${RED}${EP_TO}${NC}  ${RED}(expired ${EP_DAYS} days ago)${NC}"
    echo    "    Subject    : CN=${EP_CN}"
    echo -e "    Source     : ${DIM}${EP_SRC}${NC}"
    echo ""
  done
fi
} | tee -a "$REPORT"

# ══════════════════════════════════════════════════════════════════════════
#  [B] VALID CERTIFICATES
# ══════════════════════════════════════════════════════════════════════════
VALID_TOTAL=$(( OK_COUNT + EXPIRING_COUNT ))
{
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
printf "${GREEN}${BOLD}║  [B] VALID CERTIFICATES  (%d found)%-25s║${NC}\n" "$VALID_TOTAL" ""
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [ ${#RES_VALID[@]} -eq 0 ]; then
  echo -e "  ${DIM}No valid certificates found.${NC}"
  echo ""
else
  for entry in "${RES_VALID[@]}"; do
    IFS="|" read -r VP_HOST VP_FROM VP_TO VP_DAYS VP_CN VP_SRC VP_STATUS <<< "$entry"
    if [ "$VP_STATUS" = "EXPIRING" ]; then
      echo -e "  ${YELLOW}!${NC} ${BOLD}${VP_HOST}${NC}  ${YELLOW}(expiring soon)${NC}"
      echo    "    Valid From : ${VP_FROM}"
      echo -e "    Valid To   : ${YELLOW}${VP_TO}${NC}  ${YELLOW}(${VP_DAYS} days left)${NC}"
    else
      echo -e "  ${GREEN}✓${NC} ${BOLD}${VP_HOST}${NC}"
      echo    "    Valid From : ${VP_FROM}"
      echo -e "    Valid To   : ${GREEN}${VP_TO}${NC}  ${DIM}(${VP_DAYS} days left)${NC}"
    fi
    echo    "    Subject    : CN=${VP_CN}"
    echo -e "    Source     : ${DIM}${VP_SRC}${NC}"
    echo ""
  done
fi
} | tee -a "$REPORT"

# ══════════════════════════════════════════════════════════════════════════
#  [C] WEAK SHA-1 SIGNATURES
# ══════════════════════════════════════════════════════════════════════════
{
echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
printf "${YELLOW}${BOLD}║  [C] WEAK SHA-1 SIGNATURES  (%d found)%-22s║${NC}\n" "$SHA1_COUNT" ""
echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
if [ ${#RES_SHA1[@]} -eq 0 ]; then
  echo -e "  ${GREEN}No weak SHA-1 signatures found.${NC}"
  echo ""
else
  for entry in "${RES_SHA1[@]}"; do
    IFS="|" read -r SH_HOST SH_ALG SH_CN <<< "$entry"
    echo -e "  ${YELLOW}!${NC} ${BOLD}${SH_HOST}${NC}"
    echo -e "    Signature  : ${RED}${SH_ALG}${NC}"
    echo    "    Subject    : CN=${SH_CN}"
    echo ""
  done
fi
} | tee -a "$REPORT"

# ══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════
{
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SSL Certificate Check — Summary${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "  Total checked    : ${BOLD}${TOTAL}${NC}  ${DIM}(Nessus-reported SSL targets)${NC}"
echo    "  ──────────────────────────────────────────────────────────"
echo -e "  ${RED}Expired          : ${EXPIRED_COUNT}${NC}"
echo -e "  ${YELLOW}Expiring <30d    : ${EXPIRING_COUNT}${NC}"
echo -e "  ${GREEN}Valid            : ${OK_COUNT}${NC}"
echo -e "  ${RED}No response      : ${FAIL_COUNT}${NC}"
echo    "  ──────────────────────────────────────────────────────────"
echo -e "  ${YELLOW}Weak SHA-1       : ${SHA1_COUNT}${NC}  ${DIM}(checked across all ${TOTAL} targets)${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Report saved  : ${BOLD}${REPORT}${NC}"
echo -e "${GREEN}[+]${NC} testssl logs  : ${BOLD}${TESTSSL_RAW_DIR}/${NC}"
} | tee -a "$REPORT"
'''


def _fill(template, scan_name, total):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (template
            .replace("__SCAN__", _safe(scan_name))
            .replace("__TS__", ts)
            .replace("__TOTAL__", str(total)))


def generate_ssl_script(findings: list, scan_name: str = "scan") -> str:
    ssl_hosts = _extract_ssl_hosts(findings)
    total = len(ssl_hosts)
    if total == 0:
        return "#!/usr/bin/env bash\necho 'No SSL/TLS findings found.'\n"
    body = _fill(_SSL_HEADER, scan_name, total)
    body += f'\necho -e "  Running SSL check on {total} Nessus-reported targets..."\necho ""\n\n'
    for host, port in ssl_hosts:
        body += f'check_ssl "{host}" "{port}"\n'
    body += _SSL_FOOTER
    return body


# ======================================================================
#  SERVER VERSION SCRIPT  (nmap http-server-header -> curl)
# ======================================================================
_SV_HEADER = r'''#!/usr/bin/env bash
# ================================================================
#  AA-VAPT -- Server Version Disclosure Verification (Auto-generated)
#  Source scan : __SCAN__
#  Generated   : __TS__
#  Targets     : __TOTAL__
#  Flow: nmap http-server-header (primary) -> curl -I (secondary)
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

LOG_DIR="$(pwd)/aa-vapt-logs"; mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${LOG_DIR}/server_version_report_${STAMP}.txt"
RAW_LOG="${LOG_DIR}/server_version_raw_${STAMP}.log"
TIMEOUT=8
CONFIRMED=0; MISSING=0; TOTAL=0

NMAP=$(command -v nmap 2>/dev/null)
CURL=$(command -v curl 2>/dev/null)
if [ -z "$NMAP" ] && [ -z "$CURL" ]; then
  echo -e "${RED}[x]${NC} Install nmap or curl"; exit 1
fi

{
echo "========================================================"
echo "  AA-VAPT -- Server Version Disclosure Verification"
echo "  Scan   : __SCAN__"
echo "  Date   : $(date)"
echo "  Targets: __TOTAL__"
echo "  Engine : nmap http-server-header (primary) -> curl (secondary)"
echo "========================================================"
echo ""
} | tee "$OUT"

check_http(){
  local HOST="$1" PORT="$2" PROTO="$3"
  TOTAL=$((TOTAL+1))
  local BANNER="" SRC=""

  if [ -n "$NMAP" ]; then
    local NOUT
    NOUT=$(timeout 30 "$NMAP" -Pn -p "$PORT" --script http-server-header,http-headers "$HOST" 2>/dev/null)
    echo "######## ${HOST}:${PORT} (nmap) ########" >> "$RAW_LOG"; echo "$NOUT" >> "$RAW_LOG"
    BANNER=$(echo "$NOUT" | grep -iE "Server:|server-header:" | head -1 | sed -E 's/^[ |_]*//; s/Server: *//I')
    [ -n "$BANNER" ] && SRC="nmap"
  fi

  if [ -z "$BANNER" ] && [ -n "$CURL" ]; then
    local COUT
    COUT=$(timeout "$TIMEOUT" "$CURL" -sk -I "${PROTO}://${HOST}:${PORT}/" 2>/dev/null)
    echo "######## ${HOST}:${PORT} (curl) ########" >> "$RAW_LOG"; echo "$COUT" >> "$RAW_LOG"
    BANNER=$(echo "$COUT" | grep -iE "^server:|^x-powered-by:|^x-aspnet" | head -1 | sed -E 's/\r$//')
    [ -n "$BANNER" ] && SRC="curl"
  fi

  if [ -n "$BANNER" ]; then
    echo -e "  ${RED}X ${BOLD}${HOST}:${PORT}${NC} -- ${RED}VERSION LEAK${NC} ${DIM}(via ${SRC})${NC}"
    echo -e "    ${BANNER}"
    { echo "  [LEAK] ${HOST}:${PORT}  ${BANNER}"; } >> "$OUT"
    CONFIRMED=$((CONFIRMED+1))
  else
    echo -e "  ${GREEN}+ ${BOLD}${HOST}:${PORT}${NC} -- ${GREEN}no banner / no response${NC}"
    { echo "  [OK]   ${HOST}:${PORT}  no server header"; } >> "$OUT"
    MISSING=$((MISSING+1))
  fi
  echo ""
}

section(){ echo -e "${BOLD}${CYAN}--- $1 ---${NC}" | tee -a "$OUT"; echo ""; }

'''

_SV_FOOTER = r'''
echo -e "${BOLD}${CYAN}=====================================================${NC}"
echo -e "${BOLD}  Server Version Disclosure Summary${NC}"
echo -e "  Total checked : ${BOLD}${TOTAL}${NC}"
echo -e "  ${RED}Version leaks  : ${CONFIRMED}${NC}"
echo -e "  ${GREEN}No banner      : ${MISSING}${NC}"
echo -e "${BOLD}${CYAN}=====================================================${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Report : ${BOLD}${OUT}${NC}"
echo -e "${GREEN}[+]${NC} Raw log: ${BOLD}${RAW_LOG}${NC}"
{
echo "========================================================"
echo "  SUMMARY  Total: $TOTAL | Leaks: $CONFIRMED | Clean: $MISSING"
echo "========================================================"
} >> "$OUT"
'''


def generate_server_version_script(findings: list, scan_name: str = "scan") -> str:
    http_hosts = _extract_http_hosts(findings)
    total = len(http_hosts)
    if total == 0:
        return "#!/usr/bin/env bash\necho 'No server version disclosure findings.'\n"
    body = _fill(_SV_HEADER, scan_name, total)

    by_type = defaultdict(list)
    for host, port, stype in http_hosts:
        by_type[stype].append((host, port))

    https_ports = {"443", "8443", "8089", "7551", "7552", "9443"}
    for stype, hosts in sorted(by_type.items()):
        body += f'section "{_safe(stype, 40)} ({len(hosts)} targets)"\n'
        for host, port in hosts:
            proto = "https" if port in https_ports else "http"
            body += f'check_http "{host}" "{port}" "{proto}"\n'
        body += "\n"
    body += _SV_FOOTER
    return body


# ======================================================================
#  SSH SCRIPT  (nmap ssh2-enum-algos -> ssh-audit)
# ======================================================================
_SSH_HEADER = r'''#!/usr/bin/env bash
# ================================================================
#  AA-VAPT -- Weak SSH Algorithms Verification (Auto-generated)
#  Source scan : __SCAN__
#  Generated   : __TS__
#  Targets     : __TOTAL__
#  Flow: nmap ssh2-enum-algos (primary) -> ssh-audit (secondary)
#  Checks: weak ciphers (CBC/3DES/arcfour) / weak MAC / weak KEX / SSHv1
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

LOG_DIR="$(pwd)/aa-vapt-logs"; mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="${LOG_DIR}/ssh_weak_report_${STAMP}.txt"
RAW_LOG="${LOG_DIR}/ssh_weak_raw_${STAMP}.log"
TIMEOUT=30
WEAK_COUNT=0; OK_COUNT=0; FAIL_COUNT=0; TOTAL=0

NMAP=$(command -v nmap 2>/dev/null)
SSH_AUDIT=$(command -v ssh-audit 2>/dev/null)
[ -z "$SSH_AUDIT" ] && [ -x "./ssh-audit/ssh-audit.py" ] && SSH_AUDIT="python3 ./ssh-audit/ssh-audit.py"
if [ -z "$NMAP" ] && [ -z "$SSH_AUDIT" ]; then
  echo -e "${RED}[x]${NC} Install nmap (or ssh-audit)"; exit 1
fi

echo -e "${CYAN}"
echo "  +===============================================+"
echo "  |  AA-VAPT -- Weak SSH Algorithms Checker        |"
echo "  |  nmap ssh2-enum-algos -> ssh-audit             |"
echo "  +===============================================+"
echo -e "${NC}"
echo "  Targets: __TOTAL__"; echo ""

{
echo "========================================================"
echo "  AA-VAPT Weak SSH Report"
echo "  Scan   : __SCAN__"
echo "  Date   : $(date)"
echo "  Targets: __TOTAL__"
echo "  Engine : nmap ssh2-enum-algos (primary) -> ssh-audit (secondary)"
echo "========================================================"
echo ""
} | tee "$REPORT"

WEAK_CIPHER_PAT="arcfour|blowfish|cast128|3des|aes128-cbc|aes192-cbc|aes256-cbc|rijndael"
WEAK_MAC_PAT="hmac-md5|hmac-sha1-96|hmac-md5-96|umac-32|umac-64"
WEAK_KEX_PAT="diffie-hellman-group1-|diffie-hellman-group14-sha1|gss-gex-sha1|gss-group1"

check_ssh(){
  local HOST="$1" PORT="$2"
  TOTAL=$((TOTAL+1))
  local ISSUES=() SRC="" GOT=false

  if [ -n "$NMAP" ]; then
    local NOUT
    NOUT=$(timeout "$TIMEOUT" "$NMAP" -Pn -p "$PORT" --script ssh2-enum-algos "$HOST" 2>/dev/null)
    echo "######## ${HOST}:${PORT} (nmap) ########" >> "$RAW_LOG"; echo "$NOUT" >> "$RAW_LOG"
    if echo "$NOUT" | grep -q "ssh2-enum-algos"; then
      GOT=true; SRC="nmap"
      echo "$NOUT" | grep -qiE "$WEAK_CIPHER_PAT" && ISSUES+=("Weak Encryption Ciphers (CBC/3DES/arcfour)")
      echo "$NOUT" | grep -qiE "$WEAK_MAC_PAT"    && ISSUES+=("Weak MAC Algorithms (MD5 / SHA1-96)")
      echo "$NOUT" | grep -qiE "$WEAK_KEX_PAT"    && ISSUES+=("Weak Key Exchange (DH-Group1 / Group14-SHA1)")
    fi
  fi

  if [ "$GOT" = false ] && [ -n "$SSH_AUDIT" ]; then
    local AOUT
    AOUT=$(timeout "$TIMEOUT" $SSH_AUDIT -p "$PORT" "$HOST" 2>/dev/null)
    echo "######## ${HOST}:${PORT} (ssh-audit) ########" >> "$RAW_LOG"; echo "$AOUT" >> "$RAW_LOG"
    if [ -n "$AOUT" ]; then
      GOT=true; SRC="ssh-audit"
      echo "$AOUT" | grep -qiE "(warn|fail).*enc" && ISSUES+=("Weak Encryption Ciphers")
      echo "$AOUT" | grep -qiE "(warn|fail).*mac" && ISSUES+=("Weak MAC Algorithms")
      echo "$AOUT" | grep -qiE "(warn|fail).*kex" && ISSUES+=("Weak Key Exchange")
      echo "$AOUT" | grep -qiE "ssh-v1|protocol 1" && ISSUES+=("SSH Protocol v1 supported (CRITICAL)")
    fi
  fi

  if [ "$GOT" = false ]; then
    echo -e "  ${RED}X ${BOLD}${HOST}:${PORT}${NC} -- ${RED}NO RESPONSE / PORT CLOSED${NC}"; echo ""
    { echo "  [NO RESPONSE] ${HOST}:${PORT}"; echo ""; } >> "$REPORT"
    FAIL_COUNT=$((FAIL_COUNT+1)); return
  fi

  if [ ${#ISSUES[@]} -eq 0 ]; then
    echo -e "  ${GREEN}+ ${BOLD}${HOST}:${PORT}${NC} -- ${GREEN}${BOLD}NO WEAK ALGOS${NC} ${DIM}(via ${SRC})${NC}"
    { echo "  [OK] ${HOST}:${PORT} -- clean (via ${SRC})"; echo ""; } >> "$REPORT"
    OK_COUNT=$((OK_COUNT+1))
  else
    echo -e "  ${RED}X ${BOLD}${HOST}:${PORT}${NC} -- ${RED}${BOLD}WEAK SSH ALGORITHMS${NC} ${DIM}(via ${SRC})${NC}"
    for issue in "${ISSUES[@]}"; do echo -e "    ${RED}^ ${issue}${NC}"; done
    { echo "  [WEAK] ${HOST}:${PORT}  (via ${SRC})"
      for issue in "${ISSUES[@]}"; do echo "    ISSUE: ${issue}"; done; echo ""; } >> "$REPORT"
    WEAK_COUNT=$((WEAK_COUNT+1))
  fi
  echo ""
}

section(){ echo -e "${BOLD}${CYAN}--- $1 ---${NC}" | tee -a "$REPORT"; echo ""; }

'''

_SSH_FOOTER = r'''
echo -e "${BOLD}${CYAN}=====================================================${NC}"
echo -e "${BOLD}  Weak SSH Summary${NC}"
echo -e "  Total checked : ${BOLD}${TOTAL}${NC}"
echo -e "  ${RED}Weak SSH found : ${WEAK_COUNT}${NC}"
echo -e "  ${GREEN}No issues      : ${OK_COUNT}${NC}"
echo -e "  ${RED}No response    : ${FAIL_COUNT}${NC}"
echo -e "${BOLD}${CYAN}=====================================================${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Report : ${BOLD}${REPORT}${NC}"
echo -e "${GREEN}[+]${NC} Raw log: ${BOLD}${RAW_LOG}${NC}"
{
echo "========================================================"
echo "  SUMMARY  Total: $TOTAL | Weak: $WEAK_COUNT | OK: $OK_COUNT | No resp: $FAIL_COUNT"
echo "========================================================"
} >> "$REPORT"
'''


def generate_ssh_weak_script(findings: list, scan_name: str = "scan") -> str:
    ssh_hosts = _extract_ssh_hosts(findings)
    total = len(ssh_hosts)
    if total == 0:
        return "#!/usr/bin/env bash\necho 'No weak SSH findings found.'\n"
    body = _fill(_SSH_HEADER, scan_name, total)

    by_finding = defaultdict(list)
    for host, port, name in ssh_hosts:
        by_finding[name].append((host, port))

    for finding_name, hosts in sorted(by_finding.items()):
        body += f'section "{_safe(finding_name, 70)} ({len(hosts)})"\n'
        for host, port in hosts:
            body += f'check_ssh "{host}" "{port}"\n'
        body += "\n"
    body += _SSH_FOOTER
    return body


def generate_all_scripts(findings: list, scan_name: str = "scan") -> dict:
    ssl_hosts = _extract_ssl_hosts(findings)
    http_hosts = _extract_http_hosts(findings)
    ssh_hosts = _extract_ssh_hosts(findings)
    return {
        "ssl_script":            generate_ssl_script(findings, scan_name),
        "server_version_script": generate_server_version_script(findings, scan_name),
        "ssh_script":            generate_ssh_weak_script(findings, scan_name),
        "ssl_count":             len(ssl_hosts),
        "server_version_count":  len(http_hosts),
        "ssh_count":             len(ssh_hosts),
        "ssl_hosts":             [f"{h}:{p}" for h, p in ssl_hosts],
        "server_hosts":          [f"{h}:{p}" for h, p, _ in http_hosts],
        "ssh_hosts":             [f"{h}:{p}" for h, p, _ in ssh_hosts],
    }
