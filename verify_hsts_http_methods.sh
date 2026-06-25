#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  AA-VAPT — Full Security Verifier
#  Checks : HSTS · TLS 1.0/1.1 · SMBv1 · HTTP Methods ·
#            Server Version Disclosure (Nginx/Apache/PHP/IIS/
#            Tomcat/MongoDB/MySQL/Redis/Elasticsearch/etc.)
#
#  Usage  : bash verify_hsts_http_methods.sh -t <target> [-p <port>]
#  Example: bash verify_hsts_http_methods.sh -t 192.168.1.10
#           bash verify_hsts_http_methods.sh -t 192.168.1.10 -p 443
# ═══════════════════════════════════════════════════════════════════
set -uo

# ── Colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Logging helpers ───────────────────────────────────────────────────
log()    { echo -e "$*";                                           }
ok()     { echo -e "  ${GREEN}[✔ PASS]${NC}  $*";                 }
warn()   { echo -e "  ${YELLOW}[! WARN]${NC}  $*";                }
vuln()   { echo -e "  ${RED}[✘ VULN]${NC}  $*";                   }
info()   { echo -e "  ${CYAN}[→ CMD ]${NC}  ${DIM}$*${NC}";       }
result() { echo -e "  ${MAGENTA}[  OUT ]${NC}  $*";               }
skip()   { echo -e "  ${DIM}[  SKIP]  $* (tool not found)${NC}";  }
has()    { command -v "$1" &>/dev/null; }

# ── Section / tool banners ────────────────────────────────────────────
section() {
  echo ""
  echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${BLUE}║  %-56s  ║${NC}\n" "$*"
  echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

tool_header() {
  # tool_header "TOOL NAME" "description"
  echo ""
  echo -e "${BOLD}${CYAN}  ┌─────────────────────────────────────────────────────┐${NC}"
  printf  "${BOLD}${CYAN}  │  🔧 %-49s│${NC}\n" "$1 — $2"
  echo -e "${BOLD}${CYAN}  └─────────────────────────────────────────────────────┘${NC}"
}

divider() { echo -e "${DIM}  ────────────────────────────────────────────────────────${NC}"; }

# ── Args ──────────────────────────────────────────────────────────────
TARGET=""; CUSTOM_PORT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET="$2"; shift 2 ;;
    -p|--port)   CUSTOM_PORT="$2";   shift 2 ;;
    *) shift ;;
  esac
done
[[ -z "$TARGET" ]] && { echo "Usage: bash $0 -t <target> [-p <port>]"; exit 1; }

# ── Output directory ──────────────────────────────────────────────────
TS=$(date +%Y%m%d_%H%M%S)
OUT="./scan_output/full_verify_${TARGET//:/_}_${TS}"
mkdir -p "$OUT"
LOG="$OUT/00_full_scan.log"       # everything
VULN_LOG="$OUT/00_VULNS.log"      # only [✘ VULN] lines
WARN_LOG="$OUT/00_WARNS.log"      # only [! WARN] lines

# ── Tee to full log AND screen ────────────────────────────────────────
exec > >(tee -a "$LOG") 2>&1

HTTP_PORTS="${CUSTOM_PORT:-80 443 8080 8443 8000 8888}"
ALL_WEB_PORTS=$(echo "$HTTP_PORTS" | tr ' ' ',')

# ═════════════════════════════════════════════════════════════════════
log ""
log "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗"
log "║        AA-VAPT — Full Security Verifier                  ║"
log "║  HSTS · TLS · SMBv1 · Methods · Version Disclosure       ║"
log "╚══════════════════════════════════════════════════════════╝${NC}"
log ""
log "  ${BOLD}Target   :${NC} $TARGET"
log "  ${BOLD}HTTP     :${NC} $HTTP_PORTS"
log "  ${BOLD}Output   :${NC} $OUT/"
log "  ${BOLD}Started  :${NC} $(date)"
log ""


# ══════════════════════════════════════════════════════════════════════
#  STEP 1 ─ PORT SCAN
# ══════════════════════════════════════════════════════════════════════
section "STEP 1 — PORT SCAN & SERVICE DETECTION"

SCAN_PORTS="$ALL_WEB_PORTS,445,139,27017,3306,5432,6379,9200,1433,5984,11211"

tool_header "nmap" "Service version + default scripts"
if has nmap; then
  info "nmap -sV -sC --open -p $SCAN_PORTS $TARGET"
  divider
  nmap -sV -sC --open -p "$SCAN_PORTS" "$TARGET" \
    -oN "$OUT/01_portscan.txt" 2>&1 | grep -v "^#\|^Nmap done\|^Starting Nmap" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  log "  ${BOLD}Open ports summary:${NC}"
  grep "open" "$OUT/01_portscan.txt" 2>/dev/null \
    | grep -v "Not shown\|filtered" \
    | while IFS= read -r L; do log "    ${GREEN}$L${NC}"; done
else
  skip "nmap"
fi


# ══════════════════════════════════════════════════════════════════════
#  STEP 2 ─ HSTS & SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════
section "STEP 2 — HSTS & HTTP SECURITY HEADERS"

SEC_HEADERS=(
  "strict-transport-security:HSTS"
  "x-frame-options:X-Frame-Options"
  "x-content-type-options:X-Content-Type-Options"
  "content-security-policy:Content-Security-Policy"
  "referrer-policy:Referrer-Policy"
  "permissions-policy:Permissions-Policy"
  "x-xss-protection:X-XSS-Protection"
  "expect-ct:Expect-CT"
)

for PORT_N in $HTTP_PORTS; do
  PROTO="http"; [[ "$PORT_N" == "443" || "$PORT_N" == "8443" ]] && PROTO="https"
  URL="${PROTO}://${TARGET}:${PORT_N}/"

  # Skip if port not responding
  if has curl; then
    RC=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || true)
    [[ "$RC" == "000" ]] && { log "  ${DIM}Port $PORT_N — no response, skipping${NC}"; continue; }
  fi

  log ""
  log "  ${BOLD}━━━ Port ${PORT_N} (${PROTO}) ━━━${NC}"
  log ""

  # ── Tool: curl (header grab) ────────────────────────────────────
  tool_header "curl -sIkL" "HTTP header grab — port $PORT_N"
  if has curl; then
    info "curl -sIkL --max-time 15 $URL"
    divider
    HOUT=$(curl -sIkL --max-time 15 "$URL" 2>/dev/null)
    echo "$HOUT" > "$OUT/02_headers_${PORT_N}.txt"
    echo "$HOUT" | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    log "  ${BOLD}Security header analysis:${NC}"
    HOUT_LC=$(echo "$HOUT" | tr '[:upper:]' '[:lower:]')
    for ENTRY in "${SEC_HEADERS[@]}"; do
      HDR="${ENTRY%%:*}"; LABEL="${ENTRY#*:}"
      if echo "$HOUT_LC" | grep -q "^${HDR}:"; then
        VAL=$(echo "$HOUT_LC" | grep "^${HDR}:" | head -1 | tr -d '\r')
        ok "${LABEL}  ➜  ${VAL}"
        if [[ "$HDR" == "strict-transport-security" ]]; then
          echo "$VAL" | grep -q "max-age=0"          && warn "HSTS max-age=0 — header present but INEFFECTIVE"
          echo "$VAL" | grep -q "includesubdomains"  && ok  "includeSubDomains: present" \
                                                      || warn "includeSubDomains: MISSING"
          echo "$VAL" | grep -q "preload"            && ok  "preload: present" \
                                                      || warn "preload: MISSING"
        fi
      else
        vuln "${LABEL}  ➜  HEADER MISSING"
      fi
    done
    # HTTP→HTTPS redirect
    if [[ "$PORT_N" == "80" ]]; then
      log ""
      log "  ${BOLD}HTTP→HTTPS redirect check:${NC}"
      REDIR=$(curl -sIk --max-time 10 "http://${TARGET}:80/" 2>/dev/null \
              | grep -i "^location:" | tr -d '\r' | head -1)
      if echo "$REDIR" | grep -qi "https://"; then
        ok "HTTP→HTTPS redirect present: $REDIR"
      else
        vuln "HTTP→HTTPS redirect MISSING — plain HTTP accessible"
      fi
    fi
  else
    skip "curl"
  fi

  # ── Tool: nmap http-security-headers ──────────────────────────
  log ""
  tool_header "nmap" "http-security-headers script — port $PORT_N"
  if has nmap; then
    info "nmap -p $PORT_N --script http-security-headers $TARGET"
    divider
    nmap -p "$PORT_N" --script http-security-headers "$TARGET" \
      -oN "$OUT/02_nmap_headers_${PORT_N}.txt" 2>&1 \
      | grep -v "^Starting\|^Nmap done\|^#" \
      | while IFS= read -r L; do result "$L"; done
    divider
  else
    skip "nmap"
  fi
done


# ══════════════════════════════════════════════════════════════════════
#  STEP 3 ─ TLS 1.0 / TLS 1.1 WEAK PROTOCOL
# ══════════════════════════════════════════════════════════════════════
section "STEP 3 — TLS 1.0 / TLS 1.1 WEAK PROTOCOL CHECK"

TLS_PORTS=""
for P in $HTTP_PORTS; do
  [[ "$P" == "80" || "$P" == "8080" || "$P" == "8000" || "$P" == "8888" ]] && continue
  TLS_PORTS="$TLS_PORTS $P"
done

for PORT_N in $TLS_PORTS; do
  log ""
  log "  ${BOLD}━━━ Port ${PORT_N} ━━━${NC}"
  log ""

  # ── Tool: openssl ─────────────────────────────────────────────
  tool_header "openssl s_client" "TLS protocol version testing — port $PORT_N"
  if has openssl; then
    for VER in tls1 tls1_1 tls1_2 tls1_3; do
      FLAG="-${VER}"; LABEL="TLS 1.0"
      [[ "$VER" == "tls1_1" ]] && LABEL="TLS 1.1"
      [[ "$VER" == "tls1_2" ]] && LABEL="TLS 1.2"
      [[ "$VER" == "tls1_3" ]] && LABEL="TLS 1.3"
      info "echo Q | openssl s_client -connect ${TARGET}:${PORT_N} ${FLAG} -servername $TARGET"
      divider
      TOUT=$(echo Q | openssl s_client -connect "${TARGET}:${PORT_N}" \
             ${FLAG} -servername "$TARGET" 2>&1)
      echo "$TOUT" | while IFS= read -r L; do result "$L"; done
      divider
      log ""
      if echo "$TOUT" | grep -q "Cipher\|CONNECTED"; then
        case "$VER" in
          tls1)   vuln "$LABEL ACCEPTED on port $PORT_N  (BEAST / CVE-2011-3389)" ;;
          tls1_1) vuln "$LABEL ACCEPTED on port $PORT_N  (Deprecated RFC 8996)" ;;
          tls1_2) ok   "$LABEL supported (minimum acceptable)" ;;
          tls1_3) ok   "$LABEL supported (best)" ;;
        esac
      else
        case "$VER" in
          tls1|tls1_1) ok   "$LABEL rejected (good)" ;;
          tls1_2|tls1_3) warn "$LABEL not supported — check server config" ;;
        esac
      fi
      log ""
    done
  else
    skip "openssl"
  fi

  # ── Tool: nmap ssl-enum-ciphers ───────────────────────────────
  tool_header "nmap" "ssl-enum-ciphers — port $PORT_N"
  if has nmap; then
    info "nmap -p $PORT_N --script ssl-enum-ciphers $TARGET"
    divider
    nmap -p "$PORT_N" --script ssl-enum-ciphers "$TARGET" \
      -oN "$OUT/03_tls_${PORT_N}.txt" 2>&1 \
      | grep -v "^Starting\|^Nmap done\|^#" \
      | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    # Grade summary
    GRADE=$(grep -oE "least strength: [A-F]" "$OUT/03_tls_${PORT_N}.txt" 2>/dev/null | head -1)
    [[ -n "$GRADE" ]] && case "$GRADE" in
      *A*) ok   "TLS grade: $GRADE" ;;
      *B*) warn "TLS grade: $GRADE — weak ciphers present" ;;
      *C*|*D*|*F*) vuln "TLS grade: $GRADE — weak/broken ciphers" ;;
    esac
    grep -E "TLSv1\.0|TLSv1\.1|SSLv" "$OUT/03_tls_${PORT_N}.txt" 2>/dev/null \
      | while IFS= read -r L; do vuln "Weak protocol in cipher list: $L"; done
  else
    skip "nmap"
  fi

  # ── Tool: testssl.sh ──────────────────────────────────────────
  TSSL=""
  has testssl    && TSSL="testssl"
  has testssl.sh && TSSL="testssl.sh"
  [[ -x /opt/testssl.sh/testssl.sh ]] && TSSL="/opt/testssl.sh/testssl.sh"

  if [[ -n "$TSSL" ]]; then
    log ""
    tool_header "testssl.sh" "Full TLS audit — port $PORT_N"
    info "$TSSL --protocols --headers --sneaky ${TARGET}:${PORT_N}"
    divider
    "$TSSL" --protocols --headers --sneaky \
      "${TARGET}:${PORT_N}" 2>&1 | tee "$OUT/03_testssl_${PORT_N}.txt" \
      | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    grep -E "CRITICAL|HIGH|MEDIUM|LOW|WARN|OK" "$OUT/03_testssl_${PORT_N}.txt" 2>/dev/null \
      | while IFS= read -r L; do
          echo "$L" | grep -qiE "CRITICAL|HIGH" && vuln "$L" || warn "$L"
        done
  fi
done


# ══════════════════════════════════════════════════════════════════════
#  STEP 4 ─ SMBv1
# ══════════════════════════════════════════════════════════════════════
section "STEP 4 — SMBv1 DETECTION (EternalBlue / MS17-010 / WannaCry)"
log ""

# ── Tool: nmap smb scripts ────────────────────────────────────────
tool_header "nmap" "smb-security-mode + smb-protocols + smb2-security-mode"
if has nmap; then
  info "nmap -p 445,139 --script smb-security-mode,smb-protocols,smb2-security-mode $TARGET"
  divider
  nmap -p 445,139 \
    --script smb-security-mode,smb-protocols,smb2-security-mode \
    "$TARGET" -oN "$OUT/04_smb.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  if grep -qi "SMBv1\|NT LM 0.12\|NT1\|dialect.*NT" "$OUT/04_smb.txt" 2>/dev/null; then
    vuln "SMBv1 DETECTED — vulnerable to EternalBlue/WannaCry (MS17-010)"
  else
    ok "SMBv1 not detected in nmap output"
  fi
  grep -E "message signing|account|guest" "$OUT/04_smb.txt" 2>/dev/null \
    | while IFS= read -r L; do warn "SMB config: $L"; done
else
  skip "nmap"
fi

# ── Tool: nmap smb-vuln-ms17-010 ─────────────────────────────────
log ""
tool_header "nmap" "smb-vuln-ms17-010 (EternalBlue direct check)"
if has nmap; then
  info "nmap -p 445 --script smb-vuln-ms17-010 $TARGET"
  divider
  nmap -p 445 --script smb-vuln-ms17-010 \
    "$TARGET" -oN "$OUT/04_ms17010.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  grep -qi "VULNERABLE\|CVE-2017-0143" "$OUT/04_ms17010.txt" 2>/dev/null \
    && vuln "MS17-010 (EternalBlue) — CONFIRMED VULNERABLE" \
    || ok   "MS17-010 — not detected as vulnerable"
else
  skip "nmap"
fi

# ── Tool: smbclient ───────────────────────────────────────────────
log ""
tool_header "smbclient" "SMB dialect negotiation"
if has smbclient; then
  info "smbclient -L //${TARGET} -N --option='client min protocol=NT1'"
  divider
  SMBO=$(smbclient -L "//${TARGET}" -N \
         --option='client min protocol=NT1' 2>&1 | head -20 || true)
  echo "$SMBO" | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  echo "$SMBO" | grep -qi "NT1\|NT LM\|Negotiated dialect.*NT" \
    && vuln "SMBv1 negotiated via smbclient" \
    || ok   "SMBv1 not negotiated by smbclient"
else
  skip "smbclient"
fi


# ══════════════════════════════════════════════════════════════════════
#  STEP 5 ─ HTTP METHODS
# ══════════════════════════════════════════════════════════════════════
section "STEP 5 — HTTP METHODS ENUMERATION (PUT/DELETE/TRACE/PATCH/WebDAV)"

DANGEROUS_METHODS=("PUT" "DELETE" "TRACE" "PATCH" "CONNECT"
                   "PROPFIND" "PROPPATCH" "MKCOL" "COPY" "MOVE" "LOCK" "UNLOCK")

for PORT_N in $HTTP_PORTS; do
  PROTO="http"; [[ "$PORT_N" == "443" || "$PORT_N" == "8443" ]] && PROTO="https"
  URL="${PROTO}://${TARGET}:${PORT_N}/"

  if has curl; then
    RC=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || true)
    [[ "$RC" == "000" ]] && { log "  ${DIM}Port $PORT_N — no response, skipping${NC}"; continue; }
  fi

  log ""
  log "  ${BOLD}━━━ Port ${PORT_N} (${PROTO}) ━━━${NC}"
  log ""

  # ── Tool: curl OPTIONS ────────────────────────────────────────
  tool_header "curl -X OPTIONS" "Allow header — port $PORT_N"
  if has curl; then
    info "curl -sk -X OPTIONS -I $URL"
    divider
    OPTS=$(curl -sk -X OPTIONS --max-time 15 -I "$URL" 2>/dev/null)
    echo "$OPTS" > "$OUT/05_methods_${PORT_N}.txt"
    echo "$OPTS" | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    ALLOW=$(echo "$OPTS" | grep -i "^allow:" | tr -d '\r' | head -1)
    if [[ -n "$ALLOW" ]]; then
      log "  ${BOLD}Allow header:${NC} ${YELLOW}$ALLOW${NC}"
      for M in "${DANGEROUS_METHODS[@]}"; do
        echo "$ALLOW" | grep -qi "\b$M\b" && vuln "Dangerous method in Allow: $M"
      done
    else
      info "No Allow header returned — probing methods manually"
    fi
  else
    skip "curl"
  fi

  # ── Tool: curl manual method probe ───────────────────────────
  log ""
  tool_header "curl" "Manual method probe (status codes) — port $PORT_N"
  if has curl; then
    log "  ${BOLD}Probing each method:${NC}"
    log ""
    for M in GET POST PUT DELETE PATCH TRACE OPTIONS HEAD CONNECT PROPFIND; do
      info "curl -sk -X $M -o /dev/null -w '%{http_code}' $URL"
      SC=$(curl -sk -X "$M" --max-time 10 -o /dev/null \
           -w "%{http_code}" "$URL" 2>/dev/null || true)
      echo "$M $SC" >> "$OUT/05_methods_${PORT_N}.txt"
      case "$M" in
        GET|POST|HEAD|OPTIONS)
          log "    ${CYAN}$M${NC}  →  HTTP $SC  ${DIM}(expected)${NC}" ;;
        TRACE)
          [[ "$SC" == "200" ]] \
            && vuln "TRACE  →  HTTP $SC  — XST (Cross-Site Tracing) possible" \
            || ok   "TRACE  →  HTTP $SC  — disabled" ;;
        PUT)
          [[ "$SC" =~ ^(200|201|204)$ ]] \
            && vuln "PUT    →  HTTP $SC  — arbitrary file upload risk" \
            || ok   "PUT    →  HTTP $SC  — disabled" ;;
        DELETE)
          [[ "$SC" =~ ^(200|204)$ ]] \
            && vuln "DELETE →  HTTP $SC  — file deletion possible" \
            || ok   "DELETE →  HTTP $SC  — disabled" ;;
        PATCH)
          [[ "$SC" =~ ^(200|204)$ ]] \
            && warn "PATCH  →  HTTP $SC  — review if expected" \
            || ok   "PATCH  →  HTTP $SC  — disabled" ;;
        *)
          [[ "$SC" =~ ^(200|201)$ ]] \
            && warn "$M  →  HTTP $SC  — enabled, review needed" \
            || ok   "$M  →  HTTP $SC  — disabled" ;;
      esac
    done
  else
    skip "curl"
  fi

  # ── Tool: nmap http-methods ───────────────────────────────────
  log ""
  tool_header "nmap" "http-methods NSE script — port $PORT_N"
  if has nmap; then
    info "nmap -p $PORT_N --script http-methods --script-args http-methods.url-path='/' $TARGET"
    divider
    nmap -p "$PORT_N" --script http-methods \
      --script-args "http-methods.url-path='/'" \
      "$TARGET" -oN "$OUT/05_nmap_methods_${PORT_N}.txt" 2>&1 \
      | grep -v "^Starting\|^Nmap done\|^#" \
      | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    grep -E "Supported|Potentially risky|PUT|DELETE|TRACE|PATCH|PROPFIND" \
      "$OUT/05_nmap_methods_${PORT_N}.txt" 2>/dev/null \
      | while IFS= read -r L; do
          echo "$L" | grep -qi "risky\|PUT\|DELETE\|TRACE" \
            && vuln "nmap http-methods: $L" \
            || warn "nmap http-methods: $L"
        done
  else
    skip "nmap"
  fi
done


# ══════════════════════════════════════════════════════════════════════
#  STEP 6 ─ SERVER VERSION DISCLOSURE
# ══════════════════════════════════════════════════════════════════════
section "STEP 6 — SERVER VERSION DISCLOSURE"

# ── 6a. Web server headers ────────────────────────────────────────
log "${BOLD}  6a — Web Server Banner (Nginx / Apache / IIS / PHP / Tomcat)${NC}"
log ""

for PORT_N in $HTTP_PORTS; do
  PROTO="http"; [[ "$PORT_N" == "443" || "$PORT_N" == "8443" ]] && PROTO="https"
  URL="${PROTO}://${TARGET}:${PORT_N}/"

  if has curl; then
    RC=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || true)
    [[ "$RC" == "000" ]] && continue
  fi

  log ""
  log "  ${BOLD}━━━ Port ${PORT_N} ━━━${NC}"
  log ""

  # ── Tool: curl normal request ─────────────────────────────────
  tool_header "curl -sIkL" "Banner headers — port $PORT_N"
  if has curl; then
    info "curl -sIkL --max-time 15 $URL"
    divider
    HOUT=$(curl -sIkL --max-time 15 "$URL" 2>/dev/null)
    echo "$HOUT" > "$OUT/06a_banner_${PORT_N}.txt"
    echo "$HOUT" | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    log "  ${BOLD}Version-leaking header analysis:${NC}"
    for HDR in "server:" "x-powered-by:" "x-aspnet-version:" "x-aspnetmvc-version:" \
               "x-generator:" "via:" "x-backend:" "x-drupal-cache:" "x-varnish:"; do
      VAL=$(echo "$HOUT" | grep -i "^${HDR}" | tr -d '\r' | head -1)
      if [[ -n "$VAL" ]]; then
        echo "$VAL" | grep -qE "[0-9]+\.[0-9]+" \
          && vuln "VERSION EXPOSED (port $PORT_N): $VAL" \
          || warn "HEADER PRESENT (port $PORT_N): $VAL"
      fi
    done
  fi

  # ── Tool: curl 404 error page ─────────────────────────────────
  log ""
  tool_header "curl" "404 error page banner leak — port $PORT_N"
  if has curl; then
    info "curl -sik ${URL}aa_vapt_404test  (force error page)"
    divider
    EOUT=$(curl -sik --max-time 10 "${URL}aa_vapt_404test" 2>/dev/null | head -50)
    echo "$EOUT" > "$OUT/06a_404_${PORT_N}.txt"
    echo "$EOUT" | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    for P in "nginx/" "Apache/" "Apache-Coyote/" "Microsoft-IIS/" "Jetty/" \
             "Tomcat/" "PHP/" "Python/" "Ruby/" "OpenResty/"; do
      FOUND=$(echo "$EOUT" | grep -oi "${P}[0-9.]*" | head -1)
      [[ -n "$FOUND" ]] && vuln "ERROR PAGE EXPOSES version: $FOUND (port $PORT_N)"
    done
  fi

  # ── Tool: nmap version scan ───────────────────────────────────
  log ""
  tool_header "nmap -sV" "Aggressive version detection — port $PORT_N"
  if has nmap; then
    info "nmap -p $PORT_N -sV --version-intensity 9 --script http-server-header,http-title,banner $TARGET"
    divider
    nmap -p "$PORT_N" -sV --version-intensity 9 \
      --script http-server-header,http-title,banner \
      "$TARGET" -oN "$OUT/06a_nmap_${PORT_N}.txt" 2>&1 \
      | grep -v "^Starting\|^Nmap done\|^#" \
      | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    grep -iE "nginx|apache|iis|tomcat|jetty|lighttpd|caddy|server" \
      "$OUT/06a_nmap_${PORT_N}.txt" 2>/dev/null \
      | while IFS= read -r L; do
          echo "$L" | grep -qE "[0-9]+\.[0-9]+" \
            && vuln "VERSION EXPOSED: $L" \
            || warn "BANNER: $L"
        done
  fi
done


# ── 6b. MongoDB ──────────────────────────────────────────────────
log ""
log "${BOLD}  6b — MongoDB (port 27017)${NC}"
log ""

tool_header "nmap" "mongodb-info + mongodb-databases"
if has nmap; then
  info "nmap -p 27017 --script mongodb-info,mongodb-databases $TARGET"
  divider
  nmap -p 27017 --script mongodb-info,mongodb-databases \
    "$TARGET" -oN "$OUT/06b_mongodb.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  if grep -q "MongoDB" "$OUT/06b_mongodb.txt" 2>/dev/null; then
    VER=$(grep -oE "MongoDB [0-9.]+" "$OUT/06b_mongodb.txt" | head -1)
    AUTH=$(grep -i "auth\|Access denied\|not authorized" "$OUT/06b_mongodb.txt" | head -1)
    [[ -n "$VER" ]] && vuln "MongoDB version exposed: $VER"
    [[ -z "$AUTH" ]] \
      && vuln "MongoDB accessible WITHOUT authentication (data exposed!)" \
      || ok   "MongoDB requires authentication"
  else
    ok "MongoDB port 27017 closed / not accessible"
  fi
else
  skip "nmap"
fi


# ── 6c. MySQL ─────────────────────────────────────────────────────
log ""
log "${BOLD}  6c — MySQL (port 3306)${NC}"
log ""

tool_header "nmap" "mysql-info + mysql-empty-password"
if has nmap; then
  info "nmap -p 3306 --script mysql-info,mysql-empty-password $TARGET"
  divider
  nmap -p 3306 --script mysql-info,mysql-empty-password \
    "$TARGET" -oN "$OUT/06c_mysql.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  grep -iE "MySQL [0-9]|version|empty.password|Valid credentials" \
    "$OUT/06c_mysql.txt" 2>/dev/null \
    | while IFS= read -r L; do
        echo "$L" | grep -qiE "version|MySQL [0-9]" \
          && vuln "MySQL: $L" \
          || warn "MySQL: $L"
      done
else
  skip "nmap"
fi


# ── 6d. Redis ─────────────────────────────────────────────────────
log ""
log "${BOLD}  6d — Redis (port 6379)${NC}"
log ""

tool_header "redis-cli" "Unauthenticated INFO server"
if has redis-cli; then
  info "redis-cli -h $TARGET -p 6379 --no-auth-warning INFO server"
  divider
  ROUT=$(redis-cli -h "$TARGET" -p 6379 --no-auth-warning INFO server 2>&1 | head -20 || true)
  echo "$ROUT" | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  echo "$ROUT" | grep -q "redis_version" \
    && vuln "Redis UNAUTHENTICATED access — server info exposed" \
    && echo "$ROUT" | grep -E "redis_version|os:|tcp_port" \
       | while IFS= read -r L; do vuln "  Redis: $L"; done \
    || ok "Redis requires auth or not accessible"
else
  skip "redis-cli"
fi

log ""
tool_header "nmap" "redis-info script"
if has nmap; then
  info "nmap -p 6379 --script redis-info $TARGET"
  divider
  nmap -p 6379 --script redis-info \
    "$TARGET" -oN "$OUT/06d_redis.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  grep -iE "version|redis_version|config" "$OUT/06d_redis.txt" 2>/dev/null \
    | while IFS= read -r L; do vuln "Redis version exposed: $L"; done
else
  skip "nmap"
fi


# ── 6e. Elasticsearch ─────────────────────────────────────────────
log ""
log "${BOLD}  6e — Elasticsearch (port 9200)${NC}"
log ""

tool_header "curl" "Elasticsearch root endpoint + _cat/indices"
if has curl; then
  info "curl -sk http://${TARGET}:9200/"
  divider
  ESOUT=$(curl -sk --max-time 10 "http://${TARGET}:9200/" 2>/dev/null)
  echo "$ESOUT" | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  if echo "$ESOUT" | grep -qi "version\|cluster_name"; then
    vuln "Elasticsearch UNAUTHENTICATED access — version exposed"
    echo "$ESOUT" | grep -oE '"number"\s*:\s*"[^"]*"' \
      | while IFS= read -r L; do vuln "  ES version: $L"; done
    log ""
    info "curl -sk http://${TARGET}:9200/_cat/indices?v"
    divider
    IDXOUT=$(curl -sk --max-time 10 "http://${TARGET}:9200/_cat/indices?v" 2>/dev/null)
    echo "$IDXOUT" | head -10 | while IFS= read -r L; do result "$L"; done
    divider
    [[ -n "$IDXOUT" ]] && vuln "Elasticsearch indices accessible without auth"
  else
    ok "Elasticsearch port 9200 closed / requires auth"
  fi
else
  skip "curl"
fi


# ── 6f. Memcached ─────────────────────────────────────────────────
log ""
log "${BOLD}  6f — Memcached (port 11211)${NC}"
log ""

tool_header "nc" "Memcached stats — unauthenticated"
if has nc; then
  info "echo -e 'stats\r\nquit\r\n' | nc -w 5 $TARGET 11211"
  divider
  MCOUT=$(echo -e "stats\r\nquit\r\n" | nc -w 5 "$TARGET" 11211 2>/dev/null | head -20 || true)
  echo "$MCOUT" | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  if echo "$MCOUT" | grep -qi "STAT version"; then
    VER=$(echo "$MCOUT" | grep -i "STAT version" | awk '{print $3}' | tr -d '\r')
    vuln "Memcached UNAUTHENTICATED — version $VER (UDP amplification DRDoS risk)"
  else
    ok "Memcached port 11211 closed / not responding"
  fi
else
  skip "nc (netcat)"
fi


# ── 6g. MSSQL ─────────────────────────────────────────────────────
log ""
log "${BOLD}  6g — MSSQL (port 1433)${NC}"
log ""

tool_header "nmap" "ms-sql-info + ms-sql-empty-password"
if has nmap; then
  info "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config $TARGET"
  divider
  nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config \
    "$TARGET" -oN "$OUT/06g_mssql.txt" 2>&1 \
    | grep -v "^Starting\|^Nmap done\|^#" \
    | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  grep -iE "Version|SQL Server [0-9]|empty.password|Login" "$OUT/06g_mssql.txt" 2>/dev/null \
    | while IFS= read -r L; do
        echo "$L" | grep -qiE "version|SQL Server [0-9]" \
          && vuln "MSSQL: $L" \
          || warn "MSSQL: $L"
      done
else
  skip "nmap"
fi


# ── 6h. CouchDB ───────────────────────────────────────────────────
log ""
log "${BOLD}  6h — CouchDB (port 5984)${NC}"
log ""

tool_header "curl" "CouchDB root + _all_dbs"
if has curl; then
  info "curl -sk http://${TARGET}:5984/"
  divider
  CBOUT=$(curl -sk --max-time 10 "http://${TARGET}:5984/" 2>/dev/null)
  echo "$CBOUT" | while IFS= read -r L; do result "$L"; done
  divider
  log ""
  if echo "$CBOUT" | grep -qi "couchdb\|version"; then
    vuln "CouchDB UNAUTHENTICATED access: $CBOUT"
    info "curl -sk http://${TARGET}:5984/_all_dbs"
    DBOUT=$(curl -sk --max-time 10 "http://${TARGET}:5984/_all_dbs" 2>/dev/null)
    [[ -n "$DBOUT" ]] && vuln "CouchDB _all_dbs accessible: $DBOUT"
  else
    ok "CouchDB port 5984 closed / not responding"
  fi
else
  skip "curl"
fi


# ── 6i. PHP version ───────────────────────────────────────────────
log ""
log "${BOLD}  6i — PHP Version Disclosure${NC}"
log ""

for PORT_N in $HTTP_PORTS; do
  PROTO="http"; [[ "$PORT_N" == "443" || "$PORT_N" == "8443" ]] && PROTO="https"
  URL="${PROTO}://${TARGET}:${PORT_N}/"
  if has curl; then
    RC=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || true)
    [[ "$RC" == "000" ]] && continue

    tool_header "curl" "X-Powered-By + phpinfo.php check — port $PORT_N"
    info "curl -sIkL $URL  (checking X-Powered-By)"
    divider
    PHDR=$(curl -sIkL --max-time 10 "$URL" 2>/dev/null)
    echo "$PHDR" | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    PHP_V=$(echo "$PHDR" | grep -i "^x-powered-by:.*php" | tr -d '\r' | head -1)
    [[ -n "$PHP_V" ]] \
      && vuln "PHP version exposed via X-Powered-By (port $PORT_N): $PHP_V" \
      || ok   "X-Powered-By: PHP not exposed (port $PORT_N)"

    log ""
    info "curl -sk ${URL}phpinfo.php  (check if exposed)"
    PIOUT=$(curl -sk --max-time 10 "${URL}phpinfo.php" 2>/dev/null | head -3 || true)
    echo "$PIOUT" | while IFS= read -r L; do result "$L"; done
    echo "$PIOUT" | grep -qi "phpinfo\|PHP Version" \
      && vuln "phpinfo() accessible at ${URL}phpinfo.php" \
      || ok   "phpinfo.php not accessible (port $PORT_N)"
    log ""
  fi
done


# ══════════════════════════════════════════════════════════════════════
#  STEP 7 ─ NIKTO (if available)
# ══════════════════════════════════════════════════════════════════════
if has nikto; then
  section "STEP 7 — NIKTO WEB SCANNER"
  for PORT_N in $HTTP_PORTS; do
    PROTO="http"; [[ "$PORT_N" == "443" || "$PORT_N" == "8443" ]] && PROTO="https"
    if has curl; then
      RC=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${PROTO}://${TARGET}:${PORT_N}/" 2>/dev/null || true)
      [[ "$RC" == "000" ]] && continue
    fi
    log ""
    tool_header "nikto" "Web vulnerability scan — port $PORT_N"
    info "nikto -h $TARGET -p $PORT_N"
    divider
    nikto -h "$TARGET" -p "$PORT_N" \
      -output "$OUT/07_nikto_${PORT_N}.txt" 2>&1 \
      | while IFS= read -r L; do result "$L"; done
    divider
    log ""
    grep -iE "OSVDB|CVE|PUT|DELETE|TRACE|outdated|Header|HSTS|version" \
      "$OUT/07_nikto_${PORT_N}.txt" 2>/dev/null | head -20 \
      | while IFS= read -r L; do warn "nikto: $L"; done
  done
fi


# ══════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY — extract all VULNs and WARNs from full log
# ══════════════════════════════════════════════════════════════════════
section "FINAL SUMMARY"

# Strip ANSI codes and write clean summary files
sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep "\[✘ VULN\]" | sort -u > "$VULN_LOG"
sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep "\[! WARN\]" | sort -u > "$WARN_LOG"

VULN_COUNT=$(wc -l < "$VULN_LOG" 2>/dev/null || echo 0)
WARN_COUNT=$(wc -l < "$WARN_LOG" 2>/dev/null || echo 0)

log "${BOLD}${RED}  ✘ VULNERABILITIES FOUND : $VULN_COUNT${NC}"
[[ "$VULN_COUNT" -gt 0 ]] && cat "$VULN_LOG" | while IFS= read -r L; do
  echo -e "  ${RED}$L${NC}"
done

log ""
log "${BOLD}${YELLOW}  ! WARNINGS              : $WARN_COUNT${NC}"
[[ "$WARN_COUNT" -gt 0 ]] && cat "$WARN_LOG" | while IFS= read -r L; do
  echo -e "  ${YELLOW}$L${NC}"
done

log ""
log "${BOLD}  Output files:${NC}"
ls -1 "$OUT/"*.txt 2>/dev/null | while IFS= read -r F; do
  log "    ${DIM}$F${NC}"
done

log ""
log "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗"
log "║                    SCAN COMPLETE                         ║"
log "╚══════════════════════════════════════════════════════════╝${NC}"
log "  Target       : ${BOLD}$TARGET${NC}"
log "  Full log     : $LOG"
log "  Vulns only   : $VULN_LOG"
log "  Warnings only: $WARN_LOG"
log "  All outputs  : $OUT/"
log "  Finished     : $(date)"
log ""
log "  Legend:  ${RED}[✘ VULN]${NC} confirmed  ·  ${YELLOW}[! WARN]${NC} review needed  ·  ${GREEN}[✔ PASS]${NC} clean"
log ""
