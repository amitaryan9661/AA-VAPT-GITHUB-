"""
SOAR Playbooks — Pre-defined response workflows per vulnerability type.
Each playbook defines: triggers, verification steps, confidence rules,
auto-verdict threshold, and remediation guidance.
"""

PLAYBOOKS: dict = {

    # ── Oracle Database ────────────────────────────────────────
    "oracle": {
        "name": "Oracle Database Assessment",
        "icon": "🔴",
        "triggers": {
            "plugin_ids": ["10658", "22073", "10335"],
            "services":   ["oracle_tnslsnr", "oracle"],
            "ports":      ["1521", "1522", "1525", "1526"]
        },
        "steps": [
            {"id": 1, "tool": "nmap",       "purpose": "Oracle TNS version via NSE",
             "cmd": "nmap -p {port} --script oracle-tns-version -sV {host}",
             "expect": ["oracle", "tnslsnr", "version", r"\d+\.\d+\.\d+"],
             "on_match": "version_detected", "weight": 30},
            {"id": 2, "tool": "nmap",       "purpose": "Oracle SID brute-force",
             "cmd": "nmap -p {port} --script oracle-sid-brute {host}",
             "expect": ["found", "orcl", "xe", "prod", "sid"],
             "on_match": "sid_found", "weight": 25},
            {"id": 3, "tool": "tnscmd10g",  "purpose": "Direct TNS version query",
             "cmd": "tnscmd10g version -h {host} -p {port}",
             "expect": ["tnslsnr", "version", r"\d+\.\d+"],
             "on_match": "version_confirmed", "weight": 30},
            {"id": 4, "tool": "odat",       "purpose": "ODAT SID guesser",
             "cmd": "odat sidguesser -s {host} -p {port}",
             "expect": ["valid", "sid", "found"],
             "on_match": "sid_confirmed", "weight": 20},
            {"id": 5, "tool": "odat",       "purpose": "Default credentials check",
             "cmd": "odat passwordguesser -s {host} -p {port} -d ORCL --accounts-file /usr/share/odat/accounts/accounts.txt",
             "expect": ["login", "success", "authenticated", "sys", "scott"],
             "on_match": "default_creds", "weight": 50, "type": "exploit"},
            {"id": 6, "tool": "metasploit", "purpose": "MSF Oracle login scanner",
             "cmd": 'msfconsole -q -x "use auxiliary/scanner/oracle/oracle_login; set RHOSTS {host}; set RPORT {port}; set SID ORCL; run; exit"',
             "expect": ["login successful", "authenticated"],
             "on_match": "msf_login", "weight": 60, "type": "exploit"},
        ],
        "auto_verdict_threshold": 70,
        "risk_level": "high",
        "remediation": [
            "Filter TCP port 1521 to allow only authorized IPs",
            "Change all default Oracle credentials (sys, system, scott, dbsnmp)",
            "Disable remote TNS listener registration",
            "Apply latest Oracle CPU (Critical Patch Update)"
        ],
        "cve_searches": ["oracle database default password", "oracle tnslsnr cve"]
    },

    # ── SMB / Windows ──────────────────────────────────────────
    "smb": {
        "name": "SMB / Windows Assessment",
        "icon": "🟠",
        "triggers": {
            "plugin_ids": ["57608", "70658", "10394", "11011"],
            "services":   ["microsoft-ds", "netbios-ssn", "smb"],
            "ports":      ["445", "139"]
        },
        "steps": [
            {"id": 1, "tool": "nmap",          "purpose": "SMB vulnerability scripts",
             "cmd": "nmap -p 445,139 --script smb-vuln-* {host}",
             "expect": ["vulnerable", "CVE-2017-0144", "MS17-010", "eternalblue"],
             "on_match": "smb_vuln", "weight": 80, "type": "exploit"},
            {"id": 2, "tool": "nmap",          "purpose": "SMB enumeration",
             "cmd": "nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery {host}",
             "expect": ["disk", "ipc", "admin", "user"],
             "on_match": "smb_enum", "weight": 30},
            {"id": 3, "tool": "enum4linux",    "purpose": "Full SMB enumeration",
             "cmd": "enum4linux -a {host}",
             "expect": ["user:", "share", "workgroup", "os:"],
             "on_match": "enum4linux_data", "weight": 35},
            {"id": 4, "tool": "smbmap",        "purpose": "SMB null session access",
             "cmd": "smbmap -H {host} -u '' -p ''",
             "expect": ["read", "write", "disk"],
             "on_match": "null_session", "weight": 50},
            {"id": 5, "tool": "crackmapexec",  "purpose": "SMB signing check",
             "cmd": "crackmapexec smb {host} --shares -u '' -p ''",
             "expect": ["signing:false", "shares", "smb"],
             "on_match": "cme_data", "weight": 25},
        ],
        "auto_verdict_threshold": 65,
        "risk_level": "critical",
        "remediation": [
            "Apply MS17-010 patch immediately",
            "Disable SMBv1 protocol",
            "Enable SMB signing",
            "Restrict null session access"
        ],
        "cve_searches": ["CVE-2017-0144", "MS17-010 EternalBlue"]
    },

    # ── SSH ────────────────────────────────────────────────────
    "ssh": {
        "name": "SSH Service Assessment",
        "icon": "🔵",
        "triggers": {
            "plugin_ids": ["10267", "70657", "153953"],
            "services":   ["ssh"],
            "ports":      ["22", "2222"]
        },
        "steps": [
            {"id": 1, "tool": "ssh-audit",     "purpose": "SSH security audit",
             "cmd": "ssh-audit {host}",
             "expect": ["fail", "warn", "cve", "weak"],
             "on_match": "ssh_weak", "weight": 40},
            {"id": 2, "tool": "nmap",          "purpose": "SSH auth methods",
             "cmd": "nmap -p {port} --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos {host}",
             "expect": ["password", "publickey", "keyboard-interactive"],
             "on_match": "password_auth", "weight": 30},
            {"id": 3, "tool": "nmap",          "purpose": "SSH version check",
             "cmd": "nmap -p {port} -sV {host}",
             "expect": ["openssh", r"\d+\.\d+"],
             "on_match": "version_found", "weight": 20},
        ],
        "auto_verdict_threshold": 60,
        "risk_level": "medium",
        "remediation": [
            "Disable password authentication, use key-based auth only",
            "Update OpenSSH to latest version",
            "Disable weak algorithms (DES, RC4, MD5)",
            "Enable fail2ban or similar brute-force protection"
        ],
        "cve_searches": ["openssh vulnerabilities 2024 2025"]
    },

    # ── HTTP / Web ─────────────────────────────────────────────
    "web": {
        "name": "Web Service Assessment",
        "icon": "🌐",
        "triggers": {
            "plugin_ids": ["10107", "10386", "11213"],
            "services":   ["http", "https", "www"],
            "ports":      ["80", "443", "8080", "8443", "8000"]
        },
        "steps": [
            {"id": 1, "tool": "whatweb",       "purpose": "Technology fingerprint",
             "cmd": "whatweb -a 3 http://{host}:{port}/",
             "expect": ["apache", "nginx", "iis", "php", "wordpress", "jquery"],
             "on_match": "tech_found", "weight": 20},
            {"id": 2, "tool": "nikto",         "purpose": "Web vulnerability scan",
             "cmd": "nikto -h {host} -p {port} -nointeractive",
             "expect": ["osvdb", "cve", "vulnerable", "outdated"],
             "on_match": "nikto_vuln", "weight": 50},
            {"id": 3, "tool": "nmap",          "purpose": "HTTP vuln scripts",
             "cmd": "nmap -p {port} --script http-vuln*,http-shellshock {host}",
             "expect": ["vulnerable", "shellshock", "slowloris"],
             "on_match": "http_vuln", "weight": 60, "type": "exploit"},
            {"id": 4, "tool": "curl",          "purpose": "Security headers check",
             "cmd": "curl -sIL http://{host}:{port}/ | grep -iE 'x-frame|content-security|strict-transport|server:|x-powered'",
             "expect": ["server:", "x-powered-by", "apache", "nginx"],
             "on_match": "headers_found", "weight": 15},
        ],
        "auto_verdict_threshold": 60,
        "risk_level": "medium",
        "remediation": [
            "Update web server and framework to latest versions",
            "Add security headers (CSP, HSTS, X-Frame-Options)",
            "Remove version disclosure from Server header",
            "Implement WAF protection"
        ],
        "cve_searches": ["web server vulnerability 2024"]
    },

    # ── FTP ────────────────────────────────────────────────────
    "ftp": {
        "name": "FTP Service Assessment",
        "icon": "📁",
        "triggers": {
            "plugin_ids": ["10079", "10085"],
            "services":   ["ftp", "ftps"],
            "ports":      ["21", "990"]
        },
        "steps": [
            {"id": 1, "tool": "nmap",   "purpose": "FTP vulnerability + anon check",
             "cmd": "nmap -p {port} --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln* {host}",
             "expect": ["anonymous", "ftp login ok", "vulnerable"],
             "on_match": "ftp_anon", "weight": 70, "type": "exploit"},
        ],
        "auto_verdict_threshold": 60,
        "risk_level": "high",
        "remediation": [
            "Disable anonymous FTP access",
            "Use SFTP or FTPS instead of plain FTP",
            "Apply filesystem access controls"
        ],
        "cve_searches": ["ftp anonymous access vulnerability"]
    },

    # ── Default / Generic ──────────────────────────────────────
    "default": {
        "name": "Generic Assessment",
        "icon": "⚪",
        "triggers": {"plugin_ids": [], "services": [], "ports": []},
        "steps": [
            {"id": 1, "tool": "nmap", "purpose": "Service version detection",
             "cmd": "nmap -sV -sC -p {port} {host}",
             "expect": ["open", "version"],
             "on_match": "service_found", "weight": 20},
            {"id": 2, "tool": "nmap", "purpose": "Vulnerability scripts",
             "cmd": "nmap --script vuln -p {port} {host}",
             "expect": ["vulnerable", "cve"],
             "on_match": "vuln_found", "weight": 50},
        ],
        "auto_verdict_threshold": 65,
        "risk_level": "low",
        "remediation": ["Apply latest patches", "Restrict access to authorized IPs only"],
        "cve_searches": []
    }
}


def get_playbook(plugin_id: str, service: str, port: str) -> dict:
    """Return the best matching playbook for a finding."""
    svc = (service or "").lower()
    port_str = str(port or "")
    for pb in PLAYBOOKS.values():
        t = pb.get("triggers", {})
        if (plugin_id in t.get("plugin_ids", []) or
                any(s in svc for s in t.get("services", [])) or
                port_str in t.get("ports", [])):
            return pb
    return PLAYBOOKS["default"]
