# -*- coding: utf-8 -*-
"""
Tool Registry — Every tool the AI agent can call.

The agent (LLM) sees tool names + descriptions and picks which to call.
We execute the call and return the observation back to the agent.

Tool schema:
  name        — unique snake_case id
  description — what it does (seen by LLM — be specific!)
  parameters  — {param_name: {"type": str, "description": str, "required": bool}}
  dangerous   — True = requires human approval before execution
  category    — recon | enum | vuln | exploit | memory | report | utility
"""
from __future__ import annotations
import logging

log = logging.getLogger("aavapt.agent.tools")

# ─────────────────────────────────────────────────────────────
#  TOOL DEFINITIONS  (LLM reads these to decide what to call)
# ─────────────────────────────────────────────────────────────

TOOLS: list[dict] = [

    # ── Reconnaissance ──────────────────────────────────────
    {
        "name": "nmap_scan",
        "category": "recon",
        "dangerous": False,
        "description": (
            "Run an nmap scan on a target IP or hostname. "
            "Returns open ports, services, versions, OS guess. "
            "Use this first on any new target."
        ),
        "parameters": {
            "target":  {"type": "string",  "required": True,  "description": "IP address or hostname to scan"},
            "ports":   {"type": "string",  "required": False, "description": "Port range e.g. '22,80,443' or '1-1000' or 'top100'. Default: top100"},
            "flags":   {"type": "string",  "required": False, "description": "Extra nmap flags e.g. '-sV -O --script vuln'. Default: -sV -sC"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 120"},
        },
    },

    {
        "name": "check_ssl",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Check SSL/TLS configuration on a host:port. "
            "Detects weak ciphers, expired certs, TLS version support, "
            "HSTS, POODLE, BEAST, Heartbleed, CRIME, DROWN. "
            "Use when port 443, 8443, or any HTTPS service is found."
        ),
        "parameters": {
            "host":    {"type": "string",  "required": True,  "description": "Target hostname or IP"},
            "port":    {"type": "integer", "required": False, "description": "Port number. Default: 443"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 60"},
        },
    },

    {
        "name": "ssh_audit",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Audit SSH server configuration — checks weak algorithms (CBC, MD5, DH-group1), "
            "key exchange methods, host key types, banner grabbing. "
            "Use when port 22 or any SSH service is detected."
        ),
        "parameters": {
            "host": {"type": "string",  "required": True,  "description": "Target hostname or IP"},
            "port": {"type": "integer", "required": False, "description": "SSH port. Default: 22"},
        },
    },

    {
        "name": "http_headers_check",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Grab HTTP response headers and check for missing security headers: "
            "HSTS, CSP, X-Frame-Options, X-Content-Type-Options, CORS misconfig, "
            "server version disclosure. Use on any HTTP/HTTPS port."
        ),
        "parameters": {
            "url":     {"type": "string", "required": True,  "description": "Full URL e.g. https://192.168.1.1:8443/"},
            "timeout": {"type": "integer","required": False, "description": "Timeout seconds. Default: 15"},
        },
    },

    {
        "name": "nikto_scan",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Run Nikto web vulnerability scanner against a web server. "
            "Finds outdated software, dangerous files, misconfigurations, default pages. "
            "Slower than header check — use for deeper web analysis."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Full target URL e.g. http://192.168.1.10:80/"},
            "timeout": {"type": "integer", "required": False, "description": "Max scan time seconds. Default: 180"},
        },
    },

    {
        "name": "smb_check",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Enumerate SMB/Windows shares and check security config: "
            "SMB signing, null sessions, anonymous shares, SMBv1 support. "
            "Use when port 445 or 139 is open."
        ),
        "parameters": {
            "host": {"type": "string", "required": True, "description": "Target IP or hostname"},
        },
    },

    {
        "name": "ftp_check",
        "category": "enum",
        "dangerous": False,
        "description": "Check FTP service for anonymous login, banner, vsftpd backdoor.",
        "parameters": {
            "host": {"type": "string",  "required": True,  "description": "Target IP or hostname"},
            "port": {"type": "integer", "required": False, "description": "FTP port. Default: 21"},
        },
    },

    # ── Vulnerability Analysis ───────────────────────────────
    {
        "name": "analyze_finding",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Ask the AI to deeply analyze a specific Nessus finding. "
            "Returns verdict (confirmed/fp/needs-more), confidence score, "
            "indicators, next steps. Use to validate individual findings."
        ),
        "parameters": {
            "finding_name":   {"type": "string", "required": True,  "description": "Name of the finding/vulnerability"},
            "plugin_id":      {"type": "string", "required": False, "description": "Nessus plugin ID"},
            "severity":       {"type": "string", "required": False, "description": "critical/high/medium/low/info"},
            "synopsis":       {"type": "string", "required": False, "description": "Brief description"},
            "plugin_output":  {"type": "string", "required": False, "description": "Raw Nessus plugin output"},
            "host":           {"type": "string", "required": False, "description": "Target host"},
        },
    },

    {
        "name": "detect_attack_chains",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Analyze ALL loaded findings together to detect multi-step attack chains. "
            "Individual Medium findings may combine into CRITICAL attack paths: "
            "LLMNR→SMB Relay, Kerberoasting, Pass-the-Hash, SSL MITM, etc. "
            "Always run this after loading a Nessus scan."
        ),
        "parameters": {
            "narrate": {"type": "boolean", "required": False, "description": "Generate LLM narrative for each chain. Default: true"},
        },
    },

    {
        "name": "epss_check",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Check EPSS (Exploit Prediction Scoring System) probability and CISA KEV "
            "(Known Exploited Vulnerabilities) status for a list of CVEs. "
            "Returns exploit probability score and whether actively exploited in wild."
        ),
        "parameters": {
            "cves": {"type": "array", "required": True, "description": "List of CVE IDs e.g. ['CVE-2024-6387', 'CVE-2023-44487']"},
        },
    },

    # ── Memory & Knowledge ───────────────────────────────────
    {
        "name": "search_memory",
        "category": "memory",
        "dangerous": False,
        "description": (
            "Search past verified findings in RAG memory (ChromaDB). "
            "Returns similar findings from previous scans with verdicts and confidence. "
            "Use to check if a finding was seen before and how it was classified."
        ),
        "parameters": {
            "query":     {"type": "string",  "required": True,  "description": "Search query e.g. 'SMB signing disabled' or 'CVE-2024-6387'"},
            "n_results": {"type": "integer", "required": False, "description": "Max results to return. Default: 5"},
        },
    },

    {
        "name": "get_loaded_findings",
        "category": "memory",
        "dangerous": False,
        "description": (
            "Get all findings currently loaded from the Nessus scan. "
            "Returns count, severity breakdown, and top findings. "
            "Use at start to understand what scan data is available."
        ),
        "parameters": {
            "severity_filter": {"type": "string", "required": False, "description": "Filter by severity: critical/high/medium/low/info/all. Default: all"},
            "limit":           {"type": "integer","required": False, "description": "Max findings to return. Default: 50"},
        },
    },

    {
        "name": "search_findings",
        "category": "memory",
        "dangerous": False,
        "description": "Search loaded scan findings by keyword, IP, port, CVE, or service name.",
        "parameters": {
            "query": {"type": "string",  "required": True,  "description": "Search term"},
            "limit": {"type": "integer", "required": False, "description": "Max results. Default: 20"},
        },
    },

    # ── Exploit / Dangerous ──────────────────────────────────
    {
        "name": "generate_poc_script",
        "category": "exploit",
        "dangerous": False,
        "description": (
            "Generate a ready-to-run Bash PoC (Proof of Concept) script for a detected attack chain. "
            "Script uses Responder, ntlmrelayx, impacket, GetUserSPNs, etc. "
            "Returns the script text — does NOT execute it."
        ),
        "parameters": {
            "chain_id":       {"type": "string", "required": True,  "description": "Chain ID e.g. 'smb_relay_ntlm', 'kerberoasting_path'"},
            "affected_hosts": {"type": "array",  "required": False, "description": "Target host IPs for the PoC script"},
        },
    },

    {
        "name": "brute_force_ssh",
        "category": "exploit",
        "dangerous": True,  # ← requires human approval
        "description": (
            "Run hydra SSH brute force against target with a wordlist. "
            "DANGEROUS: generates significant log noise, may lock accounts. "
            "REQUIRES HUMAN APPROVAL before execution."
        ),
        "parameters": {
            "host":     {"type": "string", "required": True,  "description": "Target IP"},
            "port":     {"type": "integer","required": False, "description": "SSH port. Default: 22"},
            "wordlist": {"type": "string", "required": False, "description": "Wordlist path. Default: /usr/share/wordlists/rockyou.txt"},
            "username": {"type": "string", "required": False, "description": "Username to test. Default: root"},
        },
    },

    {
        "name": "run_metasploit_module",
        "category": "exploit",
        "dangerous": True,  # ← requires human approval
        "description": (
            "Run a Metasploit module against a target. "
            "DANGEROUS: may cause crashes, RCE, or service disruption. "
            "REQUIRES HUMAN APPROVAL before execution."
        ),
        "parameters": {
            "module":  {"type": "string", "required": True,  "description": "MSF module path e.g. 'exploit/windows/smb/ms17_010_eternalblue'"},
            "target":  {"type": "string", "required": True,  "description": "Target IP"},
            "port":    {"type": "integer","required": False, "description": "Target port"},
            "options": {"type": "object", "required": False, "description": "Additional module options as key-value dict"},
        },
    },

    # ── Reporting ────────────────────────────────────────────
    {
        "name": "generate_report",
        "category": "report",
        "dangerous": False,
        "description": (
            "Generate a comprehensive penetration test report from all findings, "
            "attack chains, and analysis results. "
            "Includes executive summary, technical findings, risk ratings, remediation steps."
        ),
        "parameters": {
            "format":    {"type": "string", "required": False, "description": "Output format: markdown/html/json. Default: markdown"},
            "scan_name": {"type": "string", "required": False, "description": "Name for this engagement. Default: 'VAPT Report'"},
        },
    },

    {
        "name": "executive_summary",
        "category": "report",
        "dangerous": False,
        "description": "Generate a management-level executive summary of all findings (non-technical, business impact focused).",
        "parameters": {
            "audience": {"type": "string", "required": False, "description": "Target audience: executive/technical. Default: executive"},
        },
    },

    # ── Web App Attack Tools ─────────────────────────────────
    {
        "name": "whatweb_scan",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Identify web technologies, CMS, frameworks, server software on a URL. "
            "Detects WordPress, Joomla, PHP version, jQuery, Apache/Nginx version, etc. "
            "Use before deeper web scanning to fingerprint the stack."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL e.g. http://192.168.1.10/"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "gobuster_scan",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Directory/file brute-force enumeration with gobuster. "
            "Finds hidden paths, admin panels, backup files, APIs, config files. "
            "Use on HTTP services to discover hidden content."
        ),
        "parameters": {
            "url":       {"type": "string",  "required": True,  "description": "Target base URL e.g. http://10.0.0.5/"},
            "wordlist":  {"type": "string",  "required": False, "description": "Wordlist path. Default: /usr/share/wordlists/dirb/common.txt"},
            "extensions":{"type": "string",  "required": False, "description": "File extensions to check e.g. 'php,txt,html'. Default: php,html,txt"},
            "threads":   {"type": "integer", "required": False, "description": "Number of threads. Default: 20"},
            "timeout":   {"type": "integer", "required": False, "description": "Timeout seconds. Default: 120"},
        },
    },

    {
        "name": "ffuf_scan",
        "category": "enum",
        "dangerous": False,
        "description": (
            "Fast web fuzzer (ffuf) for directory discovery and parameter fuzzing. "
            "Faster than gobuster, supports virtual host fuzzing, POST body fuzzing. "
            "Use when gobuster is too slow or for API endpoint discovery."
        ),
        "parameters": {
            "url":      {"type": "string",  "required": True,  "description": "Target URL with FUZZ keyword e.g. http://10.0.0.5/FUZZ"},
            "wordlist": {"type": "string",  "required": False, "description": "Wordlist path. Default: /usr/share/wordlists/dirb/common.txt"},
            "method":   {"type": "string",  "required": False, "description": "HTTP method: GET/POST. Default: GET"},
            "timeout":  {"type": "integer", "required": False, "description": "Timeout seconds. Default: 60"},
        },
    },

    {
        "name": "nuclei_scan",
        "category": "vuln",
        "dangerous": False,        "description": (
            "Run Nuclei vulnerability scanner with community templates. "
            "Detects CVEs, misconfigurations, exposed panels, default creds, XSS, SSRF, etc. "
            "One of the most powerful automated web vuln scanners. Use after HTTP enumeration."
        ),
        "parameters": {
            "target":    {"type": "string",  "required": True,  "description": "Target URL or IP e.g. http://10.0.0.5/ or 10.0.0.5"},
            "templates": {"type": "string",  "required": False, "description": "Template category: cves/misconfiguration/default-logins/exposures/all. Default: cves,misconfiguration"},
            "timeout":   {"type": "integer", "required": False, "description": "Timeout seconds. Default: 180"},
        },
    },

    {
        "name": "subfinder_scan",
        "category": "recon",
        "dangerous": False,
        "description": (
            "Passive subdomain enumeration using subfinder. "
            "Discovers subdomains via certificate transparency, DNS records, and public sources. "
            "Use when target is a domain name to find additional attack surface."
        ),
        "parameters": {
            "domain":   {"type": "string",  "required": True,  "description": "Target domain e.g. example.com"},
            "timeout":  {"type": "integer", "required": False, "description": "Timeout seconds. Default: 60"},
        },
    },

    {
        "name": "sqlmap_scan",
        "category": "vuln",
        "dangerous": True,
        "description": (
            "Automated SQL injection detection and exploitation with sqlmap. "
            "Tests forms, parameters, cookies for SQL injection. Can dump databases. "
            "DANGEROUS — always requires human approval."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with parameter e.g. http://10.0.0.5/login.php?id=1"},
            "data":    {"type": "string",  "required": False, "description": "POST data e.g. username=admin&pass=test"},
            "level":   {"type": "integer", "required": False, "description": "Test level 1-5. Default: 1"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 120"},
        },
    },

    {
        "name": "xss_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Test for reflected and stored Cross-Site Scripting (XSS) vulnerabilities. "
            "Injects common XSS payloads into URL parameters and form fields. "
            "Use on web apps after directory enumeration finds forms/parameters."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with parameter e.g. http://10.0.0.5/search?q=test"},
            "param":   {"type": "string",  "required": False, "description": "Specific parameter to test. Default: tests all params"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "sqli_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Quick manual SQL injection probe — tests common payloads to detect SQLi. "
            "Faster than sqlmap, good for initial detection. Does NOT exploit, just detects. "
            "Use before sqlmap_scan to confirm SQLi is present."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with parameter"},
            "param":   {"type": "string",  "required": False, "description": "Parameter name to test"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "lfi_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Test for Local File Inclusion (LFI) vulnerabilities. "
            "Tries common traversal payloads to read /etc/passwd and other sensitive files. "
            "Use when URL parameters accept file paths or include directives."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with file parameter e.g. http://10.0.0.5/page.php?file=home"},
            "param":   {"type": "string",  "required": False, "description": "Parameter to test. Default: auto-detect"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "ssrf_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Test for Server-Side Request Forgery (SSRF) vulnerabilities. "
            "Checks if server fetches attacker-controlled URLs via parameters. "
            "Use on web apps that fetch remote resources (image URLs, webhooks, etc.)."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with parameter that accepts URLs"},
            "param":   {"type": "string",  "required": False, "description": "Parameter to test for SSRF"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "cors_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Test for CORS (Cross-Origin Resource Sharing) misconfigurations. "
            "Checks if server reflects arbitrary Origin headers, allowing cross-origin attacks. "
            "Use on APIs and web apps that serve authenticated data."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL e.g. http://10.0.0.5/api/data"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 15"},
        },
    },

    {
        "name": "cmd_injection_test",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Test for OS command injection vulnerabilities. "
            "Injects shell metacharacters into parameters to detect command execution. "
            "Use on forms/parameters that might pass input to system commands."
        ),
        "parameters": {
            "url":     {"type": "string",  "required": True,  "description": "Target URL with injectable parameter"},
            "param":   {"type": "string",  "required": False, "description": "Parameter name to test"},
            "timeout": {"type": "integer", "required": False, "description": "Timeout seconds. Default: 30"},
        },
    },

    {
        "name": "jwt_analyze",
        "category": "vuln",
        "dangerous": False,
        "description": (
            "Analyze JWT tokens for vulnerabilities: alg:none, weak secrets, RS256→HS256 confusion. "
            "Decodes and checks JWT from cookies or Authorization headers. "
            "Use when target app uses JWT authentication."
        ),
        "parameters": {
            "token":  {"type": "string",  "required": True,  "description": "JWT token string to analyze"},
            "secret": {"type": "string",  "required": False, "description": "Known secret to verify signature (optional)"},
        },
    },

]  # END TOOLS


# ─────────────────────────────────────────────────────────────
#  Helpers for agent / API
# ─────────────────────────────────────────────────────────────

def get_tool(name: str) -> dict | None:
    """Return tool definition by name."""
    for t in TOOLS:
        if t["name"] == name:
            return t
    return None


def is_dangerous(name: str) -> bool:
    """Return True if tool requires human approval."""
    t = get_tool(name)
    return bool(t and t.get("dangerous"))


def tools_by_category(category: str) -> list[dict]:
    """Filter tools by category."""
    return [t for t in TOOLS if t.get("category") == category]


def get_tool_schema_for_ollama() -> list[dict]:
    """
    Convert TOOLS into Ollama's tool_calls schema format.
    Each tool becomes: {type: function, function: {name, description, parameters}}
    """
    result = []
    for t in TOOLS:
        params_schema: dict = {"type": "object", "properties": {}, "required": []}
        for pname, pdef in (t.get("parameters") or {}).items():
            params_schema["properties"][pname] = {
                "type": pdef.get("type", "string"),
                "description": pdef.get("description", ""),
            }
            if pdef.get("required"):
                params_schema["required"].append(pname)
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": params_schema,
            }
        })
    return result


# Backwards-compat alias used by some modules
TOOL_REGISTRY = get_tool_schema_for_ollama()


def get_all_tools() -> list[dict]:
    """Return all tool definitions (used by react_loop._build_tool_schemas)."""
    return TOOLS


def get_dangerous_tools() -> list[str]:
    """Return names of all tools that require HITL approval."""
    return [t["name"] for t in TOOLS if t.get("dangerous")]
"dangerous")]
