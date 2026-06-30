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

    # ── Utility ──────────────────────────────────────────────
    {
        "name": "ask_human",
        "category": "utility",
        "dangerous": False,
        "description": (
            "Ask the human operator a question when the agent needs clarification, "
            "missing information, or a decision before proceeding. "
            "Use when target scope is unclear, credentials needed, or permission uncertain."
        ),
        "parameters": {
            "question": {"type": "string", "required": True,  "description": "The question to ask the human"},
            "options":  {"type": "array",  "required": False, "description": "Optional predefined answer choices"},
        },
    },

    {
        "name": "think",
        "category": "utility",
        "dangerous": False,
        "description": (
            "Internal reasoning step — use to think through findings, plan next actions, "
            "or explain conclusions without calling an external tool. "
            "Output is shown to the user as agent reasoning."
        ),
        "parameters": {
            "thought": {"type": "string", "required": True, "description": "What you are thinking / reasoning about"},
        },
    },

    {
        "name": "finish",
        "category": "utility",
        "dangerous": False,
        "description": (
            "Signal that the agent has completed the task. "
            "Provide a final answer summarizing all findings, conclusions, and recommendations. "
            "ALWAYS call this as the last action."
        ),
        "parameters": {
            "answer": {"type": "string", "required": True, "description": "Final answer / summary for the user"},
        },
    },
]

# ─────────────────────────────────────────────────────────────
#  Lookup helpers
# ─────────────────────────────────────────────────────────────

_TOOL_MAP: dict[str, dict] = {t["name"]: t for t in TOOLS}


def get_tool(name: str) -> dict | None:
    return _TOOL_MAP.get(name)


def get_all_tools() -> list[dict]:
    return TOOLS


def is_dangerous(name: str) -> bool:
    t = _TOOL_MAP.get(name)
    return bool(t and t.get("dangerous"))


def tools_prompt() -> str:
    """Format all tools as a compact string for the LLM system prompt."""
    lines = []
    for t in TOOLS:
        params = ", ".join(
            f"{k}({'required' if v['required'] else 'optional'})"
            for k, v in t.get("parameters", {}).items()
        )
        lines.append(f"  [{t['category']}] {t['name']}({params})\n    → {t['description']}")
    return "\n\n".join(lines)
