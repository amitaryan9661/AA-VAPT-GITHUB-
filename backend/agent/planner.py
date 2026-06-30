# -*- coding: utf-8 -*-
"""
Natural Language Planner
========================
Converts ANY human input into a structured agent goal + initial plan.

Examples:
  "pentest 192.168.1.50"
  → goal: "Full pentest of 192.168.1.50"
  → target: "192.168.1.50"
  → plan: [nmap_scan, check_ssl, smb_check, detect_chains, generate_report]

  "SSL check port 8443 on 10.0.0.5"
  → goal: "SSL audit on 10.0.0.5:8443"
  → target: "10.0.0.5"
  → plan: [check_ssl(port=8443)]

  "What attack chains are in the loaded scan?"
  → goal: "Detect attack chains in current scan"
  → plan: [detect_attack_chains]

The planner uses:
  1. Regex extraction for IPs, ports, CVEs
  2. Keyword intent detection (English)
  3. LLM fallback for complex/ambiguous inputs
"""
from __future__ import annotations
import re
import logging
from typing import Optional

log = logging.getLogger("aavapt.agent.planner")

# ─────────────────────────────────────────────────────────────
#  Intent keywords (English)
# ─────────────────────────────────────────────────────────────

_INTENT_MAP = {
    "full_pentest": [
        "pentest", "penetration test", "full scan", "pura scan",
        "security test", "audit", "assess", "vulnerability scan",
        "vapt", "vulnerability assessment",
    ],
    "ssl_check": [
        "ssl", "tls", "certificate", "cert", "https", "cipher",
        "ssl check", "ssl scan", "tls check",
    ],
    "ssh_check": [
        "ssh", "ssh audit", "ssh scan", "port 22",
    ],
    "web_scan": [
        "web", "http", "nikto", "webapp", "website", "web app",
        "web scan", "web vulnerability", "web vuln",
    ],
    "smb_check": [
        "smb", "samba", "windows", "netbios", "shares",
        "smb signing", "ms17", "eternalblue",
    ],
    "chain_detection": [
        "chain", "attack chain", "attack path", "chains detect",
        "multi step", "llmnr", "smb relay", "kerberoast",
    ],
    "memory_search": [
        "memory", "past", "history", "seen before",
        "search memory", "recall", "similar",
    ],
    "exploit_check": [
        "epss", "cve", "exploit", "known exploited", "kev",
        "cisa", "exploitable",
    ],
    "report": [
        "report", "generate report",
        "summary", "findings report", "executive summary",
    ],
    "findings_check": [
        "findings", "scan results",
        "vulnerabilities", "issues", "problems",
    ],
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\b(?:port\s+)?(\d{2,5})\b", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|uk|gov|edu|mil|int|xyz|dev|app|site|tech|biz|info|local|lan)\b")
# Words that look like domains but aren't targets
_DOMAIN_BLACKLIST = {"localhost", "example.com", "test.com", "http.com",
                     "https.com", "evil.local", "domain.com"}


# ─────────────────────────────────────────────────────────────
#  Main planner entry point
# ─────────────────────────────────────────────────────────────

def parse_goal(user_input: str) -> dict:
    """
    Parse natural language input into a structured plan.

    Returns:
      {
        goal:        str   — clean goal description
        target:      str   — IP/hostname if detected
        port:        int   — specific port if detected
        cves:        list  — CVE IDs if detected
        intent:      str   — detected intent category
        initial_tools: list[dict]  — ordered list of tools to try
        raw_input:   str
      }
    """
    text = user_input.strip()
    text_lower = text.lower()

    # ── Extract entities ───────────────────────────────────
    ips = _IP_RE.findall(text)
    ports_raw = _PORT_RE.findall(text)
    cves = _CVE_RE.findall(text)

    target = ips[0] if ips else ""
    # Find specific port (exclude IPs)
    port = None
    ip_str = " ".join(ips)  # all IP text to exclude
    for p in ports_raw:
        pint = int(p)
        # Valid port range, not part of any IP, not a year-like number
        if 1 <= pint <= 65535 and str(pint) not in ip_str and pint not in range(1900, 2100):
            port = pint
            break

    # If no IP, try domain (filter out blacklisted/common false positives)
    if not target:
        domains = [d for d in _DOMAIN_RE.findall(text)
                   if d.lower() not in _DOMAIN_BLACKLIST
                   and not d.lower().startswith("http")]
        if domains:
            target = domains[0]

    # ── Detect intent ──────────────────────────────────────
    intent = _detect_intent(text_lower)

    # ── Build plan ─────────────────────────────────────────
    plan = _build_plan(intent, target, port, cves, text_lower)

    # ── Clean goal string ──────────────────────────────────
    goal = _make_goal_string(intent, target, port, cves, text)

    result = {
        "goal": goal,
        "target": target,
        "port": port,
        "cves": cves,
        "intent": intent,
        "initial_tools": plan,
        "raw_input": text,
    }
    log.info("Planner: intent=%s target=%s port=%s → %d tools planned",
             intent, target or "none", port or "none", len(plan))
    return result


def _detect_intent(text: str) -> str:
    scores: dict[str, int] = {}
    for intent, keywords in _INTENT_MAP.items():
        score = sum(1 for kw in keywords if kw in text)
        if score:
            scores[intent] = score
    if not scores:
        # Has IP/domain → default to full pentest
        if _IP_RE.search(text) or _DOMAIN_RE.search(text):
            return "full_pentest"
        return "general"
    return max(scores, key=scores.__getitem__)


def _build_plan(intent: str, target: str, port: Optional[int],
                cves: list, text: str) -> list[dict]:
    """Build ordered list of tool calls based on intent."""
    tools = []

    if intent == "full_pentest" and target:
        tools = [
            {"tool": "nmap_scan",         "args": {"target": target}},
            {"tool": "check_ssl",          "args": {"host": target, "port": port or 443}},
            {"tool": "ssh_audit",          "args": {"host": target}},
            {"tool": "http_headers_check", "args": {"url": f"http://{target}/"}},
            {"tool": "smb_check",          "args": {"host": target}},
            {"tool": "detect_attack_chains","args": {"narrate": True}},
            {"tool": "generate_report",    "args": {"format": "markdown"}},
        ]

    elif intent == "ssl_check":
        tools = [{"tool": "check_ssl", "args": {"host": target or "TARGET", "port": port or 443}}]

    elif intent == "ssh_check":
        tools = [{"tool": "ssh_audit", "args": {"host": target or "TARGET", "port": port or 22}}]

    elif intent == "web_scan":
        url = f"http://{target}:{port}/" if port else f"http://{target}/"
        tools = [
            {"tool": "http_headers_check", "args": {"url": url}},
            {"tool": "nikto_scan",         "args": {"url": url}},
        ]

    elif intent == "smb_check":
        tools = [{"tool": "smb_check", "args": {"host": target or "TARGET"}}]

    elif intent == "chain_detection":
        tools = [
            {"tool": "get_loaded_findings", "args": {}},
            {"tool": "detect_attack_chains", "args": {"narrate": True}},
        ]

    elif intent == "memory_search":
        query = re.sub(r"\b(search|memory|past|recall|similar)\b", "",
                       text, flags=re.I).strip() or text
        tools = [{"tool": "search_memory", "args": {"query": query}}]

    elif intent == "exploit_check" and cves:
        tools = [{"tool": "epss_check", "args": {"cves": cves}}]

    elif intent == "report":
        tools = [
            {"tool": "detect_attack_chains", "args": {"narrate": True}},
            {"tool": "generate_report", "args": {"format": "markdown"}},
        ]

    elif intent == "findings_check":
        tools = [{"tool": "get_loaded_findings", "args": {}}]

    else:
        # General / unknown — just use get_loaded_findings as start
        tools = [{"tool": "get_loaded_findings", "args": {}}]

    return tools


def _make_goal_string(intent: str, target: str, port: Optional[int],
                      cves: list, original: str) -> str:
    goal_map = {
        "full_pentest":    f"Full penetration test of {target}" if target else "Full pentest of loaded scan",
        "ssl_check":       f"SSL/TLS audit on {target}:{port or 443}" if target else "SSL/TLS audit",
        "ssh_check":       f"SSH security audit on {target}:{port or 22}" if target else "SSH audit",
        "web_scan":        f"Web vulnerability scan on {target}" if target else "Web vulnerability scan",
        "smb_check":       f"SMB enumeration on {target}" if target else "SMB check",
        "chain_detection": "Attack chain detection on loaded scan",
        "memory_search":   f"Search memory: {original[:60]}",
        "exploit_check":   f"Exploit intelligence for {', '.join(cves)}",
        "report":          "Generate penetration test report",
        "findings_check":  "Check loaded scan findings",
        "general":         original[:100],
    }
    return goal_map.get(intent, original[:100])
