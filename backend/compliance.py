"""
AA-VAPT Compliance Engine
─────────────────────────
• OWASP Top 10 2021 auto-mapper
• PCI-DSS v4.0 gap analysis
• ISO 27001:2022 controls gap analysis
• Risk scoring engine (0-100)
"""

from __future__ import annotations
import re
from typing import Any

# ─────────────────────────────────────────────────────────────
#  OWASP Top 10 2021
# ─────────────────────────────────────────────────────────────

OWASP_TOP10 = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "keywords": [
            "access control", "idor", "insecure direct object", "privilege escalat",
            "authorization bypass", "path traversal", "directory traversal",
            "lfi", "local file inclusion", "rfi", "remote file inclusion",
            "csrf", "cross-site request forgery", "missing authorization",
            "horizontal privilege", "vertical privilege", "forced browsing",
            "admin bypass", "role bypass", "permission bypass",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "keywords": [
            "ssl", "tls", "weak cipher", "weak encryption", "cleartext",
            "plaintext password", "unencrypted", "self-signed", "expired cert",
            "md5", "sha1", "des", "rc4", "weak hash", "insecure crypto",
            "heartbleed", "poodle", "beast", "sweet32", "drown", "logjam",
            "padding oracle", "cbc mode", "ecb mode", "key length",
            "certificate", "http (not https)", "sensitive data exposure",
        ],
        "cve_patterns": ["CVE-2014-0160", "CVE-2014-3566"],
    },
    {
        "id": "A03",
        "name": "Injection",
        "keywords": [
            "sql injection", "sqli", "xss", "cross-site scripting",
            "command injection", "os command", "ldap injection", "xpath injection",
            "ssji", "server-side template injection", "ssti", "nosql injection",
            "xml injection", "xxe", "xml external entity", "code injection",
            "eval injection", "log injection", "header injection",
            "html injection", "reflected", "stored xss", "dom xss",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "keywords": [
            "insecure design", "business logic", "race condition",
            "mass assignment", "object deserialization", "insecure deserialization",
            "unrestricted file upload", "file upload bypass",
            "open redirect", "account enumeration", "captcha bypass",
            "rate limit", "brute force protection", "password policy",
            "security by obscurity",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "keywords": [
            "misconfiguration", "default credential", "default password",
            "unnecessary service", "debug enabled", "verbose error",
            "stack trace", "directory listing", "directory indexing",
            "cors", "cross-origin", "http header", "security header",
            "x-frame-options", "content-security-policy", "csp",
            "x-content-type", "hsts", "clickjacking",
            "smb", "ftp", "telnet", "snmp default", "exposed service",
            "open port", "unnecessary open port", "admin interface exposed",
            "phpinfo", "server-status", "server-info",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "keywords": [
            "outdated", "end of life", "eol", "unsupported version",
            "known vulnerability", "cve-", "deprecated", "vulnerable version",
            "old version", "apache struts", "log4j", "log4shell",
            "spring4shell", "shellshock", "heartbleed", "drupalgeddon",
            "wordpress vulnerability", "joomla vulnerability",
            "third-party component", "library vulnerability",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "keywords": [
            "authentication", "weak password", "default credential",
            "brute force", "credential stuffing", "session fixation",
            "session hijacking", "session token", "jwt", "weak jwt",
            "password reuse", "multi-factor", "mfa bypass",
            "account lockout", "password complexity", "basic auth",
            "ntlm", "kerberos", "ssh key", "anonymous login",
            "ftp anonymous", "null session", "guest account",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A08",
        "name": "Software and Data Integrity Failures",
        "keywords": [
            "deserialization", "insecure deserialization", "pickle",
            "java deserialization", ".net deserialization", "ysoserial",
            "ci/cd", "supply chain", "dependency confusion",
            "typosquatting", "integrity check", "unsigned update",
            "subresource integrity", "cdn hijack",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "keywords": [
            "logging", "log", "audit trail", "monitoring",
            "alerting", "siem", "no log", "missing log",
            "insufficient log", "log tampering", "log deletion",
        ],
        "cve_patterns": [],
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery",
        "keywords": [
            "ssrf", "server-side request forgery", "internal service",
            "metadata endpoint", "169.254.169.254", "cloud metadata",
            "imds", "internal network access", "localhost bypass",
            "url redirection", "blind ssrf",
        ],
        "cve_patterns": [],
    },
]


def map_finding_to_owasp(finding: dict) -> list[str]:
    """Return list of OWASP category IDs that match this finding."""
    text = " ".join([
        finding.get("name") or "",
        finding.get("synopsis") or "",
        finding.get("plugin_output") or "",
        finding.get("description") or "",
    ]).lower()

    matched = []
    for cat in OWASP_TOP10:
        for kw in cat["keywords"]:
            if kw in text:
                matched.append(cat["id"])
                break
        else:
            # Check CVE patterns
            if cat["cve_patterns"]:
                for cve in cat["cve_patterns"]:
                    if cve.lower() in text:
                        matched.append(cat["id"])
                        break

    return list(dict.fromkeys(matched))  # dedupe, preserve order


def owasp_analysis(findings: list[dict]) -> dict:
    """
    Map all findings to OWASP Top 10 categories.
    Returns per-category counts + coverage summary.
    """
    # category_id → {count, severity_breakdown, findings}
    buckets: dict[str, dict] = {
        cat["id"]: {
            "id": cat["id"],
            "name": cat["name"],
            "count": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "findings": [],
        }
        for cat in OWASP_TOP10
    }

    unmapped = []
    for f in findings:
        cats = map_finding_to_owasp(f)
        if not cats:
            unmapped.append(f.get("name", "unknown"))
            continue
        for cid in cats:
            b = buckets[cid]
            b["count"] += 1
            sev = f.get("severity", "info")
            if sev in b:
                b[sev] += 1
            b["findings"].append({
                "name": f.get("name", ""),
                "severity": f.get("severity", "info"),
                "host": f.get("host", ""),
            })

    categories = list(buckets.values())
    covered = sum(1 for c in categories if c["count"] > 0)

    return {
        "categories": categories,
        "covered": covered,
        "total_categories": 10,
        "coverage_pct": round(covered / 10 * 100),
        "unmapped_count": len(unmapped),
        "unmapped_sample": unmapped[:10],
    }


# ─────────────────────────────────────────────────────────────
#  PCI-DSS v4.0 Requirements
# ─────────────────────────────────────────────────────────────

PCI_REQUIREMENTS = [
    {
        "id": "PCI-1",
        "name": "Network Security Controls",
        "desc": "Install and maintain network security controls (firewalls, segmentation).",
        "fail_keywords": ["open port", "exposed service", "smb exposed", "ftp exposed",
                          "telnet", "rpc exposed", "unnecessary service", "no firewall"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-2",
        "name": "Secure Configurations",
        "desc": "Apply secure configurations to all system components.",
        "fail_keywords": ["default credential", "default password", "default config",
                          "misconfiguration", "phpinfo", "debug enabled",
                          "directory listing", "verbose error"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-3",
        "name": "Protect Stored Account Data",
        "desc": "Protect stored cardholder/account data.",
        "fail_keywords": ["cleartext", "unencrypted", "plaintext password",
                          "sensitive data", "plaintext storage", "md5 password",
                          "weak hash"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-4",
        "name": "Protect Data in Transit",
        "desc": "Protect cardholder data with strong cryptography during transmission.",
        "fail_keywords": ["ssl 2", "ssl 3", "tls 1.0", "tls1.0", "tls 1.1",
                          "weak cipher", "cleartext", "http (not https)",
                          "poodle", "beast", "rc4", "des", "null cipher"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-5",
        "name": "Protect Against Malware",
        "desc": "Protect all systems and networks from malicious software.",
        "fail_keywords": ["malware", "backdoor", "rootkit", "webshell",
                          "remote access trojan", "rat detected"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-6",
        "name": "Secure Systems and Software",
        "desc": "Develop and maintain secure systems and software.",
        "fail_keywords": ["sql injection", "xss", "cross-site scripting",
                          "command injection", "outdated", "vulnerable version",
                          "cve-", "log4", "spring4shell", "unpatched"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-7",
        "name": "Restrict Access",
        "desc": "Restrict access to system components and cardholder data by business need.",
        "fail_keywords": ["idor", "access control", "privilege escalat",
                          "unauthorized access", "broken access", "admin exposed"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-8",
        "name": "Identify and Authenticate Users",
        "desc": "Identify users and authenticate access to system components.",
        "fail_keywords": ["weak password", "brute force", "no mfa", "authentication bypass",
                          "anonymous login", "null session", "default credential",
                          "jwt", "session fixation", "credential"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-9",
        "name": "Restrict Physical Access",
        "desc": "Restrict physical access to cardholder data.",
        "fail_keywords": [],  # Cannot assess from network scan
        "pass_if_no_match": True,
        "note": "Physical controls cannot be assessed via network scanning.",
    },
    {
        "id": "PCI-10",
        "name": "Log and Monitor Access",
        "desc": "Log and monitor all access to system components and cardholder data.",
        "fail_keywords": ["no logging", "missing log", "insufficient log",
                          "audit trail", "log deletion"],
        "pass_if_no_match": True,
    },
    {
        "id": "PCI-11",
        "name": "Test Security Regularly",
        "desc": "Test security of systems and networks regularly.",
        "fail_keywords": [],  # This requirement IS the test — always flag as manual
        "pass_if_no_match": True,
        "note": "Regular penetration testing (this scan) satisfies PCI-11 evidence.",
    },
    {
        "id": "PCI-12",
        "name": "Support Information Security Policy",
        "desc": "Support information security with organizational policies and programs.",
        "fail_keywords": [],
        "pass_if_no_match": True,
        "note": "Policy review requires manual assessment — not automatable via scanning.",
    },
]


def pci_analysis(findings: list[dict]) -> dict:
    """Evaluate PCI-DSS v4.0 compliance based on current findings."""
    findings_text_list = [
        " ".join([
            f.get("name") or "",
            f.get("synopsis") or "",
            f.get("plugin_output") or "",
        ]).lower()
        for f in findings
    ]

    results = []
    pass_count = 0
    fail_count = 0
    manual_count = 0

    for req in PCI_REQUIREMENTS:
        note = req.get("note", "")
        fail_kws = req.get("fail_keywords", [])

        if note and not fail_kws:
            status = "manual"
            manual_count += 1
            matched_findings = []
        else:
            matched_findings = []
            for i, f in enumerate(findings):
                ft = findings_text_list[i]
                for kw in fail_kws:
                    if kw in ft:
                        matched_findings.append({
                            "name": f.get("name", ""),
                            "severity": f.get("severity", "info"),
                            "host": f.get("host", ""),
                        })
                        break

            if matched_findings:
                status = "fail"
                fail_count += 1
            else:
                status = "pass"
                pass_count += 1

        results.append({
            "id": req["id"],
            "name": req["name"],
            "desc": req["desc"],
            "status": status,
            "note": note,
            "matched_findings": matched_findings[:5],
            "finding_count": len(matched_findings),
        })

    total = len(PCI_REQUIREMENTS)
    return {
        "requirements": results,
        "pass": pass_count,
        "fail": fail_count,
        "manual": manual_count,
        "total": total,
        "compliance_pct": round(pass_count / max(total - manual_count, 1) * 100),
        "version": "PCI-DSS v4.0",
    }


# ─────────────────────────────────────────────────────────────
#  ISO 27001:2022 Controls (Annex A — technological)
# ─────────────────────────────────────────────────────────────

ISO_CONTROLS = [
    {
        "id": "A.8.1",
        "name": "User Endpoint Devices",
        "desc": "Policies for securing user endpoint devices.",
        "fail_keywords": ["default credential", "outdated os", "unpatched"],
    },
    {
        "id": "A.8.2",
        "name": "Privileged Access Rights",
        "desc": "Allocation and use of privileged access rights.",
        "fail_keywords": ["privilege escalat", "sudo", "root access", "admin exposed",
                          "privilege bypass"],
    },
    {
        "id": "A.8.3",
        "name": "Information Access Restriction",
        "desc": "Restrict access to information and application system functions.",
        "fail_keywords": ["idor", "access control", "broken access", "unauthorized access"],
    },
    {
        "id": "A.8.5",
        "name": "Secure Authentication",
        "desc": "Secure authentication technologies and procedures.",
        "fail_keywords": ["weak password", "default credential", "authentication bypass",
                          "brute force", "null session", "anonymous login",
                          "no mfa", "session fixation"],
    },
    {
        "id": "A.8.7",
        "name": "Protection Against Malware",
        "desc": "Protection against malware.",
        "fail_keywords": ["malware", "backdoor", "webshell", "rootkit"],
    },
    {
        "id": "A.8.8",
        "name": "Management of Technical Vulnerabilities",
        "desc": "Manage technical vulnerabilities of information systems.",
        "fail_keywords": ["cve-", "outdated", "unpatched", "vulnerable version",
                          "end of life", "eol", "known vulnerability"],
    },
    {
        "id": "A.8.9",
        "name": "Configuration Management",
        "desc": "Configurations — including security configurations — established and managed.",
        "fail_keywords": ["misconfiguration", "default config", "debug enabled",
                          "directory listing", "phpinfo", "verbose error",
                          "unnecessary service"],
    },
    {
        "id": "A.8.11",
        "name": "Data Masking",
        "desc": "Data masking in accordance with access control policy.",
        "fail_keywords": ["sensitive data", "plaintext password", "cleartext credential",
                          "data exposure"],
    },
    {
        "id": "A.8.12",
        "name": "Data Leakage Prevention",
        "desc": "Apply data leakage prevention measures.",
        "fail_keywords": ["information disclosure", "data leak", "sensitive data exposure",
                          "version disclosure", "server banner"],
    },
    {
        "id": "A.8.16",
        "name": "Monitoring Activities",
        "desc": "Networks, systems and applications monitored for anomalous behaviour.",
        "fail_keywords": ["no logging", "missing log", "insufficient log"],
    },
    {
        "id": "A.8.20",
        "name": "Networks Security",
        "desc": "Networks secured, managed and controlled.",
        "fail_keywords": ["open port", "exposed service", "telnet", "ftp exposed",
                          "smb exposed", "rpc exposed"],
    },
    {
        "id": "A.8.21",
        "name": "Security of Network Services",
        "desc": "Security mechanisms, service levels and requirements for network services.",
        "fail_keywords": ["ssl", "tls 1.0", "weak cipher", "cleartext", "poodle",
                          "beast", "rc4"],
    },
    {
        "id": "A.8.23",
        "name": "Web Filtering",
        "desc": "Access to external websites managed to reduce exposure.",
        "fail_keywords": ["ssrf", "open redirect", "server-side request forgery"],
    },
    {
        "id": "A.8.24",
        "name": "Use of Cryptography",
        "desc": "Rules for effective use of cryptography.",
        "fail_keywords": ["weak cipher", "md5", "sha1", "des", "rc4", "weak hash",
                          "weak encryption", "self-signed"],
    },
    {
        "id": "A.8.25",
        "name": "Secure Development Lifecycle",
        "desc": "Rules for secure development applied.",
        "fail_keywords": ["sql injection", "xss", "command injection", "ssrf",
                          "insecure deserialization", "code injection"],
    },
    {
        "id": "A.8.28",
        "name": "Secure Coding",
        "desc": "Secure coding principles applied in software development.",
        "fail_keywords": ["sql injection", "xss", "cross-site scripting",
                          "injection", "buffer overflow", "format string"],
    },
]


def iso27001_analysis(findings: list[dict]) -> dict:
    """Evaluate ISO 27001:2022 Annex A technological controls."""
    findings_text_list = [
        " ".join([
            f.get("name") or "",
            f.get("synopsis") or "",
            f.get("plugin_output") or "",
        ]).lower()
        for f in findings
    ]

    results = []
    pass_count = 0
    fail_count = 0

    for ctrl in ISO_CONTROLS:
        matched_findings = []
        for i, f in enumerate(findings):
            ft = findings_text_list[i]
            for kw in ctrl["fail_keywords"]:
                if kw in ft:
                    matched_findings.append({
                        "name": f.get("name", ""),
                        "severity": f.get("severity", "info"),
                        "host": f.get("host", ""),
                    })
                    break

        if matched_findings:
            status = "fail"
            fail_count += 1
        else:
            status = "pass"
            pass_count += 1

        results.append({
            "id": ctrl["id"],
            "name": ctrl["name"],
            "desc": ctrl["desc"],
            "status": status,
            "matched_findings": matched_findings[:5],
            "finding_count": len(matched_findings),
        })

    total = len(ISO_CONTROLS)
    return {
        "controls": results,
        "pass": pass_count,
        "fail": fail_count,
        "total": total,
        "compliance_pct": round(pass_count / max(total, 1) * 100),
        "version": "ISO 27001:2022",
        "scope": "Annex A — Technological Controls (A.8.x)",
    }


# ─────────────────────────────────────────────────────────────
#  Risk Scoring Engine
# ─────────────────────────────────────────────────────────────

_SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
_SEV_ORDER  = ["critical", "high", "medium", "low", "info"]

def risk_score(findings: list[dict]) -> dict:
    """
    Calculate overall risk score (0–100) and per-severity breakdown.

    Algorithm:
      raw_score = Σ(weight[sev] * count[sev])  capped at 400
      final     = round(min(raw_score / 400, 1.0) * 100)

    Rating bands:
      0-25   → LOW
      26-50  → MEDIUM
      51-75  → HIGH
      76-100 → CRITICAL
    """
    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    host_set: set[str] = set()
    owasp_hit: set[str] = set()

    for f in findings:
        sev = f.get("severity") or "info"
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
        host = f.get("host") or ""
        if host:
            host_set.add(host)
        for oid in map_finding_to_owasp(f):
            owasp_hit.add(oid)

    raw = sum(_SEV_WEIGHT[s] * counts[s] for s in _SEV_ORDER)
    # Scale: 400 raw points = score 100
    score = min(round(raw / 400 * 100), 100)

    if score <= 25:
        rating = "LOW"
        color = "#22c55e"
    elif score <= 50:
        rating = "MEDIUM"
        color = "#f59e0b"
    elif score <= 75:
        rating = "HIGH"
        color = "#f97316"
    else:
        rating = "CRITICAL"
        color = "#ef4444"

    # Per-severity contribution percentage
    total_weighted = max(raw, 1)
    contrib = {
        s: round(_SEV_WEIGHT[s] * counts[s] / total_weighted * 100)
        for s in _SEV_ORDER if counts[s] > 0
    }

    return {
        "score": score,
        "rating": rating,
        "color": color,
        "raw_score": raw,
        "severity_counts": counts,
        "severity_contribution": contrib,
        "total_findings": len(findings),
        "affected_hosts": len(host_set),
        "owasp_categories_hit": len(owasp_hit),
        "recommendation": _risk_recommendation(score, counts),
    }


def _risk_recommendation(score: int, counts: dict) -> str:
    if counts.get("critical", 0) > 0:
        return (
            f"IMMEDIATE ACTION REQUIRED: {counts['critical']} critical "
            "finding(s) present. Remediate before production use."
        )
    if counts.get("high", 0) > 3:
        return (
            f"{counts['high']} high-severity findings detected. "
            "Schedule emergency remediation within 7 days."
        )
    if score > 50:
        return "Significant risk exposure. Prioritise high findings and retest within 30 days."
    if score > 25:
        return "Moderate risk. Address medium findings and review security posture."
    return "Risk is within acceptable range. Continue regular assessments."


# ─────────────────────────────────────────────────────────────
#  Scan Diff
# ─────────────────────────────────────────────────────────────

def diff_scans(old_findings: list[dict], new_findings: list[dict]) -> dict:
    """
    Compare two sets of findings.
    Uses (name, host) as identity key.
    """
    def _key(f: dict) -> str:
        return f"{(f.get('name') or '').strip().lower()}|{(f.get('host') or '').strip().lower()}"

    old_keys = {_key(f): f for f in old_findings}
    new_keys = {_key(f): f for f in new_findings}

    new_items   = [new_keys[k] for k in new_keys if k not in old_keys]
    fixed_items = [old_keys[k] for k in old_keys if k not in new_keys]
    persisting  = [new_keys[k] for k in new_keys if k in old_keys]

    # Severity changes
    severity_changes = []
    for k in new_keys:
        if k in old_keys:
            old_sev = old_keys[k].get("severity", "info")
            new_sev = new_keys[k].get("severity", "info")
            if old_sev != new_sev:
                severity_changes.append({
                    "name": new_keys[k].get("name", ""),
                    "host": new_keys[k].get("host", ""),
                    "old_severity": old_sev,
                    "new_severity": new_sev,
                })

    return {
        "new": new_items,
        "fixed": fixed_items,
        "persisting": persisting,
        "severity_changes": severity_changes,
        "summary": {
            "new_count": len(new_items),
            "fixed_count": len(fixed_items),
            "persisting_count": len(persisting),
            "severity_changes_count": len(severity_changes),
            "trend": (
                "improving" if len(fixed_items) > len(new_items) else
                "worsening" if len(new_items) > len(fixed_items) else
                "stable"
            ),
        },
    }


# ─────────────────────────────────────────────────────────────
#  Network Topology Builder
# ─────────────────────────────────────────────────────────────

def build_topology(findings: list[dict]) -> dict:
    """
    Build a D3-ready force-graph from findings.
    Nodes: hosts + services
    Links: host → service, host → vulnerability category
    """
    nodes: dict[str, dict] = {}
    links: list[dict] = []

    # Root node
    nodes["root"] = {
        "id": "root",
        "label": "Target Network",
        "type": "root",
        "severity": "info",
        "size": 20,
    }

    seen_links: set[str] = set()
    sv_order = ["critical", "high", "medium", "low", "info"]

    def _add_link(src: str, tgt: str, ltype: str = "network"):
        key = f"{src}→{tgt}"
        if key not in seen_links:
            seen_links.add(key)
            links.append({"source": src, "target": tgt, "type": ltype})


    for f in findings:
        host = (f.get("host") or "unknown").strip() or "unknown"
        sev = f.get("severity") or "info"
        if sev not in sv_order:
            sev = "info"
        name = f.get("name") or "Finding"

        # Host node
        if host not in nodes:
            nodes[host] = {
                "id": host,
                "label": host,
                "type": "host",
                "severity": sev,
                "size": 12,
                "finding_count": 0,
            }
            _add_link("root", host, "network")
        else:
            # Escalate severity if higher
            if sv_order.index(sev) < sv_order.index(nodes[host]["severity"]):
                nodes[host]["severity"] = sev
        nodes[host]["finding_count"] = nodes[host].get("finding_count", 0) + 1

        # Service / finding node
        fid = f"{host}:{name[:40]}"
        if fid not in nodes:
            nodes[fid] = {
                "id": fid,
                "label": name[:35],
                "type": "finding",
                "severity": sev,
                "size": 7,
                "host": host,
                "synopsis": (f.get("synopsis") or "")[:120],
            }
            _add_link(host, fid, "finding")

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "node_count": len(nodes),
        "link_count": len(links),
    }
