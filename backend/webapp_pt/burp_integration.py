"""
Burp Suite Integration — 3 modes:
- PRO_AUTO:   Burp Suite Pro REST API (localhost:1337)
- COMMUNITY:  Burp Suite Community via proxy (localhost:8080)
- MANUAL:     User pastes raw request — burp_parser handles it

All traffic via localhost only. Zero external calls.
"""

import json
import logging
import time
from typing import Optional

log = logging.getLogger("aavapt.burp")

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

BURP_PRO_API_BASE = "http://localhost:1337/v0.1"
BURP_COMMUNITY_PROXY = "http://127.0.0.1:8080"
BURP_PRO_API_KEY: Optional[str] = None  # Set via /api/burp/set-api-key


class BurpMode:
    PRO_AUTO  = "PRO_AUTO"
    COMMUNITY = "COMMUNITY"
    MANUAL    = "MANUAL"


# ─────────────────────────────────────────────
# Mode Detection
# ─────────────────────────────────────────────

def detect_burp_mode() -> dict:
    """
    Detect which Burp mode is available.
    Returns: {mode, available, details}
    """
    # Try Pro API first
    pro_status = _check_burp_pro_api()
    if pro_status["available"]:
        return {
            "mode": BurpMode.PRO_AUTO,
            "available": True,
            "details": pro_status,
            "message": "Burp Suite Pro REST API detected (localhost:1337)",
        }

    # Try Community proxy
    community_status = _check_burp_proxy()
    if community_status["available"]:
        return {
            "mode": BurpMode.COMMUNITY,
            "available": True,
            "details": community_status,
            "message": "Burp Suite proxy detected (localhost:8080) — Community mode",
        }

    # Fallback to manual
    return {
        "mode": BurpMode.MANUAL,
        "available": True,
        "details": {},
        "message": "Burp not detected — Manual mode (paste raw requests)",
    }


def _check_burp_pro_api() -> dict:
    try:
        import requests
        headers = {}
        if BURP_PRO_API_KEY:
            headers["Authorization"] = f"Bearer {BURP_PRO_API_KEY}"
        r = requests.get(f"{BURP_PRO_API_BASE}/", headers=headers, timeout=3)
        if r.status_code in (200, 401, 403):
            return {"available": True, "status_code": r.status_code,
                    "authenticated": r.status_code == 200}
    except Exception:
        pass
    return {"available": False}


def _check_burp_proxy() -> dict:
    try:
        import requests
        # Try to connect through proxy (simple connection test)
        r = requests.get(
            "http://burptest.local/",
            proxies={"http": BURP_COMMUNITY_PROXY, "https": BURP_COMMUNITY_PROXY},
            timeout=3,
        )
        return {"available": True}
    except Exception as e:
        # Connection refused = no proxy. Other error might mean proxy exists but target unavailable.
        err_str = str(e).lower()
        if "connection refused" not in err_str and "timed out" not in err_str:
            return {"available": True}
    return {"available": False}


def set_api_key(api_key: str):
    global BURP_PRO_API_KEY
    BURP_PRO_API_KEY = api_key
    log.info("Burp Pro API key configured")


# ─────────────────────────────────────────────
# Burp Pro REST API — Scan Management
# ─────────────────────────────────────────────

def start_scan_pro(target_url: str, scan_type: str = "crawl_and_audit",
                   scope_urls: list = None) -> dict:
    """
    Start a Burp Pro scan via REST API.
    scan_type: 'crawl_and_audit' | 'audit_selected_items' | 'crawl'
    """
    if not BURP_PRO_API_KEY:
        return {"error": "Burp Pro API key not configured. Call /api/burp/set-api-key first."}
    try:
        import requests
        payload = {
            "scan_configurations": [{"name": scan_type}],
            "target_url": target_url,
        }
        if scope_urls:
            payload["scope"] = {
                "include": [{"rule": url, "type": "SimpleScopeRule"} for url in scope_urls]
            }
        r = requests.post(
            f"{BURP_PRO_API_BASE}/scan",
            headers={"Authorization": f"Bearer {BURP_PRO_API_KEY}",
                     "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code in (200, 201):
            data = r.json()
            scan_id = data.get("task_id") or r.headers.get("Location", "").split("/")[-1]
            log.info(f"Burp Pro scan started: {scan_id}")
            return {"success": True, "scan_id": scan_id, "mode": BurpMode.PRO_AUTO}
        else:
            return {"error": f"Burp API returned {r.status_code}: {r.text[:500]}"}
    except Exception as e:
        return {"error": f"Burp Pro API error: {e}"}


def get_scan_status_pro(scan_id: str) -> dict:
    """Get Burp Pro scan status."""
    if not BURP_PRO_API_KEY:
        return {"error": "API key not configured"}
    try:
        import requests
        r = requests.get(
            f"{BURP_PRO_API_BASE}/scan/{scan_id}",
            headers={"Authorization": f"Bearer {BURP_PRO_API_KEY}"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "scan_id": scan_id,
                "status": data.get("scan_status", "unknown"),
                "progress": data.get("scan_metrics", {}).get("crawl_request_count", 0),
                "issue_count": len(data.get("issue_events", [])),
                "raw": data,
            }
        return {"error": f"Status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def get_scan_issues_pro(scan_id: str) -> list:
    """Get issues found by Burp Pro scan."""
    if not BURP_PRO_API_KEY:
        return []
    try:
        import requests
        r = requests.get(
            f"{BURP_PRO_API_BASE}/scan/{scan_id}",
            headers={"Authorization": f"Bearer {BURP_PRO_API_KEY}"},
            timeout=10,
        )
        if r.status_code == 200:
            events = r.json().get("issue_events", [])
            issues = []
            for event in events:
                issue = event.get("issue", {})
                issues.append({
                    "name": issue.get("name", "Unknown"),
                    "severity": issue.get("severity", "info").lower(),
                    "confidence": issue.get("confidence", "tentative"),
                    "path": issue.get("path", ""),
                    "description": issue.get("issue_background", "")[:500],
                    "remediation": issue.get("remediation_background", "")[:500],
                    "evidence": _extract_burp_evidence(issue),
                })
            return issues
    except Exception as e:
        log.warning(f"Get issues failed: {e}")
    return []


def _extract_burp_evidence(issue: dict) -> str:
    """Extract request/response evidence from Burp issue."""
    evidence_parts = []
    for evidence in issue.get("evidence", [])[:2]:
        req_response = evidence.get("request_response", {})
        request = req_response.get("request", [])
        if isinstance(request, list):
            parts = [p.get("data", "") for p in request if "data" in p]
            evidence_parts.append("REQUEST:\n" + "".join(parts)[:500])
    return "\n\n".join(evidence_parts) if evidence_parts else ""


def import_burp_xml(xml_content: str) -> dict:
    """
    Import Burp Suite XML export file and extract issues.
    Works with Community and Pro exports.
    """
    from .burp_parser import parse_burp_xml
    import re

    requests_parsed = parse_burp_xml(xml_content)

    # Also parse issues from XML
    issues = []
    issue_blocks = re.findall(r'<issues>(.*?)</issues>', xml_content, re.DOTALL)
    if not issue_blocks:
        issue_blocks = re.findall(r'<issue>(.*?)</issue>', xml_content, re.DOTALL)

    for block in issue_blocks:
        name_m = re.search(r'<name>(.*?)</name>', block)
        sev_m = re.search(r'<severity>(.*?)</severity>', block)
        desc_m = re.search(r'<issueBackground>(.*?)</issueBackground>', block, re.DOTALL)
        path_m = re.search(r'<path>(.*?)</path>', block)
        issues.append({
            "name": name_m.group(1) if name_m else "Unknown Issue",
            "severity": (sev_m.group(1) or "info").lower() if sev_m else "info",
            "description": _strip_html(desc_m.group(1)[:500]) if desc_m else "",
            "path": path_m.group(1) if path_m else "",
        })

    return {
        "mode": "xml_import",
        "requests_found": len(requests_parsed),
        "issues_found": len(issues),
        "requests": [r.to_dict() for r in requests_parsed[:20]],
        "issues": issues,
    }


def _strip_html(text: str) -> str:
    import re
    return re.sub(r'<[^>]+>', '', text).strip()


# ─────────────────────────────────────────────
# Community Mode — Proxy-based analysis
# ─────────────────────────────────────────────

def send_through_proxy(url: str, method: str = "GET",
                       headers: dict = None, body: str = None,
                       verify_ssl: bool = False) -> dict:
    """
    Send a request through Burp Community proxy (localhost:8080).
    Useful for capturing requests in Burp history.
    """
    try:
        import requests
        proxies = {"http": BURP_COMMUNITY_PROXY, "https": BURP_COMMUNITY_PROXY}
        req_headers = headers or {}
        r = requests.request(
            method=method,
            url=url,
            headers=req_headers,
            data=body,
            proxies=proxies,
            verify=verify_ssl,
            timeout=30,
        )
        return {
            "success": True,
            "status_code": r.status_code,
            "response_headers": dict(r.headers),
            "response_body": r.text[:2000],
            "note": "Request captured in Burp Proxy history",
        }
    except Exception as e:
        return {"error": f"Proxy request failed: {e}",
                "hint": "Is Burp running with proxy on localhost:8080?"}


# ─────────────────────────────────────────────
# Manual Mode — Analyze raw request
# ─────────────────────────────────────────────

def analyze_manual_request(raw_request: str, target_host: str = "") -> dict:
    """
    Full analysis of a manually pasted Burp request.
    Combines parser + injection detection + payload suggestions.
    """
    from .burp_parser import analyze_request, build_intruder_payloads

    analysis = analyze_request(raw_request, default_host=target_host)

    # Enrich with payload lists for each detected test type
    payload_map = {}
    for test_type in analysis.get("suggested_tests", []):
        payloads = build_intruder_payloads(test_type)
        if payloads:
            payload_map[test_type] = payloads[:10]

    analysis["payload_suggestions"] = payload_map
    analysis["mode"] = BurpMode.MANUAL
    return analysis


# ─────────────────────────────────────────────
# Permission Gate Check
# ─────────────────────────────────────────────

def validate_scan_permission(permissions: dict, target_url: str) -> dict:
    """
    Mandatory permission gate before any automated scan.
    All 4 boxes + target URL confirmation required.
    """
    errors = []

    if not permissions.get("has_written_permission"):
        errors.append("Written authorization from target owner required")
    if not permissions.get("is_authorized_tester"):
        errors.append("Must confirm you are an authorized tester")
    if not permissions.get("understands_scope"):
        errors.append("Must confirm you understand the scope")
    if not permissions.get("agrees_not_to_exploit"):
        errors.append("Must agree not to exploit findings beyond PoC")

    confirmed_url = permissions.get("confirmed_target_url", "").strip()
    if confirmed_url != target_url.strip():
        errors.append(
            f"Target URL mismatch: you typed '{confirmed_url}', "
            f"session target is '{target_url}'"
        )

    if errors:
        return {
            "granted": False,
            "errors": errors,
            "message": "Permission gate failed — all conditions must be met before scanning",
        }

    return {
        "granted": True,
        "message": "Permission gate passed — scanning authorized",
        "timestamp": time.time(),
    }
