"""
h1_patterns.py — HackerOne-derived web vulnerability pattern database.
Mirrors the embedded _H1_PATTERNS array in webapp-pt.html so the
/api/webapp-pt/h1-patterns endpoint can serve the same data server-side.
"""

_PATTERNS = [
    {
        "id": "sqli_search",
        "title": "SQL Injection via Search Parameter",
        "severity": "high",
        "cwe": "CWE-89",
        "wstg": "WSTG-INPV-05",
        "h1_count": 1380,
        "category": "injection",
        "tags": ["sqli", "sql", "injection", "database"],
        "description": "User-controlled input in search/filter parameters passed directly to SQL query without parameterization.",
        "detection": "Single quote causes SQL error; time-based payloads cause response delay.",
        "steps": [
            "Add single quote to search param",
            "Check for SQL error in response",
            "Try OR 1=1 and SLEEP(5)",
            "Use sqlmap: sqlmap -r req.txt -p search --dbs",
        ],
    },
    {
        "id": "xss_reflected",
        "title": "Reflected XSS via URL Parameter",
        "severity": "medium",
        "cwe": "CWE-79",
        "wstg": "WSTG-INPV-01",
        "h1_count": 2840,
        "category": "xss",
        "tags": ["xss", "cross-site", "reflected", "script"],
        "description": "User-supplied data reflected in HTML response without proper encoding, allowing JavaScript execution.",
        "detection": "Payload appears unencoded in response. Alert box appears.",
        "steps": [
            "Send XSS probe in parameter",
            "View page source for unencoded payload",
            "Try attribute injection: img onerror payload",
            "Use dalfox for automated detection",
        ],
    },
    {
        "id": "ssrf_url",
        "title": "SSRF via URL Parameter",
        "severity": "critical",
        "cwe": "CWE-918",
        "wstg": "WSTG-INPV-19",
        "h1_count": 970,
        "category": "ssrf",
        "tags": ["ssrf", "server-side", "request-forgery", "url"],
        "description": "Application fetches remote URLs specified by user, allowing access to internal resources and cloud metadata.",
        "detection": "Internal service data returned; Burp Collaborator receives DNS/HTTP callback.",
        "steps": [
            "Set URL param to http://169.254.169.254/latest/meta-data/",
            "Check for AWS credentials in response",
            "Use Burp Collaborator for out-of-band detection",
            "Try internal IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
        ],
    },
    {
        "id": "idor",
        "title": "Insecure Direct Object Reference (IDOR)",
        "severity": "high",
        "cwe": "CWE-639",
        "wstg": "WSTG-ATHZ-04",
        "h1_count": 3200,
        "category": "authorization",
        "tags": ["idor", "access", "control", "authorization", "id"],
        "description": "Application uses user-supplied ID to access objects without verifying the requesting user owns or has access to them.",
        "detection": "Changing ID in request returns other users data without authorization error.",
        "steps": [
            "Create two test accounts",
            "With Account A session, change user_id to Account B ID",
            "Check if Account B data is returned",
            "Test all ID parameters and path-based IDs",
        ],
    },
    {
        "id": "cors_creds",
        "title": "CORS Misconfiguration with Credentials",
        "severity": "high",
        "cwe": "CWE-942",
        "wstg": "WSTG-CLNT-07",
        "h1_count": 740,
        "category": "cors",
        "tags": ["cors", "cross-origin", "origin"],
        "description": "API reflects arbitrary Origin header with Access-Control-Allow-Credentials: true, allowing cross-origin credential theft.",
        "detection": "Request with Origin: evil.com returns Access-Control-Allow-Origin: evil.com + Allow-Credentials: true.",
        "steps": [
            "Add Origin: https://evil.com to authenticated request",
            "Check response for Allow-Origin and Allow-Credentials headers",
            "Create PoC fetch with credentials from evil.com",
            "Test all API endpoints",
        ],
    },
    {
        "id": "jwt_alg",
        "title": "JWT Algorithm Confusion (none / HS256)",
        "severity": "critical",
        "cwe": "CWE-347",
        "wstg": "WSTG-SESS-10",
        "h1_count": 450,
        "category": "auth",
        "tags": ["jwt", "token", "algorithm", "none"],
        "description": "JWT signature verification bypassed by changing algorithm to none or exploiting RS256 to HS256 confusion.",
        "detection": "Token with alg:none accepted; role escalation via modified claims.",
        "steps": [
            "Decode JWT at jwt.io",
            "Change alg to none, modify role/user_id claim",
            "Re-encode without signature (trailing dot)",
            "Try RS256 to HS256: sign with public key fetched from JWKS endpoint",
        ],
    },
    {
        "id": "ssti",
        "title": "Server-Side Template Injection (SSTI)",
        "severity": "critical",
        "cwe": "CWE-94",
        "wstg": "WSTG-INPV-18",
        "h1_count": 310,
        "category": "injection",
        "tags": ["ssti", "template", "injection", "rce"],
        "description": "User input is evaluated as template code, leading to arbitrary code execution.",
        "detection": "{{7*7}} returns 49; ${7*7} returns 49.",
        "steps": [
            "Send {{7*7}} in string parameters",
            "If 49 returned — SSTI confirmed",
            "Identify engine: {{7*'7'}} returns 7777777 for Jinja2",
            "Exploit via OS command execution payload for identified engine",
        ],
    },
    {
        "id": "path_traversal",
        "title": "Path Traversal / LFI",
        "severity": "high",
        "cwe": "CWE-22",
        "wstg": "WSTG-INPV-07",
        "h1_count": 620,
        "category": "injection",
        "tags": ["lfi", "path", "traversal", "file", "inclusion"],
        "description": "File path parameter allows directory traversal to read arbitrary files from the server filesystem.",
        "detection": "../../../etc/passwd in file/path param returns /etc/passwd contents.",
        "steps": [
            "Change file param to ../../../etc/passwd",
            "Try URL-encoded: ..%2F..%2F..%2Fetc%2Fpasswd",
            "PHP: try php://filter/convert.base64-encode/resource=/etc/passwd",
            "Windows: try ../../../../Windows/win.ini",
        ],
    },
    {
        "id": "xxe",
        "title": "XXE — XML External Entity Injection",
        "severity": "critical",
        "cwe": "CWE-611",
        "wstg": "WSTG-INPV-07",
        "h1_count": 480,
        "category": "injection",
        "tags": ["xxe", "xml", "external", "entity"],
        "description": "XML parser processes external entity declarations, allowing file read or SSRF.",
        "detection": "File contents returned when XML entity references local file.",
        "steps": [
            "Identify XML input (body, SVG upload, DOCX)",
            "Inject DOCTYPE with SYSTEM entity referencing /etc/passwd",
            "For blind: use Burp Collaborator in SYSTEM identifier",
            "Try Content-Type change: JSON endpoint to XML body",
        ],
    },
    {
        "id": "open_redirect",
        "title": "Open Redirect via returnUrl Parameter",
        "severity": "medium",
        "cwe": "CWE-601",
        "wstg": "WSTG-CLNT-04",
        "h1_count": 860,
        "category": "redirect",
        "tags": ["redirect", "open", "return", "next", "url"],
        "description": "Application redirects user to attacker-controlled URL via unvalidated returnUrl/next/redirect parameter.",
        "detection": "Setting param to external URL causes redirect to that URL.",
        "steps": [
            "Find redirect params: next=, returnUrl=, redirect=, goto=",
            "Set to https://evil.com",
            "If blocked, try //evil.com or /backslash/ bypass variations",
            "Report impact: OAuth flow hijack or phishing with trusted domain",
        ],
    },
    {
        "id": "host_header_reset",
        "title": "Password Reset Link Poisoning via Host Header",
        "severity": "high",
        "cwe": "CWE-74",
        "wstg": "WSTG-INPV-17",
        "h1_count": 360,
        "category": "injection",
        "tags": ["host", "header", "password", "reset", "poisoning"],
        "description": "Application uses Host header for building password reset link. Attacker sets Host: evil.com causing reset link to point to attacker server.",
        "detection": "Reset email URL contains injected host.",
        "steps": [
            "Intercept password reset request in Burp",
            "Change Host header to attacker.com",
            "Trigger password reset for victim email",
            "Check if reset email link points to attacker.com",
        ],
    },
    {
        "id": "cmd_injection",
        "title": "Command Injection via OS-level Parameter",
        "severity": "critical",
        "cwe": "CWE-78",
        "wstg": "WSTG-INPV-12",
        "h1_count": 290,
        "category": "injection",
        "tags": ["rce", "command", "injection", "exec", "shell", "os"],
        "description": "User input passed to OS command without sanitization, allowing arbitrary command execution.",
        "detection": "| id appended to param returns command output in response.",
        "steps": [
            "Identify OS-like params: host, ip, cmd, filename, ping",
            "Inject | id or ; id and check response",
            "Blind: try | sleep 5 and measure response time",
            "OOB: curl to collaborator with command output",
        ],
    },
]


def get_all_patterns() -> list:
    """Return all H1 vulnerability patterns."""
    return _PATTERNS


def search_patterns(query: str) -> list:
    """Case-insensitive keyword search across title, tags, description, cwe, wstg."""
    q = query.lower().strip()
    if not q:
        return _PATTERNS
    results = []
    for p in _PATTERNS:
        haystack = " ".join([
            p["title"],
            p.get("description", ""),
            p.get("cwe", ""),
            p.get("wstg", ""),
            p.get("category", ""),
            " ".join(p.get("tags", [])),
        ]).lower()
        if q in haystack:
            results.append(p)
    return results


def get_patterns_by_category(category: str) -> list:
    """Filter patterns by category."""
    cat = category.lower().strip()
    return [p for p in _PATTERNS if p.get("category", "").lower() == cat]
