"""
In-memory store of the CURRENTLY loaded scan's findings.

The frontend pushes findings here (POST /api/findings/sync) whenever a scan is
loaded. MCP tools and the global search/chat panel query this single source so
the whole pipeline (frontend, backend, MCP, AI) shares one view of the scan.
"""
import re
import logging
import threading

log = logging.getLogger("aavapt.findings")

_LOCK = threading.Lock()
_FINDINGS = []          # list of normalized finding dicts
_META = {}              # {"target":..., "scan_date":..., "count":...}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\((?:tcp|udp)/(\d+)")


def _hosts_from(f):
    """Collect every IP referenced by a finding (explicit field + plugin output)."""
    hosts = set()
    for key in ("host", "ip"):
        v = str(f.get(key, "") or "")
        if _IP_RE.fullmatch(v.strip()):
            hosts.add(v.strip())
    hosts.update(_IP_RE.findall(str(f.get("pluginOutput", f.get("plugin_output", "")) or "")))
    return hosts


def set_findings(findings, meta=None):
    global _FINDINGS, _META
    norm = []
    for i, f in enumerate(findings or []):
        norm.append({
            "idx": f.get("idx", i),
            "name": f.get("name", f.get("pluginName", "")),
            "plugin_id": str(f.get("pluginId", f.get("plugin_id", ""))),
            "severity": str(f.get("severity", "info")).lower(),
            "port": str(f.get("port", "") or ""),
            "service": f.get("service", f.get("svc_name", "")),
            "synopsis": f.get("synopsis", ""),
            "plugin_output": f.get("pluginOutput", f.get("plugin_output", "")),
            "cves": f.get("cves", []),
            "hosts": sorted(_hosts_from(f)),
        })
    with _LOCK:
        _FINDINGS = norm
        _META = meta or {}
        _META["count"] = len(norm)
    log.info("findings_store: loaded %d findings (target=%s)", len(norm), (_META.get("target") if _META else "?"))
    return len(norm)


def get_all():
    with _LOCK:
        return list(_FINDINGS)


def get_page(page: int = 0, per_page: int = 100) -> dict:
    """ENH-06: Paginated access to findings — avoids returning huge lists at once.
    Returns {"findings": [...], "page": N, "per_page": N, "total": N, "has_more": bool}
    """
    per_page = max(1, min(per_page, 500))   # clamp 1-500
    with _LOCK:
        total = len(_FINDINGS)
        start = page * per_page
        end   = start + per_page
        chunk = list(_FINDINGS[start:end])
    return {
        "findings": chunk,
        "page": page,
        "per_page": per_page,
        "total": total,
        "has_more": end < total,
    }


def get_meta():
    with _LOCK:
        return dict(_META)


def search(query, limit=50):
    """Keyword / IP / port / CVE search across the loaded scan (offline-safe)."""
    q = str(query or "").strip().lower()
    if not q:
        return []
    out = []
    with _LOCK:
        for f in _FINDINGS:
            hay = " ".join([
                f["name"], f["plugin_id"], f["severity"], f["port"],
                str(f["service"]), f["synopsis"], f["plugin_output"],
                " ".join(f["cves"]), " ".join(f["hosts"]),
            ]).lower()
            if q in hay:
                out.append(f)
            if len(out) >= limit:
                break
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda x: sev_rank.get(x["severity"], 5))
    return out


def host_summary(ip):
    """All findings + ports + services + severities for a single IP."""
    ip = str(ip or "").strip()
    with _LOCK:
        related = [f for f in _FINDINGS if ip in f["hosts"]]
    ports = sorted({f["port"] for f in related if f["port"] and f["port"] != "0"},
                   key=lambda x: int(x) if x.isdigit() else 0)
    services = sorted({str(f["service"]) for f in related if f["service"]})
    sev_count = {}
    for f in related:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
    return {
        "ip": ip,
        "total_findings": len(related),
        "ports": ports,
        "services": services,
        "severity_breakdown": sev_count,
        "findings": [
            {"name": f["name"], "plugin_id": f["plugin_id"],
             "severity": f["severity"], "port": f["port"], "service": f["service"]}
            for f in related
        ],
    }
