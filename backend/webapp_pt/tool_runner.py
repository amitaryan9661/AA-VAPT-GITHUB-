"""
tool_runner.py — Safe, whitelist-based runner for web-pentest CLI tools.

Design / safety:
  * Only tools in the TOOLS whitelist can run. No arbitrary commands.
  * Commands are executed with asyncio.create_subprocess_exec using an ARGV LIST
    (never a shell string) — so target values are passed as single args and are
    NOT interpreted by any shell. No `os.system`, no `shell=True`.
  * The target is validated (no whitespace/control chars, cannot start with '-')
    to prevent argument injection.
  * Each tool has its own timeout. Output is captured and parsed into a unified
    findings shape so results from every tool MERGE into one list.
  * If a tool isn't installed, we return a friendly install hint instead of crashing.

Runs ON THE USER'S MACHINE (where the backend lives, e.g. Kali) — that's where
nuclei/httpx/subfinder/etc. are installed.
"""
from __future__ import annotations
import asyncio, json, re, shutil, time, uuid
from urllib.parse import urlparse

# ───────────────────────── target helpers ─────────────────────────

_BAD = re.compile(r"[\s\x00-\x1f]")  # whitespace / control chars not allowed

def _valid(target: str) -> bool:
    if not target or _BAD.search(target):
        return False
    if target.startswith("-"):       # block argument injection
        return False
    return True

def _as_url(target: str) -> str:
    t = target.strip()
    if not re.match(r"^https?://", t, re.I):
        t = "https://" + t
    return t

def _as_domain(target: str) -> str:
    t = target.strip()
    if re.match(r"^https?://", t, re.I):
        t = urlparse(t).netloc
    return t.split("/")[0].split(":")[0]

# ───────────────────────── parsers ─────────────────────────
# Every parser returns a list of unified findings:
#   {source, severity, name, location, detail}
# severity ∈ critical|high|medium|low|info

def _p_lines(src, sev, name):
    def parse(out):
        res = []
        for ln in out.splitlines():
            ln = ln.strip()
            if ln:
                res.append({"source": src, "severity": sev, "name": name,
                            "location": ln, "detail": ""})
        return res
    return parse

def _p_nuclei(out):
    res = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or not ln.startswith("{"):
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        info = j.get("info", {}) or {}
        res.append({
            "source": "nuclei",
            "severity": (info.get("severity") or "info").lower(),
            "name": info.get("name") or j.get("template-id") or "nuclei match",
            "location": j.get("matched-at") or j.get("host") or "",
            "detail": (info.get("description") or "").strip()[:300],
        })
    return res

def _p_httpx(out):
    res = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or not ln.startswith("{"):
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        techs = j.get("tech") or j.get("technologies") or []
        detail = []
        if j.get("status_code") or j.get("status-code"):
            detail.append("HTTP " + str(j.get("status_code") or j.get("status-code")))
        if j.get("title"):
            detail.append(str(j.get("title")))
        if techs:
            detail.append("tech: " + ", ".join(map(str, techs)))
        res.append({"source": "httpx", "severity": "info", "name": "Live host",
                    "location": j.get("url") or j.get("input") or "",
                    "detail": " · ".join(detail)})
    return res

def _p_dalfox(out):
    res = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        res.append({"source": "dalfox", "severity": "high",
                    "name": "Possible XSS (" + str(j.get("type", "")) + ")",
                    "location": j.get("data") or j.get("evidence") or "",
                    "detail": str(j.get("message", ""))[:300]})
    if not res and out.strip():
        res.append({"source": "dalfox", "severity": "info", "name": "dalfox output",
                    "location": "", "detail": out.strip()[:300]})
    return res

def _p_wappalyzer(out):
    """npm `wappalyzer <url>` -> {"technologies":[{name,version,categories}]}."""
    try:
        j = json.loads(out)
    except Exception:
        return _p_raw("wappalyzer")(out)
    res = []
    techs = j.get("technologies", []) if isinstance(j, dict) else []
    for t in techs:
        nm = t.get("name")
        if not nm:
            continue
        ver = t.get("version") or ""
        cats = ", ".join([c.get("name", "") for c in (t.get("categories") or []) if isinstance(c, dict)])
        res.append({"source": "wappalyzer", "severity": "info", "name": "Technology",
                    "location": nm + ((" " + ver) if ver else ""), "detail": cats})
    return res

def _p_webanalyze(out):
    """webanalyze `-output json` -> [{hostname, matches:[{app_name/name, version}]}]."""
    try:
        j = json.loads(out)
    except Exception:
        return _p_raw("webanalyze")(out)
    arr = j if isinstance(j, list) else [j]
    res = []
    for host in arr:
        if not isinstance(host, dict):
            continue
        for m in (host.get("matches") or []):
            nm = m.get("app_name") or m.get("name")
            if not nm:
                continue
            ver = m.get("version") or ""
            res.append({"source": "webanalyze", "severity": "info", "name": "Technology",
                        "location": nm + ((" " + ver) if ver else ""),
                        "detail": host.get("hostname", "")})
    return res

def _p_raw(src, sev="info"):
    def parse(out):
        out = (out or "").strip()
        if not out:
            return []
        return [{"source": src, "severity": sev, "name": src + " output",
                 "location": "", "detail": out[:1200]}]
    return parse

# ───────────────────────── tool registry ─────────────────────────
# build = function(url, domain, oob) -> argv list (first item = binary).

TOOLS = {
    "subfinder": {
        "bin": "subfinder",
        "build": lambda url, dom, oob: ["subfinder", "-d", dom, "-silent"],
        "parse": _p_lines("subfinder", "info", "Subdomain"),
        "timeout": 120,
        "hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "label": "Subdomains (subfinder)",
    },
    "httpx": {
        "bin": "httpx",
        "build": lambda url, dom, oob: ["httpx", "-u", url, "-json", "-title",
                                        "-status-code", "-tech-detect", "-silent"],
        "parse": _p_httpx,
        "timeout": 90,
        "hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "label": "Live host + tech (httpx)",
    },
    "naabu": {
        "bin": "naabu",
        "build": lambda url, dom, oob: ["naabu", "-host", dom, "-top-ports", "100", "-silent"],
        "parse": _p_lines("naabu", "info", "Open port"),
        "timeout": 180,
        "hint": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "label": "Port scan (naabu)",
    },
    "katana": {
        "bin": "katana",
        "build": lambda url, dom, oob: ["katana", "-u", url, "-d", "2", "-silent"],
        "parse": _p_lines("katana", "info", "Crawled URL"),
        "timeout": 150,
        "hint": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        "label": "Crawl URLs (katana)",
    },
    "nuclei": {
        "bin": "nuclei",
        "build": lambda url, dom, oob: ["nuclei", "-u", url, "-severity",
                                        "critical,high,medium,low", "-jsonl", "-silent"],
        "parse": _p_nuclei,
        "timeout": 600,
        "hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
        "label": "Vuln scan (nuclei)",
    },
    "wappalyzer": {
        "bin": "wappalyzer",
        "build": lambda url, dom, oob: ["wappalyzer", url],
        "parse": _p_wappalyzer,
        "timeout": 90,
        "hint": "npm install -g wappalyzer",
        "label": "Tech detect (Wappalyzer)",
    },
    "webanalyze": {
        "bin": "webanalyze",
        "build": lambda url, dom, oob: ["webanalyze", "-host", url, "-output", "json"],
        "parse": _p_webanalyze,
        "timeout": 90,
        "hint": "go install github.com/rverton/webanalyze/cmd/webanalyze@latest && webanalyze -update",
        "label": "Tech detect (webanalyze / Wappalyzer engine)",
    },
    "whatweb": {
        "bin": "whatweb",
        "build": lambda url, dom, oob: ["whatweb", "--color=never", "-a", "1", url],
        "parse": _p_raw("whatweb"),
        "timeout": 60,
        "hint": "sudo apt install whatweb   (or gem install whatweb)",
        "label": "Tech fingerprint (whatweb)",
    },
    "wafw00f": {
        "bin": "wafw00f",
        "build": lambda url, dom, oob: ["wafw00f", url],
        "parse": _p_raw("wafw00f"),
        "timeout": 60,
        "hint": "pip install wafw00f",
        "label": "WAF detect (wafw00f)",
    },
    "dalfox": {
        "bin": "dalfox",
        "build": lambda url, dom, oob: ["dalfox", "url", url, "--silence", "--format", "json"],
        "parse": _p_dalfox,
        "timeout": 240,
        "hint": "go install github.com/hahwul/dalfox/v2@latest",
        "label": "XSS scan (dalfox)",
    },
    "nikto": {
        "bin": "nikto",
        "build": lambda url, dom, oob: ["nikto", "-h", url, "-nointeractive", "-Tuning", "123bde"],
        "parse": _p_raw("nikto"),
        "timeout": 600,
        "hint": "sudo apt install nikto",
        "label": "Server scan (nikto)",
    },
}

# ── Unified ATTACK FLOW: ordered stages so the whole engagement runs from ONE place ──
STAGES = [
    ("recon", "🌐 Recon / Subdomains"),
    ("tech",  "🔬 Live Host + Tech Detection"),
    ("crawl", "🕷️ Crawl / URL Harvest"),
    ("vuln",  "🎯 Vulnerability Scan"),
]
STAGE_MAP = {
    "subfinder": "recon", "naabu": "recon",
    "httpx": "tech", "wappalyzer": "tech", "webanalyze": "tech",
    "whatweb": "tech", "wafw00f": "tech",
    "katana": "crawl",
    "nuclei": "vuln", "dalfox": "vuln", "nikto": "vuln",
}
# The full attack chain, in order (one URL -> the whole flow).
FULL_FLOW = ["subfinder", "httpx", "wappalyzer", "webanalyze", "whatweb",
             "wafw00f", "katana", "nuclei", "dalfox"]

# "Run all" now runs the full attack flow from one place.
DEFAULT_SUITE = list(FULL_FLOW)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# in-memory jobs
JOBS: dict = {}


def available_tools() -> dict:
    """Which whitelisted tools are installed on this machine."""
    out = {}
    for name, t in TOOLS.items():
        out[name] = {
            "installed": shutil.which(t["bin"]) is not None,
            "label": t["label"],
            "hint": t["hint"],
        }
    return out


async def _run_one(name: str, target: str, oob: str | None) -> dict:
    t = TOOLS.get(name)
    if not t:
        return {"tool": name, "ok": False, "error": "unknown tool", "findings": []}
    if shutil.which(t["bin"]) is None:
        return {"tool": name, "ok": False, "installed": False,
                "stage": STAGE_MAP.get(name, "vuln"),
                "error": "not installed", "hint": t["hint"], "findings": []}

    url, dom = _as_url(target), _as_domain(target)
    argv = t["build"](url, dom, oob)
    started = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=t["timeout"])
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"tool": name, "ok": False, "installed": True,
                    "error": "timeout after %ss" % t["timeout"], "findings": []}
        out = (out_b or b"").decode("utf-8", "replace")
        err = (err_b or b"").decode("utf-8", "replace")
        findings = t["parse"](out) or []
        stage = STAGE_MAP.get(name, "vuln")
        for f in findings:
            f.setdefault("stage", stage)
        return {"tool": name, "ok": True, "installed": True, "stage": stage,
                "duration": round(time.time() - started, 1),
                "count": len(findings), "findings": findings,
                "stderr": err.strip()[:400]}
    except Exception as e:
        return {"tool": name, "ok": False, "installed": True,
                "stage": STAGE_MAP.get(name, "vuln"),
                "error": str(e)[:300], "findings": []}


def _merge(per_tool: list) -> list:
    """Flatten + dedupe all findings, sorted by severity."""
    seen, merged = set(), []
    for r in per_tool:
        for f in r.get("findings", []):
            key = (f.get("source"), f.get("severity"), f.get("name"), f.get("location"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(f)
    merged.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))
    return merged


async def run_job(target: str, tools: list, oob: str | None = None) -> str:
    """Start a background job that runs the requested tools concurrently. Returns job_id."""
    job_id = uuid.uuid4().hex[:12]
    tools = [t for t in (tools or []) if t in TOOLS] or list(DEFAULT_SUITE)
    JOBS[job_id] = {"job_id": job_id, "target": target, "tools": tools,
                    "state": "running", "started": time.time(),
                    "per_tool": [], "merged": [],
                    "pending": list(tools)}

    async def worker():
        async def one(name):
            res = await _run_one(name, target, oob)
            job = JOBS.get(job_id)
            if not job:
                return
            job["per_tool"].append(res)
            if name in job["pending"]:
                job["pending"].remove(name)
            job["merged"] = _merge(job["per_tool"])
        try:
            await asyncio.gather(*[one(n) for n in tools])
            job = JOBS.get(job_id)
            if job:
                job["state"] = "done"
                job["duration"] = round(time.time() - job["started"], 1)
        except Exception as e:
            job = JOBS.get(job_id)
            if job:
                job["state"] = "error"
                job["error"] = str(e)[:300]

    asyncio.create_task(worker())
    return job_id


def get_job(job_id: str) -> dict | None:
    return JOBS.get(job_id)


def validate_target(target: str) -> tuple[bool, str]:
    if not _valid(target):
        return False, "Invalid target (no spaces/control chars; cannot start with '-')."
    return True, ""
