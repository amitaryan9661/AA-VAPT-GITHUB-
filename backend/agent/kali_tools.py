# -*- coding: utf-8 -*-
"""
Kali Tools — Real tool execution on Kali Linux.

Each function runs an actual Kali tool via asyncio subprocess,
captures output, parses it into structured results, and returns
a dict the agent can reason about.

Design rules:
  1. Every function is async — never block the event loop.
  2. Every function has a timeout — never hang forever.
  3. Output is always structured dict — agent can read it.
  4. Errors are returned as {"error": "..."}, never raised.
  5. Raw output always included — agent can dig deeper.
"""
from __future__ import annotations
import asyncio
import re
import json
import logging
import shutil
from typing import Optional

log = logging.getLogger("aavapt.agent.kali")

_DEFAULT_TIMEOUT = 120  # seconds


# ─────────────────────────────────────────────────────────────
#  Subprocess helper
# ─────────────────────────────────────────────────────────────

import os as _os
import sys as _sys

# ─────────────────────────────────────────────────────────────
#  Execution backend — auto-detect: native Linux vs WSL vs SSH
# ─────────────────────────────────────────────────────────────

def _is_windows() -> bool:
    return _sys.platform.startswith("win")

def _wsl_available() -> bool:
    """Check if WSL is installed and accessible on Windows."""
    return shutil.which("wsl") is not None

def _wrap_cmd(cmd: str) -> list[str]:
    """
    Wrap a shell command for the correct execution environment:
      - Linux/Mac (server running on Kali directly): run via bash -c
      - Windows + WSL available: route through wsl.exe -e bash -c
      - Windows without WSL: run as-is (will likely fail for Kali tools)
    """
    if not _is_windows():
        # Running directly on Linux/Kali — native bash
        return ["bash", "-c", cmd]
    if _wsl_available():
        # Windows host — send command into WSL (default distro = Kali)
        return ["wsl", "-e", "bash", "-c", cmd]
    # Fallback — Windows native (Kali tools won't be found)
    log.warning("Running on Windows without WSL — Kali tools unavailable")
    return ["cmd", "/c", cmd]


async def _run(cmd: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    """
    Run a shell command in the correct environment (native/WSL).
    Returns (returncode, stdout, stderr).
    """
    wrapped = _wrap_cmd(cmd)
    log.info("EXEC [%s]: %s", "WSL" if _is_windows() and _wsl_available() else "native", cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *wrapped,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        log.warning("TIMEOUT after %ds: %s", timeout, cmd)
        try:
            proc.kill()
        except Exception:
            pass
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        log.error("EXEC error: %s — %s", cmd, e)
        return -1, "", str(e)


def _tool_available(name: str) -> bool:
    """Check if a tool is available in the execution environment."""
    if not _is_windows():
        return shutil.which(name) is not None
    if _wsl_available():
        # Check inside WSL
        import subprocess
        try:
            r = subprocess.run(
                ["wsl", "-e", "which", name],
                capture_output=True, timeout=5
            )
            return r.returncode == 0
        except Exception:
            return False
    return shutil.which(name) is not None


# ─────────────────────────────────────────────────────────────
#  NMAP
# ─────────────────────────────────────────────────────────────

def _parse_nmap(raw: str) -> dict:
    ports = []
    for line in raw.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.*)", line)
        if m:
            port_num, proto, state, info = m.groups()
            parts = info.split(None, 2)
            service = parts[0] if parts else ""
            version = parts[1] + (" " + parts[2] if len(parts) > 2 else "") if len(parts) > 1 else ""
            ports.append({"port": int(port_num), "proto": proto,
                          "state": state, "service": service, "version": version.strip()})
    os_guess = ""
    m = re.search(r"OS guess[ds]?:?\s*([^\n]+)", raw, re.I)
    if m:
        os_guess = m.group(1).strip()
    return {"open_ports": ports, "os_guess": os_guess, "raw": raw[:8000]}


async def nmap_scan(target: str, ports: str = "top100",
                    flags: str = "-sV -sC", timeout: int = 120) -> dict:
    if not _tool_available("nmap"):
        return {"error": "nmap not found. Install: apt install nmap"}
    port_arg = ""
    if ports == "top100":
        port_arg = "--top-ports 100"
    elif ports == "top1000":
        port_arg = "--top-ports 1000"
    elif ports:
        port_arg = f"-p {ports}"
    cmd = f"nmap -Pn {flags} {port_arg} {target} 2>&1"
    rc, out, err = await _run(cmd, timeout)
    if rc == -1:
        return {"error": err or "nmap timed out", "target": target}
    result = _parse_nmap(out)
    result["target"] = target
    result["command"] = cmd.replace("2>&1", "").strip()
    result["port_count"] = len(result["open_ports"])
    log.info("nmap %s → %d open ports", target, result["port_count"])
    return result


# ─────────────────────────────────────────────────────────────
#  SSL / TLS check
# ─────────────────────────────────────────────────────────────

def _parse_testssl(raw: str) -> dict:
    issues = []
    for line in raw.splitlines():
        if any(kw in line.lower() for kw in ("vulnerable", "weak", "deprecated",
                                              "expired", "not ok", "offered", "warning")):
            clean = re.sub(r"\033\[[0-9;]*m", "", line).strip()
            if clean:
                issues.append(clean)
    tls_versions = re.findall(r"(TLSv[\d.]+|SSLv[\d.]+)\s+(offered|not offered)", raw, re.I)
    return {
        "issues": issues[:30],
        "tls_versions": [{"version": v, "status": s} for v, s in tls_versions],
        "raw": raw[:6000],
    }


async def check_ssl(host: str, port: int = 443, timeout: int = 60) -> dict:
    target = f"{host}:{port}"
    # Try testssl first
    if _tool_available("testssl"):
        cmd = f"testssl --color 0 --warnings off --quiet {target} 2>&1"
        rc, out, err = await _run(cmd, timeout)
        if rc != -1:
            result = _parse_testssl(out)
            result["tool"] = "testssl"
            result["target"] = target
            return result

    # Fallback: nmap ssl scripts
    if _tool_available("nmap"):
        cmd = f"nmap -Pn --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p {port} {host} 2>&1"
        rc, out, err = await _run(cmd, timeout)
        result = {"tool": "nmap-ssl", "target": target, "raw": out[:5000]}
        # Extract issues from nmap output
        issues = [l.strip() for l in out.splitlines()
                  if any(kw in l.lower() for kw in ("vulnerable", "weak", "tls", "ssl", "expired"))]
        result["issues"] = issues[:20]
        return result

    # Fallback: openssl
    cmd = (f"echo | openssl s_client -connect {target} 2>/dev/null "
           f"| openssl x509 -noout -dates -subject -issuer 2>/dev/null")
    rc, out, err = await _run(cmd, 20)
    return {"tool": "openssl", "target": target, "raw": out, "issues": []}


# ─────────────────────────────────────────────────────────────
#  SSH Audit
# ─────────────────────────────────────────────────────────────

async def ssh_audit(host: str, port: int = 22) -> dict:
    target = f"{host}:{port}"
    if _tool_available("ssh-audit"):
        cmd = f"ssh-audit -p {port} {host} 2>&1"
        rc, out, err = await _run(cmd, 30)
        issues = [re.sub(r"\033\[[0-9;]*m", "", l).strip()
                  for l in out.splitlines()
                  if any(kw in l.lower() for kw in ("warn", "fail", "weak", "deprecated", "cbc", "md5", "dh-group1"))]
        return {"tool": "ssh-audit", "target": target, "issues": issues[:20], "raw": out[:4000]}

    # Fallback: nmap
    if _tool_available("nmap"):
        cmd = f"nmap -Pn -p {port} --script ssh2-enum-algos,ssh-hostkey {host} 2>&1"
        rc, out, err = await _run(cmd, 30)
        return {"tool": "nmap-ssh", "target": target, "raw": out[:3000], "issues": []}

    return {"error": "ssh-audit and nmap not found", "target": target}


# ─────────────────────────────────────────────────────────────
#  HTTP Headers
# ─────────────────────────────────────────────────────────────

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

_BAD_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
]


async def http_headers_check(url: str, timeout: int = 15) -> dict:
    if _tool_available("curl"):
        cmd = f"curl -skI --max-time {timeout} --location '{url}' 2>&1"
        rc, out, _ = await _run(cmd, timeout + 5)
        headers: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        missing_security = [h for h in _SECURITY_HEADERS if h not in headers]
        exposed_info = {h: headers[h] for h in _BAD_HEADERS if h in headers}
        cors = headers.get("access-control-allow-origin", "")
        cors_issue = cors == "*"

        return {
            "tool": "curl",
            "url": url,
            "headers": headers,
            "missing_security_headers": missing_security,
            "exposed_info_headers": exposed_info,
            "cors_wildcard": cors_issue,
            "issues": (
                [f"Missing: {h}" for h in missing_security] +
                [f"Info leak: {k}: {v}" for k, v in exposed_info.items()] +
                (["CORS wildcard: Access-Control-Allow-Origin: *"] if cors_issue else [])
            ),
            "raw": out[:3000],
        }
    return {"error": "curl not found", "url": url}


# ─────────────────────────────────────────────────────────────
#  Nikto
# ─────────────────────────────────────────────────────────────

async def nikto_scan(url: str, timeout: int = 180) -> dict:
    if not _tool_available("nikto"):
        return {"error": "nikto not found. Install: apt install nikto", "url": url}
    cmd = f"nikto -h '{url}' -maxtime {timeout} -nointeractive 2>&1"
    rc, out, err = await _run(cmd, timeout + 15)
    findings = []
    for line in out.splitlines():
        if line.strip().startswith("+"):
            findings.append(line.strip().lstrip("+ "))
    return {
        "tool": "nikto",
        "url": url,
        "findings": findings[:50],
        "finding_count": len(findings),
        "raw": out[:6000],
    }


# ─────────────────────────────────────────────────────────────
#  SMB
# ─────────────────────────────────────────────────────────────

async def smb_check(host: str) -> dict:
    results: dict = {"host": host, "checks": []}
    if _tool_available("nmap"):
        cmd = f"nmap -Pn -p 445,139 --script smb-protocols,smb-security-mode,smb-vuln-ms17-010 {host} 2>&1"
        rc, out, _ = await _run(cmd, 60)
        results["nmap_smb"] = out[:3000]
        for line in out.splitlines():
            if any(kw in line.lower() for kw in ("signing", "smb1", "smb2", "vulnerable", "null")):
                results["checks"].append(line.strip())
    if _tool_available("smbclient"):
        cmd = f"smbclient -L //{host} -N 2>&1"
        rc, out, _ = await _run(cmd, 20)
        results["null_session"] = out[:1000]
        results["null_session_works"] = "Sharename" in out
    return results


# ─────────────────────────────────────────────────────────────
#  FTP
# ─────────────────────────────────────────────────────────────

async def ftp_check(host: str, port: int = 21) -> dict:
    results: dict = {"host": host, "port": port}
    if _tool_available("nmap"):
        cmd = f"nmap -Pn -p {port} --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor {host} 2>&1"
        rc, out, _ = await _run(cmd, 30)
        results["nmap_ftp"] = out[:2000]
        results["anonymous_login"] = "anonymous login" in out.lower() and "denied" not in out.lower()
    return results


# ─────────────────────────────────────────────────────────────
#  SSH Brute Force (DANGEROUS — requires HITL)
# ─────────────────────────────────────────────────────────────

async def brute_force_ssh(host: str, port: int = 22,
                          wordlist: str = "/usr/share/wordlists/rockyou.txt",
                          username: str = "root") -> dict:
    if not _tool_available("hydra"):
        return {"error": "hydra not found. Install: apt install hydra"}
    if not __import__("os").path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}
    cmd = f"hydra -l {username} -P {wordlist} -t 4 ssh://{host}:{port} -e nsr 2>&1 | head -50"
    rc, out, _ = await _run(cmd, 300)
    found = re.findall(rf"\[{port}\]\[ssh\] host: .+ login: (.+) password: (.+)", out, re.I)
    return {
        "tool": "hydra",
        "target": f"{host}:{port}",
        "username": username,
        "credentials_found": [{"login": u, "password": p} for u, p in found],
        "raw": out[:3000],
    }


# ─────────────────────────────────────────────────────────────
#  Metasploit (DANGEROUS — requires HITL)
# ─────────────────────────────────────────────────────────────

async def run_metasploit_module(module: str, target: str,
                                 port: Optional[int] = None,
                                 options: Optional[dict] = None) -> dict:
    if not _tool_available("msfconsole"):
        return {"error": "Metasploit not found. Install: apt install metasploit-framework"}
    import tempfile as _tmp, os as _os2
    opts = options or {}
    if port:
        opts["RPORT"] = port
    opt_lines = "\n".join(f"set {k} {v}" for k, v in opts.items())
    rc_script = (
        f"use {module}\n"
        f"set RHOSTS {target}\n"
        f"{opt_lines}\n"
        "set ExitOnSession false\n"
        "run -j\n"
        "sleep 10\n"
        "exit\n"
    )
    # Write RC script to a temp file to avoid shell injection via echo + single quotes
    rc_fd, rc_path = _tmp.mkstemp(suffix=".rc", prefix="msf_")
    try:
        with _os2.fdopen(rc_fd, "w") as _f:
            _f.write(rc_script)
        cmd = f"msfconsole -q -r '{rc_path}' 2>&1"
        rc, out, _ = await _run(cmd, 120)
    finally:
        _os2.unlink(rc_path) if _os2.path.exists(rc_path) else None
    return {
        "tool": "metasploit",
        "module": module,
        "target": target,
        "raw": out[:4000],
    }


# ─────────────────────────────────────────────────────────────
#  Nuclei — fast template-based vulnerability scanner
# ─────────────────────────────────────────────────────────────

async def nuclei_scan(
    target: str,
    templates: str = "cves,exposures,technologies,misconfiguration,default-logins",
    severity: str = "critical,high,medium",
    timeout: int = 300,
    proxy: str = "",
) -> dict:
    if not _tool_available("nuclei"):
        return {
            "error": "nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "target": target,
        }
    proxy_arg = f"-proxy '{proxy}'" if proxy else ""
    # Quote template categories to handle any special chars safely
    cmd = (
        f"nuclei -u '{target}' -t '{templates}' -severity '{severity}' "
        f"-silent -json -timeout 5 {proxy_arg} 2>&1 | head -200"
    )
    rc, out, err = await _run(cmd, timeout)
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            findings.append({
                "template_id": item.get("template-id", ""),
                "name": item.get("info", {}).get("name", ""),
                "severity": item.get("info", {}).get("severity", "info"),
                "matched_at": item.get("matched-at", ""),
                "description": item.get("info", {}).get("description", ""),
                "tags": item.get("info", {}).get("tags", []),
                "cve": item.get("info", {}).get("classification", {}).get("cve-id", []),
                "cvss_score": item.get("info", {}).get("classification", {}).get("cvss-score", None),
            })
        except Exception:
            pass
    return {
        "tool": "nuclei",
        "target": target,
        "templates": templates,
        "severity_filter": severity,
        "findings": findings,
        "finding_count": len(findings),
        "raw": out[:8000],
    }


# ─────────────────────────────────────────────────────────────
#  SQLMap — SQL injection detection and exploitation
# ─────────────────────────────────────────────────────────────

async def sqlmap_scan(
    url: str,
    data: str = "",
    params: str = "",
    cookies: str = "",
    level: int = 1,
    risk: int = 1,
    timeout: int = 180,
    proxy: str = "",
) -> dict:
    if not _tool_available("sqlmap"):
        return {"error": "sqlmap not found. Install: apt install sqlmap", "url": url}
    data_arg   = f"--data='{data}'" if data else ""
    params_arg = f"-p '{params}'" if params else ""
    cookie_arg = f"--cookie='{cookies}'" if cookies else ""
    proxy_arg  = f"--proxy='{proxy}'" if proxy else ""
    cmd = (
        f"sqlmap -u '{url}' {data_arg} {params_arg} {cookie_arg} {proxy_arg} "
        f"--level={level} --risk={risk} --batch --forms --smart --answers='Y' "
        f"--output-dir=/tmp/sqlmap_{abs(hash(url))%99999} 2>&1 | tail -80"
    )
    rc, out, err = await _run(cmd, timeout)
    injectable = re.findall(r"Parameter: (.+?) \((GET|POST)\)", out)
    dbms = re.search(r"back-end DBMS: (.+)", out)
    return {
        "tool": "sqlmap",
        "url": url,
        "injectable_params": [{"param": p, "method": m} for p, m in injectable],
        "dbms": dbms.group(1).strip() if dbms else None,
        "vulnerable": bool(injectable),
        "raw": out[:5000],
    }


# ─────────────────────────────────────────────────────────────
#  FFUF — directory and endpoint fuzzing
# ─────────────────────────────────────────────────────────────

async def ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "php,html,txt,js,asp,aspx",
    timeout: int = 120,
    proxy: str = "",
) -> dict:
    if not _tool_available("ffuf"):
        return {"error": "ffuf not found. Install: apt install ffuf", "url": url}
    # Fallback wordlist if seclists not present
    import os
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}", "url": url}
    target = url.rstrip("/") + "/FUZZ"
    ext_arg = f"-e .{extensions.replace(',',',.').replace(' ','')}" if extensions else ""
    import os as _os, tempfile as _tmp
    proxy_arg = f"-x {proxy}" if proxy else ""
    # Write JSON output to a secure temp file (ffuf -json writes full JSON to -o, not stdout)
    _fd, out_file = _tmp.mkstemp(suffix=".json", prefix="ffuf_")
    _os.close(_fd)  # close fd — ffuf will write to the path
    cmd = (
        f"ffuf -u '{target}' -w '{wordlist}' {ext_arg} {proxy_arg} "
        f"-mc 200,204,301,302,307,401,403 -t 40 -timeout 5 "
        f"-o '{out_file}' -of json -s 2>&1"
    )
    rc, out, err = await _run(cmd, timeout)
    results = []
    # Try reading JSON output file
    try:
        if _os.path.exists(out_file):
            with open(out_file, encoding="utf-8") as _f:
                data = json.load(_f)
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                })
            _os.unlink(out_file)
    except Exception:
        try:
            _os.unlink(out_file)
        except Exception:
            pass
    # Fallback: parse plain-text stdout
    if not results:
        for line in out.splitlines():
            m = re.search(r"\[Status: (\d+),\s*Size: (\d+)\].*?:: (.+)", line)
            if m:
                results.append({"status": int(m.group(1)), "length": int(m.group(2)), "url": m.group(3).strip()})
    return {
        "tool": "ffuf",
        "url": url,
        "wordlist": wordlist,
        "results": results[:100],
        "result_count": len(results),
        "raw": out[:5000],
    }


# ─────────────────────────────────────────────────────────────
#  WhatWeb — technology fingerprinting
# ─────────────────────────────────────────────────────────────

async def whatweb_scan(url: str, timeout: int = 30) -> dict:
    if _tool_available("whatweb"):
        cmd = f"whatweb -a 3 --quiet '{url}' 2>&1"
        rc, out, err = await _run(cmd, timeout)
        technologies = []
        versions = {}
        # Parse whatweb output: "URL [status] Tech[version], Tech2"
        tech_matches = re.findall(r"([A-Za-z][A-Za-z0-9\-\.]+)\[([^\]]+)\]", out)
        for name, value in tech_matches:
            technologies.append(name)
            if re.search(r"\d+\.\d+", value):
                versions[name] = value
        return {
            "tool": "whatweb",
            "url": url,
            "technologies": list(set(technologies)),
            "versions": versions,
            "raw": out[:3000],
        }
    # Fallback: curl + header fingerprinting
    cmd = f"curl -skI --max-time 10 '{url}' 2>&1"
    rc, out, _ = await _run(cmd, 15)
    technologies = []
    for line in out.splitlines():
        low = line.lower()
        if "x-powered-by:" in low:
            technologies.append(line.split(":", 1)[1].strip())
        if "server:" in low:
            technologies.append(line.split(":", 1)[1].strip())
    return {"tool": "curl-fallback", "url": url, "technologies": technologies, "raw": out[:2000]}


# ─────────────────────────────────────────────────────────────
#  Subfinder — passive subdomain enumeration
# ─────────────────────────────────────────────────────────────

async def subfinder_scan(domain: str, timeout: int = 90) -> dict:
    if _tool_available("subfinder"):
        cmd = f"subfinder -d '{domain}' -silent 2>&1"
        rc, out, err = await _run(cmd, timeout)
        subdomains = [s.strip() for s in out.splitlines() if s.strip() and "." in s]
        return {"tool": "subfinder", "domain": domain, "subdomains": subdomains, "count": len(subdomains)}
    # Fallback: amass passive
    if _tool_available("amass"):
        cmd = f"amass enum -passive -d '{domain}' -timeout 60 2>&1 | grep -v '\\[' | head -100"
        rc, out, err = await _run(cmd, timeout)
        subdomains = [s.strip() for s in out.splitlines() if domain in s]
        return {"tool": "amass", "domain": domain, "subdomains": subdomains, "count": len(subdomains)}
    # Fallback: DNS brute with nmap
    if _tool_available("nmap"):
        cmd = f"nmap --script dns-brute -sn '{domain}' 2>&1"
        rc, out, err = await _run(cmd, timeout)
        subdomains = re.findall(rf"[\w\-]+\.{re.escape(domain)}", out)
        return {"tool": "nmap-dnsbrute", "domain": domain, "subdomains": list(set(subdomains)), "count": len(set(subdomains))}
    return {"error": "No subdomain enumeration tool found (subfinder/amass/nmap)", "domain": domain}


# ─────────────────────────────────────────────────────────────
#  GoBuster — directory brute-force
# ─────────────────────────────────────────────────────────────

async def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    timeout: int = 120,
    proxy: str = "",
) -> dict:
    import os
    if not _tool_available("gobuster"):
        return {"error": "gobuster not found. Install: apt install gobuster", "url": url}
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}", "url": url}
    proxy_arg = f"--proxy {proxy}" if proxy else ""
    cmd = (
        f"gobuster {mode} -u '{url}' -w '{wordlist}' {proxy_arg} "
        f"-t 30 -q --no-error 2>&1 | head -200"
    )
    rc, out, err = await _run(cmd, timeout)
    found = []
    for line in out.splitlines():
        m = re.match(r"(/[\S]*)\s+\(Status: (\d+)\)", line.strip())
        if m:
            found.append({"path": m.group(1), "status": int(m.group(2))})
    return {
        "tool": "gobuster",
        "url": url,
        "mode": mode,
        "found": found[:100],
        "count": len(found),
        "raw": out[:4000],
    }


# ─────────────────────────────────────────────────────────────
#  Quick PoC Tests — curl-based, no heavy tool needed
# ─────────────────────────────────────────────────────────────

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' AND SLEEP(3)--",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
]

_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/proc/self/environ",
]

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/admin",
    "http://[::1]/admin",
    "file:///etc/passwd",
]


async def xss_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick reflected XSS test with multiple payloads."""
    from urllib.parse import quote as _quote
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    found = []
    for payload in _XSS_PAYLOADS[:3]:
        encoded = _quote(payload, safe="")
        p_name = param or "q"
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{p_name}={encoded}"
        cmd = f"curl -sk --max-time 8 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        if payload.lower() in out.lower():
            found.append({"payload": payload, "reflected": True, "url": test_url})
    return {
        "tool": "curl-xss",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "high" if found else "info",
        "finding": "Reflected XSS vulnerability confirmed" if found else "No reflected XSS found",
    }


async def sqli_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick SQL injection test — error-based and boolean-based."""
    from urllib.parse import quote as _quote
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    sqli_errors = [
        "sql syntax", "mysql_fetch", "ora-", "pg_query", "microsoft ole db",
        "unclosed quotation", "sqlite_", "you have an error in your sql",
        "warning: mysql", "supplied argument is not a valid mysql",
    ]
    found = []
    for payload in _SQLI_PAYLOADS[:3]:
        encoded = _quote(payload, safe="")
        p_name = param or "id"
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{p_name}={encoded}"
        cmd = f"curl -sk --max-time 8 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        out_low = out.lower()
        triggered = [e for e in sqli_errors if e in out_low]
        if triggered:
            found.append({"payload": payload, "error_triggered": triggered[0], "url": test_url})
    return {
        "tool": "curl-sqli",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "critical" if found else "info",
        "finding": "SQL Injection error-based confirmed" if found else "No SQLi error response found",
    }


async def lfi_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick Local File Inclusion test."""
    from urllib.parse import quote as _quote
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    lfi_indicators = ["root:x:", "root:!", "[boot loader]", "www-data:", "daemon:"]
    found = []
    for payload in _LFI_PAYLOADS[:3]:
        encoded = _quote(payload, safe="")
        p_name = param or "file"
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{p_name}={encoded}"
        cmd = f"curl -sk --max-time 8 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        triggered = [ind for ind in lfi_indicators if ind in out]
        if triggered:
            found.append({"payload": payload, "indicator_found": triggered[0], "url": test_url})
    return {
        "tool": "curl-lfi",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "critical" if found else "info",
        "finding": "Local File Inclusion confirmed — /etc/passwd readable" if found else "No LFI found",
    }


async def ssrf_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick SSRF test — metadata endpoint + localhost probing."""
    from urllib.parse import quote as _quote
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    ssrf_indicators = ["ami-id", "instance-id", "ec2", "169.254", "local-ipv4", "root:x:", "127.0.0.1"]
    found = []
    for payload in _SSRF_PAYLOADS[:3]:
        encoded = _quote(payload, safe="")
        p_name = param or "url"
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{p_name}={encoded}"
        cmd = f"curl -sk --max-time 8 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        triggered = [ind for ind in ssrf_indicators if ind.lower() in out.lower()]
        if triggered:
            found.append({"payload": payload, "indicator": triggered[0], "url": test_url})
    return {
        "tool": "curl-ssrf",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "critical" if found else "info",
        "finding": "SSRF confirmed — internal resource reached" if found else "No SSRF found",
    }


async def open_redirect_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick open redirect test."""
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    payloads = ["https://evil.com", "//evil.com", "/\\evil.com", r"\/evil.com/"]
    found = []
    for payload in payloads[:3]:
        test_url = f"{url}{'&' if '?' in url else '?'}{param or 'redirect'}={payload}"
        cmd = f"curl -skI --max-time 8 --max-redirs 0 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        if "location:" in out.lower() and "evil.com" in out.lower():
            found.append({"payload": payload, "location_header": [l for l in out.splitlines() if "location:" in l.lower()]})
    return {
        "tool": "curl-redirect",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "medium" if found else "info",
        "finding": "Open Redirect confirmed" if found else "No open redirect found",
    }


async def cors_misconfiguration_test(url: str, proxy: str = "") -> dict:
    """Test for CORS misconfiguration — reflects arbitrary origin."""
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    test_origins = ["https://evil.com", "null", f"https://attacker.{url.split('//')[-1].split('/')[0]}"]
    issues = []
    for origin in test_origins:
        cmd = f"curl -skI --max-time 8 {proxy_arg} -H 'Origin: {origin}' '{url}' 2>&1"
        _, out, _ = await _run(cmd, 12)
        acao = next((l for l in out.splitlines() if "access-control-allow-origin" in l.lower()), "")
        acac = next((l for l in out.splitlines() if "access-control-allow-credentials" in l.lower()), "")
        if origin in acao or acao.endswith("*"):
            issues.append({
                "origin_sent": origin,
                "acao_header": acao.strip(),
                "credentials_allowed": "true" in acac.lower(),
                "severity": "critical" if "true" in acac.lower() else "high",
            })
    return {
        "tool": "curl-cors",
        "url": url,
        "vulnerable": bool(issues),
        "issues": issues,
        "severity": max((i["severity"] for i in issues), default="info", key=lambda s: {"critical":3,"high":2,"medium":1,"info":0}[s]),
        "finding": "CORS misconfiguration — arbitrary origin reflected" if issues else "No CORS misconfiguration",
    }


async def command_injection_test(url: str, param: str = "", proxy: str = "") -> dict:
    """Quick OS command injection test."""
    if not _tool_available("curl"):
        return {"error": "curl not found", "url": url}
    proxy_arg = f"--proxy '{proxy}'" if proxy else ""
    payloads = [
        (";id", "uid="),
        ("|id", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        ("; sleep 3", None),  # time-based
    ]
    found = []
    for payload, indicator in payloads[:3]:
        test_url = f"{url}{'&' if '?' in url else '?'}{param or 'cmd'}={payload}"
        cmd = f"curl -sk --max-time 10 {proxy_arg} '{test_url}' 2>&1"
        _, out, _ = await _run(cmd, 14)
        if indicator and indicator in out:
            found.append({"payload": payload, "indicator": indicator, "url": test_url})
    return {
        "tool": "curl-cmdi",
        "url": url,
        "param": param,
        "vulnerable": bool(found),
        "confirmed_payloads": found,
        "severity": "critical" if found else "info",
        "finding": "OS Command Injection confirmed — `id` output found" if found else "No command injection found",
    }


async def jwt_analyze(token: str) -> dict:
    """Analyze JWT — check alg:none attack, weak secret, expired."""
    import base64, json as _json
    issues = []
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        header_b64, payload_b64 = parts[0], parts[1]
        # Pad base64
        def decode_part(p):
            p += "=" * (4 - len(p) % 4)
            return _json.loads(base64.urlsafe_b64decode(p))
        header  = decode_part(header_b64)
        payload = decode_part(payload_b64)
        import time
        # alg:none
        if header.get("alg", "").lower() in ("none", ""):
            issues.append({"type": "alg:none", "severity": "critical", "detail": "JWT uses no algorithm — trivially forgeable"})
        # weak algo
        if header.get("alg", "").upper() in ("HS256", "HS384", "HS512"):
            issues.append({"type": "weak-symmetric-key", "severity": "medium",
                           "detail": f"Symmetric algorithm {header.get('alg')} — vulnerable to brute-force"})
        # Expiry check
        exp = payload.get("exp")
        if exp and exp < time.time():
            issues.append({"type": "expired", "severity": "low",
                           "detail": f"Token expired at {exp}"})
        if not exp:
            issues.append({"type": "no-expiry", "severity": "medium",
                           "detail": "JWT has no exp claim — token never expires"})
        # Sensitive claims
        for k in ["password", "passwd", "secret", "admin", "role", "is_admin"]:
            if k in payload:
                issues.append({"type": "sensitive-claim", "severity": "medium",
                               "detail": f"Sensitive claim '{k}' present in payload"})
        return {
            "tool": "jwt-analyzer",
            "token_prefix": token[:30] + "...",
            "header": header,
            "payload": {k: v for k, v in payload.items() if k != "sub"},
            "issues": issues,
            "vulnerable": any(i["severity"] in ("critical", "high") for i in issues),
            "finding": f"{len(issues)} issue(s) found in JWT" if issues else "JWT appears well-configured",
        }
    except Exception as e:
        return {"error": f"JWT parse error: {e}", "token_prefix": token[:30]}
