# -*- coding: utf-8 -*-
"""
Vulnerability Scanner Agent 🔍
================================
Dedicated parallel vulnerability scanner.

Strategy:
  - Receives open_ports from Recon Agent
  - Runs tool-per-service in parallel asyncio tasks
  - Each confirmed finding is pushed to finding_queue immediately
  - ExploitAgent reads from finding_queue in real-time for instant PoC

Tools per service type:
  HTTP/HTTPS  → nuclei_scan + nikto_scan + http_headers_check + check_ssl + ffuf_scan
  SSH         → ssh_audit
  FTP         → ftp_check
  SMB         → smb_check
  Any         → nuclei_scan (always)
  Domain      → subfinder_scan (already done by recon, but cross-check)
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import Callable, Awaitable, Optional

from backend.agent.agents.base_agent import BaseAgent

log = logging.getLogger("aavapt.agent.vuln_scan")


class VulnScanAgent(BaseAgent):
    NAME  = "vuln_scan"
    ROLE  = "Vulnerability Scanner"
    EMOJI = "🔍"
    TOOLS = [
        {
            "name": "nuclei_scan",
            "description": "Run Nuclei — fast template-based CVE and misconfiguration scanner (best for web targets)",
            "parameters": {
                "target": "URL or IP e.g. http://10.0.0.1 or 10.0.0.1",
                "templates": "template categories: cves,exposures,technologies,misconfiguration,default-logins",
                "severity": "severity filter: critical,high,medium",
            },
        },
        {
            "name": "nikto_scan",
            "description": "Run Nikto — web server misconfiguration scanner (outdated software, dangerous files, XSS hints)",
            "parameters": {"url": "full URL e.g. http://10.0.0.1:8080/"},
        },
        {
            "name": "http_headers_check",
            "description": "Check security headers — CSP, HSTS, X-Frame-Options, CORS wildcard",
            "parameters": {"url": "full URL"},
        },
        {
            "name": "check_ssl",
            "description": "Full SSL/TLS audit — weak ciphers, cert validity, heartbleed, POODLE",
            "parameters": {"host": "target hostname/IP", "port": "HTTPS port (default 443)"},
        },
        {
            "name": "ffuf_scan",
            "description": "Directory/endpoint brute-force — find hidden paths, admin panels, backups",
            "parameters": {
                "url": "base URL e.g. http://10.0.0.1/",
                "wordlist": "wordlist path (default: /usr/share/seclists/Discovery/Web-Content/common.txt)",
                "extensions": "file extensions e.g. php,html,txt,js",
            },
        },
        {
            "name": "sqlmap_scan",
            "description": "SQLMap — automated SQL injection detection on web endpoints",
            "parameters": {
                "url": "target URL e.g. http://10.0.0.1/login.php",
                "data": "POST data string (optional)",
                "params": "specific parameter to test (optional)",
            },
        },
        {
            "name": "ssh_audit",
            "description": "Audit SSH for weak algorithms and configuration",
            "parameters": {"host": "target IP", "port": "SSH port (default 22)"},
        },
        {
            "name": "smb_check",
            "description": "SMB vulnerability check — EternalBlue, null session, SMBv1",
            "parameters": {"host": "target IP"},
        },
        {
            "name": "ftp_check",
            "description": "FTP vulnerability check — anonymous login, backdoors",
            "parameters": {"host": "target IP", "port": "FTP port (default 21)"},
        },
        {
            "name": "finish",
            "description": "All vulnerability scans complete — return full findings summary",
            "parameters": {"answer": "summary of all vulnerabilities found with severity ratings"},
        },
    ]

    def __init__(self, finding_queue: Optional[asyncio.Queue] = None):
        super().__init__()
        self._finding_queue = finding_queue  # shared queue for ExploitAgent

    # ── Parallel scan per open_ports list (called by orchestrator_v2) ──
    async def run_parallel(
        self,
        target: str,
        open_ports: list[dict],
        session_id: str,
        stream_cb: Callable[[dict], Awaitable[None]],
        proxy: str = "",
    ) -> dict:
        """
        Run all applicable scans in parallel based on discovered ports.
        Push each finding to self._finding_queue as soon as it's confirmed.
        Returns aggregated results dict.
        """
        self.status = "running"
        self.findings = []

        await self._emit(stream_cb, {
            "event": "agent_start",
            "agent": self.NAME,
            "role": self.ROLE,
            "emoji": self.EMOJI,
            "goal": f"Parallel vulnerability scan of {target}",
            "target": target,
            "session_id": session_id,
            "port_count": len(open_ports),
            "message": f"Starting parallel vuln scans on {len(open_ports)} discovered services",
        })

        # Categorize ports
        http_ports, https_ports, ssh_ports, ftp_ports, smb_ports = [], [], [], [], []
        for p in open_ports:
            port_num = p.get("port", 0)
            service  = p.get("service", "").lower()
            if port_num in (443, 8443) or "https" in service:
                https_ports.append(p)
            elif port_num in (80, 8080, 8888, 3000, 5000, 8000, 8181) or "http" in service:
                http_ports.append(p)
            if port_num == 22 or "ssh" in service:
                ssh_ports.append(p)
            if port_num == 21 or "ftp" in service:
                ftp_ports.append(p)
            if port_num in (445, 139) or "smb" in service or "netbios" in service:
                smb_ports.append(p)

        # Build all scan tasks
        tasks = []

        # Nuclei against main target (always run)
        tasks.append(self._wrap_scan("nuclei_scan", self._nuclei_task, target,
                                     _session_id=session_id, _stream_cb=stream_cb, proxy=proxy))

        # HTTP tasks
        for p in http_ports[:3]:  # limit to 3 HTTP ports
            port_num = p.get("port", 80)
            url = f"http://{target}:{port_num}/"
            tasks.append(self._wrap_scan("nikto_scan",         self._nikto_task,   url,
                                          _session_id=session_id, _stream_cb=stream_cb, proxy=proxy))
            tasks.append(self._wrap_scan("http_headers_check", self._headers_task, url,
                                          _session_id=session_id, _stream_cb=stream_cb))
            tasks.append(self._wrap_scan("ffuf_scan",          self._ffuf_task,    url,
                                          _session_id=session_id, _stream_cb=stream_cb, proxy=proxy))

        # HTTPS tasks
        for p in https_ports[:2]:
            port_num = p.get("port", 443)
            url = f"https://{target}:{port_num}/"
            tasks.append(self._wrap_scan("check_ssl",          self._ssl_task,     target, port_num,
                                          _session_id=session_id, _stream_cb=stream_cb))
            tasks.append(self._wrap_scan("nikto_scan",         self._nikto_task,   url,
                                          _session_id=session_id, _stream_cb=stream_cb, proxy=proxy))
            tasks.append(self._wrap_scan("http_headers_check", self._headers_task, url,
                                          _session_id=session_id, _stream_cb=stream_cb))

        # SSH tasks
        for p in ssh_ports[:1]:
            tasks.append(self._wrap_scan("ssh_audit", self._ssh_task, target, p.get("port", 22),
                                          _session_id=session_id, _stream_cb=stream_cb))

        # FTP tasks
        for p in ftp_ports[:1]:
            tasks.append(self._wrap_scan("ftp_check", self._ftp_task, target, p.get("port", 21),
                                          _session_id=session_id, _stream_cb=stream_cb))

        # SMB tasks
        if smb_ports:
            tasks.append(self._wrap_scan("smb_check", self._smb_task, target,
                                          _session_id=session_id, _stream_cb=stream_cb))

        # Run all in parallel (with concurrency limit)
        semaphore = asyncio.Semaphore(6)
        async def limited(t):
            async with semaphore:
                return await t

        results = await asyncio.gather(*[limited(t) for t in tasks], return_exceptions=True)

        # Signal finding_queue that vuln scan is done
        if self._finding_queue is not None:
            await self._finding_queue.put(None)  # sentinel

        self.status = "done"
        await self._emit(stream_cb, {
            "event": "agent_done",
            "agent": self.NAME,
            "emoji": self.EMOJI,
            "session_id": session_id,
            "final_answer": f"Found {len(self.findings)} vulnerabilities across {len(open_ports)} services",
            "finding_count": len(self.findings),
            "findings": self.findings,
        })

        return {
            "agent": self.NAME,
            "status": "done",
            "findings": self.findings,
            "finding_count": len(self.findings),
            "answer": f"{len(self.findings)} vulnerabilities found",
            "steps": self.steps,
        }

    # ── Individual scan wrappers ───────────────────────────────────

    async def _wrap_scan(self, scan_name: str, fn, *fn_args,
                         _session_id: str = "", _stream_cb=None, **kwargs):
        """
        Run a scan function, emit progress, harvest findings, push to queue.
        _session_id and _stream_cb are keyword-only meta args, not forwarded to fn.
        """
        session_id = _session_id
        stream_cb  = _stream_cb
        try:
            await self._emit(stream_cb, {
                "event": "agent_tool_start",
                "agent": self.NAME,
                "tool": scan_name,
                "session_id": session_id,
                "message": f"Running {scan_name}...",
            })
            result = await fn(*fn_args, **kwargs)
            new_findings = self._harvest_vuln_findings(scan_name, result)
            # Push each new finding to queue immediately
            if self._finding_queue is not None:
                for f in new_findings:
                    await self._finding_queue.put(f)
            await self._emit(stream_cb, {
                "event": "agent_observation",
                "agent": self.NAME,
                "tool": scan_name,
                "session_id": session_id,
                "new_findings": len(new_findings),
                "observation_preview": str(result)[:300],
            })
            return result
        except Exception as e:
            log.warning("vuln_scan %s error: %s", scan_name, e)
            return {"error": str(e)}

    async def _nuclei_task(self, target, proxy=""):
        from backend.agent import kali_tools as kt
        return await kt.nuclei_scan(target, proxy=proxy)

    async def _nikto_task(self, url, proxy=""):
        from backend.agent import kali_tools as kt
        return await kt.nikto_scan(url)

    async def _headers_task(self, url):
        from backend.agent import kali_tools as kt
        return await kt.http_headers_check(url)

    async def _ffuf_task(self, url, proxy=""):
        from backend.agent import kali_tools as kt
        return await kt.ffuf_scan(url, proxy=proxy)

    async def _ssl_task(self, host, port):
        from backend.agent import kali_tools as kt
        return await kt.check_ssl(host, port)

    async def _ssh_task(self, host, port):
        from backend.agent import kali_tools as kt
        return await kt.ssh_audit(host, port)

    async def _ftp_task(self, host, port):
        from backend.agent import kali_tools as kt
        return await kt.ftp_check(host, port)

    async def _smb_task(self, host):
        from backend.agent import kali_tools as kt
        return await kt.smb_check(host)

    # ── Finding harvester ──────────────────────────────────────────

    def _harvest_vuln_findings(self, tool: str, result: dict) -> list[dict]:
        """Extract structured findings and add to self.findings."""
        if not isinstance(result, dict):
            return []
        new = []

        if tool == "nuclei_scan":
            for item in result.get("findings", []):
                f = {
                    "id": f"nuclei-{item.get('template_id', 'unknown')}",
                    "name": item.get("name", item.get("template_id", "Nuclei Finding")),
                    "severity": item.get("severity", "info"),
                    "host": item.get("matched_at", result.get("target", "")),
                    "source": "nuclei",
                    "description": item.get("description", ""),
                    "cve": item.get("cve", []),
                    "cvss_score": item.get("cvss_score"),
                    "tags": item.get("tags", []),
                    "exploit_hint": self._exploit_hint_for(item),
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "nikto_scan":
            for finding in result.get("findings", []):
                severity = "medium"
                if any(kw in finding.lower() for kw in ("sql", "xss", "injection", "rce", "exec", "critical")):
                    severity = "high"
                elif any(kw in finding.lower() for kw in ("ssl", "weak", "missing", "deprecated")):
                    severity = "low"
                f = {
                    "id": f"nikto-{abs(hash(finding)) % 99999}",
                    "name": finding[:100],
                    "severity": severity,
                    "host": result.get("url", ""),
                    "source": "nikto",
                    "description": finding,
                    "exploit_hint": self._exploit_hint_for({"name": finding, "tags": []}),
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "http_headers_check":
            for issue in result.get("issues", []):
                f = {
                    "id": f"headers-{abs(hash(issue)) % 99999}",
                    "name": issue[:80],
                    "severity": "high" if "cors" in issue.lower() else "medium",
                    "host": result.get("url", ""),
                    "source": "http-headers",
                    "description": issue,
                    "exploit_hint": "cors_misconfiguration_test" if "cors" in issue.lower() else None,
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "check_ssl":
            for issue in result.get("issues", []):
                sev = "high" if any(kw in issue.lower() for kw in ("heartbleed", "poodle", "beast", "vulnerable")) else "medium"
                f = {
                    "id": f"ssl-{abs(hash(issue)) % 99999}",
                    "name": f"SSL/TLS: {issue[:60]}",
                    "severity": sev,
                    "host": result.get("target", ""),
                    "source": "ssl",
                    "description": issue,
                    "exploit_hint": None,
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "ffuf_scan":
            interesting = [r for r in result.get("results", []) if r.get("status") in (200, 401, 403)]
            for r in interesting[:20]:
                url = r.get("url", "")
                status = r.get("status", 0)
                sev = "high" if any(kw in url.lower() for kw in ("admin", "backup", "config", ".env", ".git", "phpmyadmin")) else "low"
                f = {
                    "id": f"ffuf-{abs(hash(url)) % 99999}",
                    "name": f"Found path: {url} [{status}]",
                    "severity": sev,
                    "host": result.get("url", ""),
                    "source": "ffuf",
                    "description": f"Directory/file found at {url} — HTTP {status}",
                    "found_url": url,
                    "http_status": status,
                    "exploit_hint": "xss_test" if status == 200 else None,
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "sqlmap_scan":
            if result.get("vulnerable"):
                for param in result.get("injectable_params", []):
                    f = {
                        "id": f"sqli-{abs(hash(result.get('url','')+str(param))) % 99999}",
                        "name": f"SQL Injection in {param.get('param','?')} ({param.get('method','GET')})",
                        "severity": "critical",
                        "host": result.get("url", ""),
                        "source": "sqlmap",
                        "description": f"SQLi confirmed in parameter '{param.get('param')}' via {param.get('method')}. DBMS: {result.get('dbms','unknown')}",
                        "exploit_hint": "sqli_test",
                    }
                    self.findings.append(f)
                    new.append(f)

        elif tool == "ssh_audit":
            for issue in result.get("issues", [])[:10]:
                f = {
                    "id": f"ssh-{abs(hash(issue)) % 99999}",
                    "name": f"SSH: {issue[:60]}",
                    "severity": "medium",
                    "host": result.get("target", ""),
                    "source": "ssh-audit",
                    "description": issue,
                    "exploit_hint": None,
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "smb_check":
            for check in result.get("checks", []):
                sev = "critical" if "ms17-010" in check.lower() or "eternalblue" in check.lower() else "high"
                f = {
                    "id": f"smb-{abs(hash(check)) % 99999}",
                    "name": f"SMB: {check[:60]}",
                    "severity": sev,
                    "host": result.get("host", ""),
                    "source": "smb",
                    "description": check,
                    "exploit_hint": "run_metasploit_module" if sev == "critical" else None,
                }
                self.findings.append(f)
                new.append(f)

        elif tool == "ftp_check":
            if result.get("anonymous_login"):
                f = {
                    "id": f"ftp-anon-{abs(hash(result.get('host',''))) % 99999}",
                    "name": "FTP Anonymous Login Allowed",
                    "severity": "high",
                    "host": f"{result.get('host','')}:{result.get('port',21)}",
                    "source": "ftp",
                    "description": "FTP server allows anonymous login — unauthenticated access possible",
                    "exploit_hint": None,
                }
                self.findings.append(f)
                new.append(f)

        return new

    def _exploit_hint_for(self, finding: dict) -> Optional[str]:
        """Map nuclei finding tags/name to exploit tool to try."""
        name = (finding.get("name", "") + " ".join(finding.get("tags", []))).lower()
        if any(k in name for k in ("xss", "cross-site-scripting")):
            return "xss_test"
        if any(k in name for k in ("sqli", "sql-injection", "sql injection")):
            return "sqli_test"
        if any(k in name for k in ("ssrf", "server-side-request-forgery")):
            return "ssrf_test"
        if any(k in name for k in ("lfi", "local-file-inclusion", "path-traversal")):
            return "lfi_test"
        if any(k in name for k in ("redirect", "open-redirect")):
            return "open_redirect_test"
        if any(k in name for k in ("cors", "cross-origin")):
            return "cors_misconfiguration_test"
        if any(k in name for k in ("command-injection", "rce", "remote-code")):
            return "command_injection_test"
        return None
