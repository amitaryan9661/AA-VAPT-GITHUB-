# -*- coding: utf-8 -*-
"""
Recon Agent -- Enhanced v2
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Callable, Awaitable, Optional

from backend.agent.agents.base_agent import BaseAgent

log = logging.getLogger("aavapt.agent.recon")


class ReconAgent(BaseAgent):
    NAME  = "recon"
    ROLE  = "Network Reconnaissance Specialist"
    EMOJI = "\U0001f5fa️"
    TOOLS = [
        {
            "name": "nmap_scan",
            "description": "Run nmap to discover open ports, services, OS, version info on target",
            "parameters": {
                "target": "IP or hostname or CIDR",
                "ports": "port range: top100 | top1000 | 1-65535 | 80,443,8080",
                "flags": "extra nmap flags e.g. -sV -sC -O",
            },
        },
        {
            "name": "subfinder_scan",
            "description": "Passive subdomain enumeration -- find all subdomains for a domain target",
            "parameters": {"domain": "root domain e.g. example.com"},
        },
        {
            "name": "whatweb_scan",
            "description": "Tech fingerprinting -- identify CMS, framework, server version on a URL",
            "parameters": {"url": "full URL e.g. http://10.0.0.1/"},
        },
        {
            "name": "ssh_audit",
            "description": "Audit SSH server for weak ciphers, deprecated algorithms, config issues",
            "parameters": {"host": "target IP or hostname", "port": "SSH port (default 22)"},
        },
        {
            "name": "ftp_check",
            "description": "Check FTP for anonymous login, version banner, vsftpd backdoor",
            "parameters": {"host": "target IP", "port": "FTP port (default 21)"},
        },
        {
            "name": "smb_check",
            "description": "Enumerate SMB -- null session, signing, SMBv1, EternalBlue (MS17-010)",
            "parameters": {"host": "target IP"},
        },
        {
            "name": "finish",
            "description": "Recon complete -- return full attack surface summary",
            "parameters": {"answer": "structured summary: open ports, services, OS, subdomains, tech stack"},
        },
    ]

    async def run_quick_scan(
        self,
        target: str,
        session_id: str,
        stream_cb: Callable[[dict], Awaitable[None]],
    ) -> list:
        from backend.agent import kali_tools as kt
        await self._emit(stream_cb, {
            "event": "recon_quick_scan_start",
            "agent": self.NAME,
            "session_id": session_id,
            "target": target,
            "message": "Quick port discovery -- top-100 ports...",
        })
        result = await kt.nmap_scan(target, ports="top100", flags="-sV --open", timeout=45)
        ports = result.get("open_ports", [])
        await self._emit(stream_cb, {
            "event": "recon_quick_scan_done",
            "agent": self.NAME,
            "session_id": session_id,
            "open_ports": ports,
            "port_count": len(ports),
            "nmap_raw": result.get("raw", "")[:2000],
            "message": f"Quick scan found {len(ports)} open ports",
        })
        return ports

    def _build_prompt(self, goal: str, target: str, last_obs: str, extra: str) -> str:
        tools_json = json.dumps(
            [{"name": t["name"], "description": t["description"], "parameters": t.get("parameters", {})}
             for t in self.TOOLS],
            indent=2, ensure_ascii=False,
        )
        history = "\n".join(
            f"Step {s['step']}: {s['action']}({json.dumps(s['action_input'])}) -> {str(s['observation'])[:250]}"
            for s in self.steps[-6:]
        )
        is_domain = (bool(re.match(r"^[a-zA-Z]", target or "")) and
                     "." in (target or "") and
                     not re.match(r"^\d+\.\d+", target or ""))
        domain_hint = ("Target is a DOMAIN -- run subfinder_scan first." if is_domain
                       else "Target is an IP address.")

        done_actions = {s["action"] for s in self.steps}
        if "nmap_scan" not in done_actions:
            next_hint = "Start with nmap_scan (ports=top1000) to map the full attack surface."
        else:
            last_ports = []
            for s in reversed(self.steps):
                if s["action"] == "nmap_scan":
                    try:
                        obs = json.loads(s["observation"])
                        last_ports = obs.get("open_ports", [])
                    except Exception:
                        pass
                    break
            http_ports = [p for p in last_ports
                          if p.get("service","") in ("http","https","http-alt")
                          or p.get("port") in (80,443,8080,8443,8888)]
            ssh_ports  = [p for p in last_ports if p.get("service","") == "ssh" or p.get("port") == 22]
            ftp_ports  = [p for p in last_ports if p.get("service","") == "ftp" or p.get("port") == 21]
            smb_ports  = [p for p in last_ports if p.get("port") in (445,139)]
            hints = []
            if http_ports and "whatweb_scan" not in done_actions:
                port = http_ports[0].get("port", 80)
                proto = "https" if port in (443,8443) else "http"
                hints.append(f"Run whatweb_scan on {proto}://{target}:{port}/")
            if ssh_ports and "ssh_audit" not in done_actions:
                hints.append(f"Run ssh_audit on port {ssh_ports[0].get('port',22)}")
            if ftp_ports and "ftp_check" not in done_actions:
                hints.append(f"Run ftp_check on port {ftp_ports[0].get('port',21)}")
            if smb_ports and "smb_check" not in done_actions:
                hints.append("Run smb_check for SMB enumeration")
            if is_domain and "subfinder_scan" not in done_actions:
                hints.append(f"Run subfinder_scan on {target}")
            if not hints:
                hints.append("All checks done -- use finish action now")
            next_hint = " | ".join(hints)

        return f"""You are {self.EMOJI} {self.NAME} -- {self.ROLE}.

MISSION: {goal}
TARGET: {target} ({domain_hint})
{("EXTRA CONTEXT: " + extra) if extra else ""}

NEXT RECOMMENDED ACTION: {next_hint}

AVAILABLE TOOLS:
{tools_json}

STEP HISTORY (last 6):
{history or "No steps yet"}

LAST OBSERVATION:
{str(last_obs)[:600] if last_obs else "None"}

FINDINGS SO FAR: {len(self.findings)}

Respond ONLY with valid JSON:
{{"thought":"reasoning","action":"tool_name","action_input":{{"param":"value"}}}}

To finish: {{"thought":"done","action":"finish","action_input":{{"answer":"summary"}}}}"""

    async def _execute(self, tool_name: str, args: dict, session_id: str, stream_cb) -> str:
        from backend.agent import kali_tools as kt
        tool_map = {
            "nmap_scan":      lambda: kt.nmap_scan(**args),
            "subfinder_scan": lambda: kt.subfinder_scan(**args),
            "whatweb_scan":   lambda: kt.whatweb_scan(**args),
            "ssh_audit":      lambda: kt.ssh_audit(**args),
            "ftp_check":      lambda: kt.ftp_check(**args),
            "smb_check":      lambda: kt.smb_check(**args),
        }
        fn = tool_map.get(tool_name)
        if fn:
            try:
                result = await fn()
                self._harvest_findings(tool_name, result)
                return json.dumps(result, ensure_ascii=False)
            except Exception as e:
                return f"[ERROR] {tool_name}: {e}"
        return await super()._execute(tool_name, args, session_id, stream_cb)
