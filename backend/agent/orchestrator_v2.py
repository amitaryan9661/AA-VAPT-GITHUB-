# -*- coding: utf-8 -*-
"""
Multi-Agent Orchestrator v2 — Event-Driven Pipeline
=====================================================
Architecture:

  User Input (target)
       │
  ─────┼─────────────────────────────────────────────────────
       ▼
  Phase 0: Quick Recon (nmap top-100, ~30s)
       │  open_ports list → bootstrap downstream agents
  ─────┼─────────────────────────────────────────────────────
       ▼  (PARALLEL — all 3 running simultaneously)
  ┌────┴──────────────────────────────────────────────────┐
  │  Phase 1+2: Concurrent                                │
  │  ┌──────────────────┐    ┌───────────────────────┐   │
  │  │  ReconAgent 🗺️   │    │  VulnScanAgent 🔍     │   │
  │  │  (deep scan)     │    │  (nuclei+nikto+ffuf+  │   │
  │  │  subdomains,     │    │   sqlmap per service) │   │
  │  │  whatweb, ssh,   │    │   → finding_queue ───►│   │
  │  │  smb, ftp        │    └──────────────────────┘│   │
  │  └──────────────────┘              │              │   │
  │                            finding_queue          │   │
  │                                   ▼              │   │
  │                       ┌───────────────────────┐  │   │
  │                       │  ExploitAgent 💥       │  │   │
  │                       │  (real-time PoC per   │  │   │
  │                       │   finding as it        │  │   │
  │                       │   arrives in queue)    │  │   │
  │                       └───────────────────────┘  │   │
  └───────────────────────────────────────────────────┘
       │
  ─────┼─────────────────────────────────────────────────────
       ▼
  Phase 3: Report Agent 📄 (aggregates all findings → HTML+PDF)
       │
       ▼
  Final result + HTML report download link

Each agent streams events via SSE to the frontend, tagged with
their agent name so the 3-panel UI can route correctly.
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
import uuid
from typing import Callable, Awaitable, Optional

from backend.agent.agents.recon_agent      import ReconAgent
from backend.agent.agents.vuln_scan_agent  import VulnScanAgent
from backend.agent.agents.exploit_agent    import ExploitAgent
from backend.agent.agents.report_agent     import ReportAgent
from backend.agent import memory as mem
from backend.agent.planner import parse_goal

log = logging.getLogger("aavapt.orchestrator_v2")


# ── Session event queues (session_id → asyncio.Queue for SSE) ────────
_sse_queues: dict[str, asyncio.Queue] = {}
_pipeline_results: dict[str, dict] = {}


def get_sse_queue(session_id: str) -> asyncio.Queue:
    if session_id not in _sse_queues:
        _sse_queues[session_id] = asyncio.Queue(maxsize=1000)
    return _sse_queues[session_id]


def cleanup_session(session_id: str):
    _sse_queues.pop(session_id, None)
    _pipeline_results.pop(session_id, None)


# ── Main pipeline entry point ─────────────────────────────────────────

async def run_vapt_pipeline(
    target: str,
    session_id: str,
    burp_proxy: str = "",
    extra_options: dict = None,
) -> dict:
    """
    Full VAPT pipeline — 3 agents in coordinated parallel execution.
    Streams all events to SSE queue for session_id.
    Returns final aggregated result dict.
    """
    extra_options = extra_options or {}
    sse_queue = get_sse_queue(session_id)
    all_findings: list[dict] = []
    start = time.time()

    async def stream_cb(event: dict):
        """Route events to SSE queue and WebSocket broadcast."""
        if "session_id" not in event:
            event["session_id"] = session_id
        try:
            sse_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass
        try:
            from backend.ws_manager import ws_manager
            await ws_manager.broadcast(event)
        except Exception:
            pass

    await stream_cb({
        "event": "pipeline_start",
        "session_id": session_id,
        "target": target,
        "agents": ["recon", "vuln_scan", "exploit", "report"],
        "phases": [
            {"phase": 0, "label": "Quick Port Discovery",         "agents": ["recon"],      "mode": "fast"},
            {"phase": 1, "label": "Deep Recon + Vuln Scanning",   "agents": ["recon", "vuln_scan"], "mode": "parallel"},
            {"phase": 2, "label": "Real-Time Exploit PoC",        "agents": ["exploit"],    "mode": "reactive-queue"},
            {"phase": 3, "label": "Report Generation",            "agents": ["report"],     "mode": "sequential"},
        ],
        "message": f"Starting 4-phase VAPT pipeline against {target}",
    })

    # ── Phase 0: Quick nmap (top-100 ports) ─────────────────────────
    await stream_cb({
        "event": "pipeline_phase",
        "phase": 0,
        "label": "Quick Port Discovery",
        "session_id": session_id,
    })

    recon_agent    = ReconAgent()
    open_ports = await recon_agent.run_quick_scan(target, session_id, stream_cb)

    await stream_cb({
        "event": "pipeline_phase_done",
        "phase": 0,
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "session_id": session_id,
    })

    # ── Phase 1+2: Parallel — Recon + VulnScan + Exploit ────────────
    await stream_cb({
        "event": "pipeline_phase",
        "phase": "1+2",
        "label": "Deep Recon | Vulnerability Scanning | Real-Time Exploitation",
        "session_id": session_id,
        "message": "All 3 agents running simultaneously",
    })

    # Shared queue: VulnScan → Exploit
    finding_queue: asyncio.Queue = asyncio.Queue()

    vuln_agent    = VulnScanAgent(finding_queue=finding_queue)
    exploit_agent = ExploitAgent()

    # Build goals
    recon_goal   = f"Complete deep reconnaissance of {target}"
    vuln_goal    = f"Find all vulnerabilities across all services on {target}"
    exploit_goal = f"Exploit confirmed vulnerabilities on {target} in real-time"

    # Create all 3 tasks — truly concurrent
    recon_task = asyncio.create_task(
        recon_agent.run(
            goal=recon_goal,
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
        )
    )

    vuln_task = asyncio.create_task(
        vuln_agent.run_parallel(
            target=target,
            open_ports=open_ports,
            session_id=session_id,
            stream_cb=stream_cb,
            proxy=burp_proxy,
        )
    )

    exploit_task = asyncio.create_task(
        exploit_agent.run_reactive(
            finding_queue=finding_queue,
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
            proxy=burp_proxy,
        )
    )

    # Wait for all 3 to complete
    recon_result, vuln_result, exploit_result = await asyncio.gather(
        recon_task, vuln_task, exploit_task,
        return_exceptions=True,
    )

    # Collect findings from all agents
    agent_results = []
    for result, name, emoji in [
        (recon_result,   "recon",     "🗺️"),
        (vuln_result,    "vuln_scan", "🔍"),
        (exploit_result, "exploit",   "💥"),
    ]:
        if isinstance(result, Exception):
            log.error("%s agent error: %s", name, result)
            result = {"agent": name, "status": "error", "answer": str(result), "findings": [], "steps": []}
        all_findings.extend(result.get("findings", []))
        agent_results.append({
            "agent":    name,
            "emoji":    emoji,
            "status":   result.get("status", "done"),
            "answer":   str(result.get("answer", ""))[:500],
            "steps":    result.get("steps", 0) if isinstance(result.get("steps"), int) else len(result.get("steps", [])),
            "findings": len(result.get("findings", [])),
        })

    await stream_cb({
        "event": "pipeline_phase_done",
        "phase": "1+2",
        "session_id": session_id,
        "total_findings": len(all_findings),
        "agent_results": agent_results,
    })

    # ── Phase 3: Report Generation ────────────────────────────────────
    await stream_cb({
        "event": "pipeline_phase",
        "phase": 3,
        "label": "Final Report Generation",
        "session_id": session_id,
    })

    # Deduplicate findings by id
    seen_ids = set()
    unique_findings = []
    for f in all_findings:
        fid = f.get("id", str(hash(f.get("name","")+f.get("host",""))))
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique_findings.append(f)

    report_agent = ReportAgent(
        aggregated_findings=unique_findings,
        agent_summaries=agent_results,
    )
    try:
        report_result = await report_agent.run(
            goal=f"Generate comprehensive pentest report for {target}",
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
        )
    except Exception as e:
        log.error("Report agent error: %s", e)
        report_result = {"agent": "report", "status": "error", "answer": str(e), "findings": []}

    # Save HTML report to disk
    report_html = ""
    final_report_md = report_result.get("answer", "No report generated.")
    try:
        from backend.webapp_pt.report_html import generate_html_report
        report_html = generate_html_report(
            target=target,
            findings=unique_findings,
            agent_summaries=agent_results,
            attack_chains=exploit_result.get("attack_chains", []) if isinstance(exploit_result, dict) else [],
            markdown_report=final_report_md,
        )
        # Save to file
        import os
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        report_path = os.path.join(reports_dir, f"report_{session_id}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        log.info("HTML report saved: %s", report_path)
    except Exception as e:
        log.warning("HTML report generation failed: %s", e)

    elapsed = round(time.time() - start, 1)

    final = {
        "session_id":     session_id,
        "target":         target,
        "elapsed":        elapsed,
        "total_findings": len(unique_findings),
        "findings":       unique_findings,
        "agents":         agent_results,
        "attack_chains":  exploit_result.get("attack_chains", []) if isinstance(exploit_result, dict) else [],
        "final_report":   final_report_md,
        "report_url":     f"/api/vapt/pipeline/report/{session_id}",
        "status":         "completed",
    }

    _pipeline_results[session_id] = final

    await stream_cb({
        "event": "pipeline_done",
        "session_id": session_id,
        "elapsed": elapsed,
        "total_findings": len(unique_findings),
        "report_url": f"/api/vapt/pipeline/report/{session_id}",
        "attack_chains": len(exploit_result.get("attack_chains", []) if isinstance(exploit_result, dict) else []),
        "message": f"VAPT complete in {elapsed}s — {len(unique_findings)} findings, report ready",
    })

    # Push SSE sentinel
    sse_queue.put_nowait(None)

    # Update memory
    try:
        mem.complete_session(session_id, final_report_md[:500], status="completed")
    except Exception:
        pass

    return final


def get_pipeline_result(session_id: str) -> Optional[dict]:
    return _pipeline_results.get(session_id)
