# -*- coding: utf-8 -*-
"""
Multi-Agent Orchestrator
========================
Coordinates specialist agents running in parallel.

Flow:
  User Input → Orchestrator
    ├── Phase 1 (parallel): ReconAgent + WebAgent
    ├── Phase 2 (after phase 1): ExploitAgent (uses recon results)
    └── Phase 3 (final): ReportAgent (aggregates everything)

Each agent streams events with their agent name so the UI
can show separate panels per agent.

Usage:
    result = await run_multi_agent(
        goal="Full pentest of 10.0.0.5",
        target="10.0.0.5",
        session_id="abc123",
        stream_cb=my_ws_broadcast,
    )
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
import uuid
from typing import Callable, Awaitable

from backend.agent.agents.recon_agent  import ReconAgent
from backend.agent.agents.web_agent    import WebAgent
from backend.agent.agents.exploit_agent import ExploitAgent
from backend.agent.agents.report_agent  import ReportAgent
from backend.agent import memory as mem
from backend.agent.planner import parse_goal

log = logging.getLogger("aavapt.agent.orchestrator")


# ─────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────

async def run_multi_agent(
    user_input: str,
    session_id: str | None = None,
    stream_cb: Callable[[dict], Awaitable[None]] | None = None,
) -> dict:
    """
    Run full multi-agent pentest pipeline.
    Returns aggregated result dict.
    """
    if stream_cb is None:
        async def stream_cb(_): pass

    plan = parse_goal(user_input)
    goal   = plan["goal"]
    target = plan.get("target", "")

    if not session_id:
        session_id = str(uuid.uuid4())[:8]

    # Only create session if not already created by router
    if not mem.get_session(session_id):
        mem.new_session(goal, target)
    start = time.time()

    await _emit(stream_cb, {
        "event": "orchestrator_start",
        "session_id": session_id,
        "goal": goal,
        "target": target,
        "agents": ["recon", "web", "exploit", "report"],
        "phases": [
            {"phase": 1, "agents": ["recon", "web"], "mode": "parallel"},
            {"phase": 2, "agents": ["exploit"],       "mode": "sequential"},
            {"phase": 3, "agents": ["report"],        "mode": "sequential"},
        ],
    })

    all_findings: list[dict] = []
    agent_results: list[dict] = []

    # ── Phase 1: Recon + Web (parallel) ──────────────────────
    await _emit(stream_cb, {
        "event": "orchestrator_phase",
        "phase": 1,
        "label": "Reconnaissance & Web Scanning",
        "agents": ["recon", "web"],
        "mode": "parallel",
        "session_id": session_id,
    })

    recon_task = asyncio.create_task(
        ReconAgent().run(
            goal=f"Recon: {goal}",
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
        )
    )
    web_task = asyncio.create_task(
        WebAgent().run(
            goal=f"Web security: {goal}",
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
        )
    )

    recon_result, web_result = await asyncio.gather(recon_task, web_task, return_exceptions=True)

    for res, name, emoji in [(recon_result, "recon", "🗺️"), (web_result, "web", "🕷️")]:
        if isinstance(res, Exception):
            log.error("%s agent error: %s", name, res)
            res = {"agent": name, "status": "error", "answer": str(res), "findings": [], "steps": []}
        all_findings.extend(res.get("findings", []))
        agent_results.append({
            "agent": name, "emoji": emoji,
            "status": res.get("status"),
            "answer": res.get("answer","")[:400],
            "steps": len(res.get("steps", [])),
            "findings": len(res.get("findings", [])),
        })

    # ── Phase 2: Exploit (uses recon context) ─────────────────
    await _emit(stream_cb, {
        "event": "orchestrator_phase",
        "phase": 2,
        "label": "Attack Chain Detection & Exploit Analysis",
        "agents": ["exploit"],
        "mode": "sequential",
        "session_id": session_id,
    })

    recon_context = ""
    if not isinstance(recon_result, Exception) and not isinstance(web_result, Exception):
        recon_context = (
            f"Recon found: {recon_result.get('answer','')[:300]}\n"
            f"Web found: {web_result.get('answer','')[:300]}"
        )
    elif not isinstance(recon_result, Exception):
        recon_context = f"Recon found: {recon_result.get('answer','')[:300]}"

    try:
        exploit_result = await ExploitAgent().run(
            goal=f"Exploit analysis: {goal}",
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
            extra_context=recon_context,
        )
    except Exception as e:
        exploit_result = {"agent": "exploit", "status": "error", "answer": str(e), "findings": [], "steps": []}

    all_findings.extend(exploit_result.get("findings", []))
    agent_results.append({
        "agent": "exploit", "emoji": "💥",
        "status": exploit_result.get("status"),
        "answer": exploit_result.get("answer","")[:400],
        "steps": len(exploit_result.get("steps", [])),
        "findings": len(exploit_result.get("findings", [])),
    })

    # ── Phase 3: Report (aggregates everything) ───────────────
    await _emit(stream_cb, {
        "event": "orchestrator_phase",
        "phase": 3,
        "label": "Final Report Generation",
        "agents": ["report"],
        "mode": "sequential",
        "session_id": session_id,
    })

    try:
        report_result = await ReportAgent(
            aggregated_findings=all_findings,
            agent_summaries=agent_results,
        ).run(
            goal=f"Generate pentest report: {goal}",
            target=target,
            session_id=session_id,
            stream_cb=stream_cb,
        )
    except Exception as e:
        report_result = {"agent": "report", "status": "error", "answer": str(e), "findings": [], "steps": []}

    agent_results.append({
        "agent": "report", "emoji": "📄",
        "status": report_result.get("status"),
        "answer": report_result.get("answer","")[:200],
        "steps": len(report_result.get("steps", [])),
        "findings": 0,
    })

    final_report = report_result.get("answer", "No report generated.")
    elapsed = round(time.time() - start, 1)
    total_steps = sum(r.get("steps", 0) for r in agent_results)

    mem.complete_session(session_id, final_report[:500], status="completed")

    result = {
        "session_id": session_id,
        "goal": goal,
        "target": target,
        "elapsed": elapsed,
        "total_steps": total_steps,
        "total_findings": len(all_findings),
        "agents": agent_results,
        "findings": all_findings,
        "final_report": final_report,
    }

    await _emit(stream_cb, {
        "event": "orchestrator_done",
        "session_id": session_id,
        "elapsed": elapsed,
        "total_steps": total_steps,
        "total_findings": len(all_findings),
        "final_report": final_report,
        "agents": agent_results,
    })

    return result


async def _emit(cb: Callable, event: dict):
    try:
        await cb(event)
    except Exception:
        pass
