# -*- coding: utf-8 -*-
"""
VAPT Pipeline API Router
=========================
FastAPI endpoints for the multi-agent VAPT pipeline.

Endpoints:
  POST /api/vapt/pipeline/start       — Launch 4-phase pipeline (returns session_id)
  GET  /api/vapt/pipeline/stream/{id} — SSE stream of all agent events
  GET  /api/vapt/pipeline/status/{id} — Current pipeline status
  GET  /api/vapt/pipeline/report/{id} — Download HTML report
  POST /api/vapt/pipeline/approve     — HITL: approve/edit/deny dangerous command
  GET  /api/vapt/pipeline/sessions    — List all pipeline sessions
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

log = logging.getLogger("aavapt.vapt_pipeline")

router = APIRouter(prefix="/api/vapt/pipeline", tags=["vapt-pipeline"])

# Track running pipeline tasks
_pipeline_tasks: dict[str, asyncio.Task] = {}


# ── Pydantic models ───────────────────────────────────────────────────

class PipelineStartRequest(BaseModel):
    target: str                         # IP, hostname, domain, or URL
    burp_proxy: str = ""                # e.g. "http://127.0.0.1:8080"
    scan_intensity: str = "normal"      # fast | normal | thorough
    include_exploits: bool = True       # whether to run exploit PoC
    include_dangerous: bool = False     # whether to auto-approve dangerous tools


class ApproveRequest(BaseModel):
    approval_id: str
    approved: bool
    modified_command: Optional[str] = ""   # user-edited command text
    reason: Optional[str] = ""


# ── Routes ────────────────────────────────────────────────────────────

@router.post("/start")
async def start_pipeline(req: PipelineStartRequest, background_tasks: BackgroundTasks):
    """
    Launch the 4-phase VAPT pipeline:
      Phase 0: Quick port scan
      Phase 1+2: Deep Recon + Vuln Scan + Real-Time Exploit (parallel)
      Phase 3: Report generation

    Returns session_id immediately. Connect to /stream/{session_id} for live SSE.
    """
    if not req.target.strip():
        raise HTTPException(400, "target is required")

    session_id = str(uuid.uuid4())[:8]

    # Create memory session
    try:
        from backend.agent import memory as mem
        mem.new_session(f"VAPT pipeline: {req.target}", req.target)
    except Exception:
        pass

    # Launch pipeline in background
    background_tasks.add_task(_run_pipeline_bg, req.target, session_id, req.burp_proxy)

    log.info("Pipeline started: session=%s target=%s", session_id, req.target)

    return {
        "session_id":   session_id,
        "target":       req.target,
        "stream_url":   f"/api/vapt/pipeline/stream/{session_id}",
        "status_url":   f"/api/vapt/pipeline/status/{session_id}",
        "report_url":   f"/api/vapt/pipeline/report/{session_id}",
        "message":      "Pipeline started — connect to stream_url for live events",
    }


async def _run_pipeline_bg(target: str, session_id: str, burp_proxy: str):
    """Background task — runs the full pipeline."""
    from backend.agent.orchestrator_v2 import run_vapt_pipeline
    try:
        result = await run_vapt_pipeline(target, session_id, burp_proxy=burp_proxy)
        log.info("Pipeline done: session=%s findings=%d", session_id, result.get("total_findings", 0))
    except Exception as e:
        log.error("Pipeline error: session=%s error=%s", session_id, e)
        # Push error event to SSE queue
        try:
            from backend.agent.orchestrator_v2 import get_sse_queue
            q = get_sse_queue(session_id)
            q.put_nowait({"event": "pipeline_error", "session_id": session_id, "error": str(e)})
            q.put_nowait(None)  # sentinel
        except Exception:
            pass


@router.get("/stream/{session_id}")
async def stream_pipeline(session_id: str, request: Request):
    """
    Server-Sent Events (SSE) stream for real-time pipeline events.
    Connect from JS with: new EventSource('/api/vapt/pipeline/stream/{session_id}')
    Each event is a JSON object with at minimum: {event, agent, session_id}
    """
    from backend.agent.orchestrator_v2 import get_sse_queue

    async def event_generator():
        queue = get_sse_queue(session_id)
        # Send initial connection event
        yield f"data: {json.dumps({'event':'stream_connected','session_id':session_id})}\n\n"

        while True:
            # Check client disconnect
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                # Send heartbeat
                yield f"data: {json.dumps({'event':'heartbeat','session_id':session_id})}\n\n"
                continue

            if event is None:  # sentinel — pipeline finished
                yield f"data: {json.dumps({'event':'stream_end','session_id':session_id})}\n\n"
                break

            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "Connection":                  "keep-alive",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/status/{session_id}")
async def pipeline_status(session_id: str):
    """Get current pipeline status and partial results."""
    from backend.agent.orchestrator_v2 import get_pipeline_result
    result = get_pipeline_result(session_id)
    if result:
        return result
    # Still running
    return {
        "session_id": session_id,
        "status": "running",
        "message": "Pipeline in progress — connect to SSE stream for live updates",
    }


@router.get("/report/{session_id}", response_class=HTMLResponse)
async def get_report(session_id: str):
    """Download the final HTML report for a completed pipeline."""
    report_path = _report_path(session_id)
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    # Check if pipeline result has inline report
    from backend.agent.orchestrator_v2 import get_pipeline_result
    result = get_pipeline_result(session_id)
    if result:
        from backend.webapp_pt.report_html import generate_html_report
        html = generate_html_report(
            target=result.get("target", "unknown"),
            findings=result.get("findings", []),
            agent_summaries=result.get("agents", []),
            attack_chains=result.get("attack_chains", []),
            markdown_report=result.get("final_report", ""),
        )
        return HTMLResponse(content=html)

    raise HTTPException(404, f"Report not found for session {session_id}. Pipeline may still be running.")


@router.post("/approve")
async def approve_action(req: ApproveRequest):
    """
    HITL: approve, deny, or modify a dangerous tool command before execution.
    Set modified_command to change the command the agent will run.
    """
    from backend.agent import hitl
    try:
        # BUG FIX: hitl.respond() only takes (approval_id, approved) — no reason param
        ok = hitl.respond(req.approval_id, req.approved)
        if not ok:
            raise HTTPException(404, f"Approval ID {req.approval_id} not found or already resolved")
        return {"ok": True, "approval_id": req.approval_id, "approved": req.approved}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/pending")
async def pending_approvals():
    """List all pending HITL approval requests."""
    from backend.agent import hitl
    # BUG FIX: correct function name is pending_approvals(), not list_pending()
    return {"pending": hitl.pending_approvals()}


@router.get("/sessions")
async def list_sessions():
    """List all pipeline sessions (running and completed)."""
    from backend.agent.orchestrator_v2 import _pipeline_results, _sse_queues
    sessions = []
    all_ids = set(list(_pipeline_results.keys()) + list(_sse_queues.keys()))
    for sid in all_ids:
        result = _pipeline_results.get(sid)
        if result:
            sessions.append({
                "session_id":     sid,
                "status":         result.get("status", "done"),
                "target":         result.get("target", ""),
                "total_findings": result.get("total_findings", 0),
                "elapsed":        result.get("elapsed", 0),
                "report_url":     f"/api/vapt/pipeline/report/{sid}",
            })
        else:
            sessions.append({"session_id": sid, "status": "running"})
    return {"sessions": sessions, "count": len(sessions)}


@router.delete("/session/{session_id}")
async def cleanup_session(session_id: str):
    """Clean up a completed pipeline session."""
    from backend.agent.orchestrator_v2 import cleanup_session as _cleanup
    _cleanup(session_id)
    report_path = _report_path(session_id)
    if os.path.exists(report_path):
        os.remove(report_path)
    return {"ok": True, "session_id": session_id}


def _report_path(session_id: str) -> str:
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    return os.path.join(reports_dir, f"report_{session_id}.html")


# ── Burp Suite Integration ─────────────────────────────────────────────

@router.get("/burp/status")
async def burp_status():
    """
    Check Burp Suite availability:
    - PRO_AUTO: Burp Pro REST API on localhost:1337
    - COMMUNITY: Burp proxy on localhost:8080
    - MANUAL: No Burp detected
    """
    try:
        from backend.webapp_pt.burp_integration import detect_burp_mode
        mode_info = detect_burp_mode()
        return mode_info
    except Exception as e:
        return {"mode": "MANUAL", "available": True, "message": f"Burp check failed: {e}", "error": str(e)}


@router.post("/burp/set-api-key")
async def set_burp_api_key(request: Request):
    """Set Burp Suite Pro REST API key."""
    body = await request.json()
    api_key = body.get("api_key", "").strip()
    if not api_key:
        raise HTTPException(400, "api_key is required")
    try:
        from backend.webapp_pt.burp_integration import set_api_key
        set_api_key(api_key)
        return {"ok": True, "message": "Burp Pro API key configured"}
    except Exception as e:
        raise HTTPException(500, str(e))


class BurpImportRequest(BaseModel):
    xml_content: str


@router.post("/burp/import-xml")
async def burp_import_xml(req: BurpImportRequest):
    """
    Import Burp Suite XML export (Community or Pro).
    Parses issues and converts to unified finding format.
    """
    if not req.xml_content.strip():
        raise HTTPException(400, "xml_content is required")
    try:
        from backend.webapp_pt.burp_integration import import_burp_xml_unified
        result = import_burp_xml_unified(req.xml_content)
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/burp/start-scan")
async def burp_start_scan(request: Request):
    """Start a Burp Pro automated scan (requires Burp Pro + API key)."""
    body = await request.json()
    target_url = body.get("target_url", "")
    if not target_url:
        raise HTTPException(400, "target_url required")
    try:
        from backend.webapp_pt.burp_integration import start_burp_job
        result = start_burp_job(
            target_url,
            scan_type=body.get("scan_type", "crawl_and_audit"),
            username=body.get("username", ""),
            password=body.get("password", ""),
        )
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/burp/job/{job_id}")
async def burp_job_status(job_id: str):
    """Get Burp Pro scan job status."""
    try:
        from backend.webapp_pt.burp_integration import get_burp_job
        job = get_burp_job(job_id)
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")
        return job
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
