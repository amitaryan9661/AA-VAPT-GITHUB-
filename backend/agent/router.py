# -*- coding: utf-8 -*-
"""
Agent API Router — FastAPI routes for /api/agent/*
===================================================

Endpoints:
  POST /api/agent/run           — Start agent with natural language input
  GET  /api/agent/session/{id}  — Get session status + steps
  GET  /api/agent/sessions      — List all sessions
  POST /api/agent/approve       — HITL: approve/deny dangerous action
  GET  /api/agent/tools         — List all available tools
  GET  /api/agent/pending       — List pending HITL approvals
  WS   /ws/agent/{session_id}   — Live streaming of agent steps
  POST /api/agent/chat          — Single-shot NL question (no full agent loop)
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel

from backend.agent import react_loop, memory as mem, hitl, tool_registry as registry
from backend.agent.planner import parse_goal
from backend.agent import orchestrator
from backend.ws_manager import ws_manager

log = logging.getLogger("aavapt.agent.router")

router = APIRouter(prefix="/api/agent", tags=["agent"])


# ─────────────────────────────────────────────────────────────
#  Pydantic models
# ─────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    message: str                        # Natural language input
    session_id: Optional[str] = None    # Resume existing session
    target: Optional[str] = ""          # Override target if needed
    stream: bool = True                 # Stream via WebSocket? (always True for WS)


class ApproveRequest(BaseModel):
    approval_id: str
    approved: bool
    reason: Optional[str] = ""


class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = ""


# ─────────────────────────────────────────────────────────────
#  Hook HITL broadcast to ws_manager on startup
# ─────────────────────────────────────────────────────────────

hitl.set_broadcast(ws_manager.broadcast)


# ─────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────

@router.post("/run")
async def agent_run(req: RunRequest):
    """
    Start the AI agent with a natural language instruction.

    Examples:
      {"message": "pentest 192.168.1.50"}
      {"message": "SSL check port 443 on 10.0.0.5"}
      {"message": "Detect attack chains in loaded scan"}
      {"message": "What are the critical findings?"}
      {"message": "Generate a pentest report"}

    The agent runs in the background. Connect to /ws/agent/{session_id}
    to receive live step-by-step streaming.

    Returns session_id immediately — poll /api/agent/session/{id} for results.
    """
    if not req.message.strip():
        raise HTTPException(400, "message cannot be empty")

    # Parse goal to get session_id early (for WebSocket attachment)
    plan = parse_goal(req.message)
    session_id = mem.new_session(plan["goal"], req.target or plan.get("target", ""))

    # Stream callback: broadcast each step via WebSocket
    async def stream(event: dict):
        if "session_id" not in event:
            event["session_id"] = session_id
        try:
            await ws_manager.broadcast(event)
        except Exception:
            pass

    # Run agent in background task
    asyncio.create_task(_run_agent_bg(req.message, session_id, stream))

    return {
        "session_id": session_id,
        "goal": plan["goal"],
        "target": plan.get("target", ""),
        "planned_tools": [t["tool"] for t in plan["initial_tools"]],
        "message": f"Agent started. Connect to /ws/agent/{session_id} for live updates.",
        "ws_url": f"/ws/agent/{session_id}",
    }


async def _run_agent_bg(user_input: str, session_id: str, stream_cb):
    """Background task wrapper with error handling."""
    try:
        await react_loop.run_agent(user_input, session_id=session_id, stream_cb=stream_cb)
    except Exception as e:
        log.error("Agent background error: %s", e)
        mem.complete_session(session_id, f"Agent error: {e}", status="error")
        try:
            await ws_manager.broadcast({
                "event": "agent_error",
                "session_id": session_id,
                "error": str(e),
            })
        except Exception:
            pass


@router.post("/run/sync")
async def agent_run_sync(req: RunRequest):
    """
    Run agent synchronously and return full result.
    Warning: may take minutes for full pentest. Use /run + WebSocket for large tasks.
    """
    if not req.message.strip():
        raise HTTPException(400, "message cannot be empty")

    async def stream(event: dict):
        try:
            await ws_manager.broadcast(event)
        except Exception:
            pass

    result = await react_loop.run_agent(req.message, stream_cb=stream)
    return result


@router.get("/session/{session_id}")
async def agent_session(session_id: str):
    """Get agent session status, steps, findings, and final answer."""
    sess = mem.get_session(session_id)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    return sess


@router.get("/sessions")
async def agent_sessions():
    """List all agent sessions (current + completed)."""
    sessions = mem.all_sessions()
    return {
        "total": len(sessions),
        "sessions": [
            {
                "session_id": s["session_id"],
                "goal": s["goal"],
                "target": s.get("target",""),
                "status": s["status"],
                "started_at": s["started_at"],
                "step_count": len(s.get("steps",[])),
                "finding_count": len(s.get("findings",[])),
                "final_answer": s.get("final_answer","")[:200],
            }
            for s in sessions
        ],
    }


@router.post("/approve")
async def agent_approve(req: ApproveRequest):
    """
    HITL: Human approves or denies a dangerous agent action.

    The agent pauses and waits for this response before executing
    dangerous tools like brute_force_ssh or run_metasploit_module.
    """
    ok = hitl.respond(req.approval_id, req.approved)
    if not ok:
        raise HTTPException(404, f"Approval {req.approval_id} not found or already resolved")
    action = "APPROVED" if req.approved else "DENIED"
    log.info("HITL: %s → %s", req.approval_id, action)
    try:
        await ws_manager.broadcast({
            "event": "agent_approval_response",
            "approval_id": req.approval_id,
            "approved": req.approved,
            "reason": req.reason,
        })
    except Exception:
        pass
    return {"ok": True, "approval_id": req.approval_id, "action": action}


@router.get("/pending")
async def agent_pending_approvals():
    """List all pending HITL approval requests."""
    return {"pending": hitl.pending_approvals()}


@router.get("/tools")
async def agent_tools():
    """List all tools available to the agent."""
    return {
        "total": len(registry.TOOLS),
        "tools": registry.TOOLS,
    }


# ─────────────────────────────────────────────────────────────
#  Multi-Agent routes
# ─────────────────────────────────────────────────────────────

@router.post("/multi/run")
async def multi_agent_run(req: RunRequest):
    """
    Run full multi-agent pentest pipeline in background.

    Phase 1 (parallel): ReconAgent + WebAgent
    Phase 2 (sequential): ExploitAgent
    Phase 3 (final): ReportAgent

    Returns session_id immediately.
    Connect to /ws/agent/{session_id} for live streaming.
    """
    if not req.message.strip():
        raise HTTPException(400, "message cannot be empty")

    from backend.agent.planner import parse_goal as pg
    plan = pg(req.message)
    session_id = mem.new_session(plan["goal"], plan.get("target",""))

    async def stream(event: dict):
        # Preserve per-agent session_id if set, otherwise use orchestrator session_id
        if "session_id" not in event:
            event["session_id"] = session_id
        try:
            await ws_manager.broadcast(event)
        except Exception:
            pass

    asyncio.create_task(_run_multi_bg(req.message, session_id, stream))

    return {
        "session_id": session_id,
        "goal": plan["goal"],
        "target": plan.get("target",""),
        "mode": "multi-agent",
        "agents": ["recon", "web", "exploit", "report"],
        "phases": 3,
        "message": f"Multi-agent started. Connect to /ws/agent/{session_id} for live updates.",
        "ws_url": f"/ws/agent/{session_id}",
    }


async def _run_multi_bg(user_input: str, session_id: str, stream_cb):
    """Background wrapper for multi-agent orchestrator."""
    try:
        await orchestrator.run_multi_agent(user_input, session_id=session_id, stream_cb=stream_cb)
    except Exception as e:
        log.error("Multi-agent error: %s", e)
        mem.complete_session(session_id, f"Error: {e}", status="error")
        try:
            await ws_manager.broadcast({
                "event": "orchestrator_error",
                "session_id": session_id,
                "error": str(e),
            })
        except Exception:
            pass


@router.get("/multi/agents")
async def multi_agent_list():
    """List all specialist agents and their capabilities."""
    return {
        "agents": [
            {
                "name": "recon",
                "emoji": "🗺️",
                "role": "Network Reconnaissance Specialist",
                "tools": ["nmap_scan", "ssh_audit", "ftp_check", "smb_check"],
                "phase": 1,
                "parallel": True,
            },
            {
                "name": "web",
                "emoji": "🕷️",
                "role": "Web Application Security Specialist",
                "tools": ["check_ssl", "http_headers_check", "nikto_scan"],
                "phase": 1,
                "parallel": True,
            },
            {
                "name": "exploit",
                "emoji": "💥",
                "role": "Exploit & Attack Chain Specialist",
                "tools": ["detect_attack_chains", "epss_check", "brute_force_ssh", "run_metasploit_module"],
                "phase": 2,
                "parallel": False,
            },
            {
                "name": "report",
                "emoji": "📄",
                "role": "Pentest Report Specialist",
                "tools": ["generate_report"],
                "phase": 3,
                "parallel": False,
            },
        ]
    }


@router.post("/plan")
async def agent_plan(req: ChatRequest):
    """Preview what plan the agent would make for a given input (dry run, no execution)."""
    plan = parse_goal(req.message)
    return plan


@router.post("/chat")
async def agent_chat(req: ChatRequest):
    """
    Single-shot AI chat — answer a question using loaded scan data + memory.
    Faster than full agent loop — no tool execution, just AI reasoning.
    """
    from backend.ai import ollama_client as ai
    from backend import findings_store
    from backend.ai import chromadb_memory as cm

    if not ai.is_ollama_running():
        raise HTTPException(503, "Ollama not running")

    findings = findings_store.get_all()
    memory = cm.search_similar(req.message, n_results=3)
    mem_ctx = cm.build_memory_context(memory)

    ctx = (
        f"Loaded scan: {len(findings)} findings\n"
        f"Top findings: {json.dumps(findings[:10], ensure_ascii=False)[:1000]}\n\n"
        f"Memory context:\n{mem_ctx}\n\n"
        + (f"Additional context: {req.context}" if req.context else "")
    )
    answer = await ai.chat_finding(req.message, ctx)
    return {
        "question": req.message,
        "answer": answer,
        "model": ai.get_available_model(),
        "findings_used": len(findings),
    }


# ─────────────────────────────────────────────────────────────
#  WebSocket — live agent streaming
# ─────────────────────────────────────────────────────────────

@router.websocket("/ws/{session_id}")
async def agent_ws(ws: WebSocket, session_id: str):
    """
    Subscribe to live streaming of a running agent session.

    Receives JSON events:
      agent_start       — session started, goal + planned tools
      agent_thinking    — LLM is deciding next action
      agent_step        — thought + action + action_input
      agent_tool_start  — tool execution began
      agent_tool_done   — tool execution finished
      agent_observation — observation from tool
      agent_hitl_required — dangerous action needs approval
      agent_approval_response — human approved/denied
      agent_done        — session complete, final answer
      agent_error       — something went wrong
    """
    await ws.accept()
    log.info("Agent WS connected for session %s", session_id)
    try:
        # Send current session state immediately
        sess = mem.get_session(session_id)
        if sess:
            await ws.send_text(json.dumps({
                "event": "session_state",
                "session": {
                    "session_id": sess["session_id"],
                    "goal": sess["goal"],
                    "status": sess["status"],
                    "step_count": len(sess.get("steps", [])),
                },
            }))
        # Keep connection alive
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=30)
                if msg == "ping":
                    await ws.send_text(json.dumps({"event": "pong"}))
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"event": "heartbeat"}))
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    finally:
        log.info("Agent WS disconnected for session %s", session_id)
