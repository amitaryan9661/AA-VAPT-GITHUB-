# -*- coding: utf-8 -*-
"""
Human-in-the-Loop (HITL)
========================
When the agent wants to run a DANGEROUS action (brute force, Metasploit, etc.),
it must wait for explicit human approval via WebSocket before executing.

Flow:
  1. Agent calls dangerous tool
  2. HITL sends approval_required event to frontend
  3. Human clicks Approve / Deny in the chat UI
  4. Frontend sends approval via POST /api/agent/approve
  5. Agent resumes with approved=True/False

Approvals expire after APPROVAL_TIMEOUT seconds.
"""
from __future__ import annotations
import asyncio
import uuid
import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Awaitable

log = logging.getLogger("aavapt.agent.hitl")

APPROVAL_TIMEOUT = 120  # seconds

# Pending approvals: approval_id → asyncio.Future
_pending: dict[str, asyncio.Future] = {}
_metadata: dict[str, dict] = {}

# WebSocket broadcast callback (set by router at startup)
_broadcast: Callable[[dict], Awaitable[None]] | None = None


def set_broadcast(fn: Callable[[dict], Awaitable[None]]):
    global _broadcast
    _broadcast = fn


# ─────────────────────────────────────────────────────────────
#  Request approval
# ─────────────────────────────────────────────────────────────

async def request_approval(
    session_id: str,
    tool_name: str,
    args: dict,
    reason: str = "",
) -> bool:
    """
    Pause agent and ask human to approve/deny a dangerous action.
    Returns True if approved, False if denied or timed out.
    """
    approval_id = str(uuid.uuid4())[:8]
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    _pending[approval_id] = fut
    _metadata[approval_id] = {
        "approval_id": approval_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "args": args,
        "reason": reason,
        "requested_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(seconds=APPROVAL_TIMEOUT)).isoformat(),
    }

    log.warning("HITL: approval required — %s [%s]", tool_name, approval_id)

    # Notify frontend
    if _broadcast:
        try:
            await _broadcast({
                "event": "agent_approval_required",
                "approval_id": approval_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "args": {k: str(v)[:200] for k, v in args.items()},
                "reason": reason or f"'{tool_name}' is a dangerous action and requires your approval.",
                "expires_in": APPROVAL_TIMEOUT,
            })
        except Exception as e:
            log.error("HITL broadcast error: %s", e)

    # Wait for human response or timeout
    try:
        approved = await asyncio.wait_for(fut, timeout=APPROVAL_TIMEOUT)
        log.info("HITL: %s → %s by human", tool_name, "APPROVED" if approved else "DENIED")
        return approved
    except asyncio.TimeoutError:
        log.warning("HITL: approval timed out for %s", tool_name)
        _cleanup(approval_id)
        if _broadcast:
            try:
                await _broadcast({
                    "event": "agent_approval_timeout",
                    "approval_id": approval_id,
                    "session_id": session_id,
                    "tool_name": tool_name,
                })
            except Exception:
                pass
        return False


def respond(approval_id: str, approved: bool) -> bool:
    """Called when human approves/denies via the API. Returns False if not found."""
    fut = _pending.get(approval_id)
    if not fut or fut.done():
        return False
    # Schedule on the running loop safely (called from sync context via FastAPI)
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(fut.set_result, approved)
    except RuntimeError:
        # No running loop — set directly (test / sync context)
        fut.set_result(approved)
    _cleanup(approval_id)
    return True


def _cleanup(approval_id: str):
    _pending.pop(approval_id, None)
    _metadata.pop(approval_id, None)


def pending_approvals() -> list[dict]:
    return list(_metadata.values())
