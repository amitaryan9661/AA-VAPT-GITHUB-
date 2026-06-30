# -*- coding: utf-8 -*-
"""
Agent Episodic Memory
=====================
Stores the full history of every agent run so the agent remembers
what it did in past sessions and can pick up where it left off.

Three memory types:
  1. Episodic  — "In session XYZ I found SMB signing disabled on 192.168.1.10"
  2. Semantic  — ChromaDB RAG (existing chromadb_memory.py)
  3. Working   — current session context (in-memory dict)

Episodic memory is stored in history/agent_sessions.json
"""
from __future__ import annotations
import json
import os
import uuid
import logging
import threading
from datetime import datetime
from typing import Any

log = logging.getLogger("aavapt.agent.memory")

_SESSIONS_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "history", "agent_sessions.json"
)
os.makedirs(os.path.dirname(_SESSIONS_FILE), exist_ok=True)

# Working memory: session_id → {goal, steps, findings, tool_results, ...}
# Protected by _LOCK — concurrent agent sessions write here simultaneously
_working: dict[str, dict] = {}
_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────
#  Session management
# ─────────────────────────────────────────────────────────────

def new_session(goal: str, target: str = "") -> str:
    """Create a new agent session. Returns session_id."""
    sid = str(uuid.uuid4())[:12]
    with _LOCK:
        _working[sid] = {
            "session_id": sid,
            "goal": goal,
            "target": target,
            "started_at": datetime.utcnow().isoformat(),
            "steps": [],          # list of {thought, action, action_input, observation}
            "findings": [],       # confirmed findings this session
            "tool_results": {},   # cache of tool outputs
            "status": "running",
            "final_answer": "",
        }
    log.info("Agent session started: %s | goal: %s", sid, goal[:80])
    return sid


def get_session(sid: str) -> dict | None:
    with _LOCK:
        return _working.get(sid)


def all_sessions() -> list[dict]:
    """Return all sessions: working (in-memory) + persisted (disk), deduped."""
    disk = _load_all_sessions()
    with _LOCK:
        merged = {s["session_id"]: s for s in disk}
        merged.update(_working)
    return list(merged.values())


# ─────────────────────────────────────────────────────────────
#  Step recording
# ─────────────────────────────────────────────────────────────

def record_step(sid: str, thought: str, action: str,
                action_input: dict, observation: Any):
    """Record one ReAct step into working memory."""
    with _LOCK:
        sess = _working.get(sid)
        if not sess:
            return
        step = {
            "step_num": len(sess["steps"]) + 1,
            "ts": datetime.utcnow().isoformat(),
            "thought": thought,
            "action": action,
            "action_input": action_input,
            "observation": _safe_truncate(observation),
        }
        sess["steps"].append(step)
        sess["tool_results"][action] = observation


def record_finding(sid: str, finding: dict):
    """Record a confirmed finding discovered during this session."""
    with _LOCK:
        sess = _working.get(sid)
        if not sess:
            return
        finding["discovered_at"] = datetime.utcnow().isoformat()
        sess["findings"].append(finding)


def complete_session(sid: str, answer: str, status: str = "completed"):
    """Mark session done and persist to disk."""
    with _LOCK:
        sess = _working.get(sid)
        if not sess:
            return
        sess["status"] = status
        sess["final_answer"] = answer
        sess["finished_at"] = datetime.utcnow().isoformat()
    _persist_session(sess)
    log.info("Agent session %s %s", sid, status)


# ─────────────────────────────────────────────────────────────
#  Build context string for LLM
# ─────────────────────────────────────────────────────────────

def build_step_history(sid: str, max_steps: int = 12) -> str:
    """Format recent steps as text for the LLM context window."""
    with _LOCK:
        sess = _working.get(sid)
    if not sess:
        return ""
    steps = sess["steps"][-max_steps:]
    lines = []
    for s in steps:
        lines.append(f"Step {s['step_num']}:")
        if s["thought"]:
            lines.append(f"  THOUGHT: {s['thought']}")
        lines.append(f"  ACTION: {s['action']}({json.dumps(s['action_input'], ensure_ascii=False)[:200]})")
        obs = s["observation"]
        if isinstance(obs, dict):
            obs_str = json.dumps(obs, ensure_ascii=False)[:600]
        else:
            obs_str = str(obs)[:600]
        lines.append(f"  OBSERVATION: {obs_str}")
    return "\n".join(lines)


def build_findings_context(sid: str) -> str:
    with _LOCK:
        sess = _working.get(sid)
    if not sess or not sess["findings"]:
        return "No findings recorded yet."
    lines = [f"Findings so far ({len(sess['findings'])}):"]
    for f in sess["findings"]:
        lines.append(f"  - [{f.get('severity','?').upper()}] {f.get('name','?')} "
                     f"on {f.get('host','?')}:{f.get('port','?')}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
#  Past session recall (episodic)
# ─────────────────────────────────────────────────────────────

def recall_past_sessions(query: str, limit: int = 3) -> list[dict]:
    """Return recent past sessions matching query (simple keyword search)."""
    sessions = _load_all_sessions()
    q = query.lower()
    matches = []
    for s in reversed(sessions):
        text = (s.get("goal", "") + " " + s.get("target", "") + " " +
                s.get("final_answer", "")).lower()
        if q in text or not q:
            matches.append({
                "session_id": s.get("session_id"),
                "goal": s.get("goal"),
                "target": s.get("target"),
                "status": s.get("status"),
                "started_at": s.get("started_at"),
                "finding_count": len(s.get("findings", [])),
                "summary": s.get("final_answer", "")[:200],
            })
        if len(matches) >= limit:
            break
    return matches


# ─────────────────────────────────────────────────────────────
#  Persistence
# ─────────────────────────────────────────────────────────────

def _safe_truncate(obj: Any, max_len: int = 2000) -> Any:
    if isinstance(obj, str) and len(obj) > max_len:
        return obj[:max_len] + "…[truncated]"
    if isinstance(obj, dict):
        return {k: _safe_truncate(v, 500) for k, v in list(obj.items())[:20]}
    return obj


def _persist_session(sess: dict):
    try:
        existing = _load_all_sessions()
        # Replace if exists
        existing = [s for s in existing if s.get("session_id") != sess["session_id"]]
        existing.append(sess)
        # Keep last 100 sessions
        existing = existing[-100:]
        with open(_SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2, default=str)
    except Exception as e:
        log.error("Failed to persist agent session: %s", e)


def _load_all_sessions() -> list[dict]:
    try:
        if os.path.exists(_SESSIONS_FILE):
            with open(_SESSIONS_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []
