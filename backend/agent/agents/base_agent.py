# -*- coding: utf-8 -*-
"""
Base Agent — Parent class for all specialist agents
====================================================
Each specialist agent inherits this and overrides:
  - NAME, ROLE, EMOJI, TOOLS (subset of full tool registry)
  - run(target, session_id, stream_cb) → dict
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
from typing import Callable, Awaitable, Optional

log = logging.getLogger("aavapt.agent.agents.base")

MAX_STEPS = 10
LLM_RETRIES = 3


class BaseAgent:
    NAME:  str = "base"
    ROLE:  str = "Generic agent"
    EMOJI: str = "🤖"
    TOOLS: list[dict] = []          # Override in subclass

    def __init__(self):
        self.steps: list[dict] = []
        self.findings: list[dict] = []
        self.status: str = "idle"   # idle | running | done | error

    # ─────────────────────────────────────────────────────────
    #  Public entry point
    # ─────────────────────────────────────────────────────────
    async def run(
        self,
        goal: str,
        target: str,
        session_id: str,
        stream_cb: Callable[[dict], Awaitable[None]],
        extra_context: str = "",
    ) -> dict:
        """Run this agent's ReAct loop. Returns result dict."""
        self.status = "running"
        self.steps = []
        self.findings = []
        start = time.time()

        await self._emit(stream_cb, {
            "event": "agent_start",
            "agent": self.NAME,
            "role": self.ROLE,
            "emoji": self.EMOJI,
            "goal": goal,
            "target": target,
            "session_id": session_id,
        })

        observation = ""
        for step_num in range(1, MAX_STEPS + 1):
            # ── Think ──────────────────────────────────────
            await self._emit(stream_cb, {
                "event": "agent_thinking",
                "agent": self.NAME,
                "step": step_num,
                "session_id": session_id,
            })

            prompt = self._build_prompt(goal, target, observation, extra_context)
            decision = await self._llm_decide(prompt)

            if not decision:
                break

            thought     = decision.get("thought", "")
            action      = decision.get("action", "finish")
            action_input = decision.get("action_input", {})

            await self._emit(stream_cb, {
                "event": "agent_step",
                "agent": self.NAME,
                "step": step_num,
                "thought": thought,
                "action": action,
                "action_input": action_input,
                "session_id": session_id,
            })

            if action == "finish":
                answer = (action_input or {}).get("answer", observation or "")
                self.status = "done"
                elapsed = round(time.time() - start, 1)
                await self._emit(stream_cb, {
                    "event": "agent_done",
                    "agent": self.NAME,
                    "final_answer": answer,
                    "step_count": step_num,
                    "finding_count": len(self.findings),
                    "elapsed": elapsed,
                    "session_id": session_id,
                })
                return {
                    "agent": self.NAME,
                    "status": "done",
                    "answer": answer,
                    "steps": self.steps,
                    "findings": self.findings,
                    "elapsed": elapsed,
                }

            # ── Execute tool ───────────────────────────────
            await self._emit(stream_cb, {
                "event": "agent_tool_start",
                "agent": self.NAME,
                "tool": action,
                "args": action_input,
                "session_id": session_id,
            })

            observation = await self._execute(action, action_input, session_id, stream_cb)

            self.steps.append({
                "step": step_num,
                "thought": thought,
                "action": action,
                "action_input": action_input,
                "observation": observation,
            })

            await self._emit(stream_cb, {
                "event": "agent_observation",
                "agent": self.NAME,
                "step": step_num,
                "observation_preview": observation[:300],
                "session_id": session_id,
            })

        # Max steps reached
        self.status = "done"
        return {
            "agent": self.NAME,
            "status": "max_steps",
            "answer": observation,
            "steps": self.steps,
            "findings": self.findings,
            "elapsed": round(time.time() - start, 1),
        }

    # ─────────────────────────────────────────────────────────
    #  LLM decision — uses Ollama tool-calling format
    # ─────────────────────────────────────────────────────────
    def _build_tool_schemas(self) -> list:
        """Convert self.TOOLS list → OpenAI/Ollama tool schema format."""
        schemas = []
        for t in self.TOOLS:
            props: dict = {}
            required: list = []
            for pname, pinfo in t.get("parameters", {}).items():
                if isinstance(pinfo, dict):
                    ptype = pinfo.get("type", "string")
                    type_map = {"integer":"integer","boolean":"boolean",
                                "array":"array","object":"object"}
                    jtype = type_map.get(ptype, "string")
                    prop: dict = {"type": jtype, "description": pinfo.get("description","")}
                    if jtype == "array":
                        prop["items"] = {"type": "string"}
                    props[pname] = prop
                    if pinfo.get("required"):
                        required.append(pname)
                else:
                    props[pname] = {"type": "string", "description": str(pinfo)}
            schemas.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                    },
                },
            })
        return schemas

    async def _llm_decide(self, prompt: str) -> Optional[dict]:
        """
        Ask the LLM which tool to call next.
        Uses Ollama native tool-calling format; falls back to JSON-in-text.
        Returns {action, action_input, thought} or None on failure.
        """
        from backend.ai import ollama_client as ai
        tool_schemas = self._build_tool_schemas()
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user",   "content": "What is your next action? Call the appropriate tool."},
        ]
        for attempt in range(LLM_RETRIES):
            try:
                result = await ai.chat_with_tools_async(messages, tool_schemas)
                tc = result.get("tool_call")
                if tc and tc.get("name"):
                    return {
                        "thought":      result.get("content", ""),
                        "action":       tc["name"],
                        "action_input": tc.get("arguments", {}),
                    }
                # Model replied with text instead of a tool call
                text = result.get("content", "")
                if text:
                    # Try extracting JSON from text (older models)
                    extracted = self._extract_json(text)
                    if extracted and "action" in extracted:
                        return extracted
                    # Treat as finish if text looks like a summary
                    return {"thought": text, "action": "finish",
                            "action_input": {"answer": text}}
                log.warning("%s LLM attempt %d: empty response", self.NAME, attempt + 1)
            except Exception as e:
                log.warning("%s LLM attempt %d failed: %s", self.NAME, attempt + 1, e)
            await asyncio.sleep(1)
        return None

    def _extract_json(self, text: str) -> Optional[dict]:
        """Fallback JSON extractor for models that don't support tool_calls."""
        import re
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        try:
            return json.loads(text)
        except Exception:
            pass
        m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        for start in range(len(text)):
            if text[start] != "{":
                continue
            depth, in_str, escape = 0, False, False
            for end in range(start, len(text)):
                ch = text[end]
                if escape:
                    escape = False; continue
                if ch == "\\" and in_str:
                    escape = True; continue
                if ch == '"':
                    in_str = not in_str; continue
                if in_str:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:end+1])
                        except Exception:
                            break
        return None

    # ─────────────────────────────────────────────────────────
    #  Tool dispatcher — routes to kali_tools
    # ─────────────────────────────────────────────────────────
    async def _execute(
        self,
        tool_name: str,
        args: dict,
        session_id: str,
        stream_cb: Callable,
    ) -> str:
        from backend.agent import kali_tools as kt
        from backend.agent import hitl
        from backend.agent.tool_registry import is_dangerous

        # HITL check for dangerous tools
        if is_dangerous(tool_name):
            approved = await hitl.request_approval(
                session_id, tool_name, args,
                reason=f"{self.EMOJI} {self.ROLE} wants to run dangerous tool: {tool_name}"
            )
            if not approved:
                return f"[DENIED] {tool_name} was not approved by human."

        fn_map = {
            "nmap_scan":          lambda: kt.nmap_scan(**args),
            "check_ssl":          lambda: kt.check_ssl(**args),
            "ssh_audit":          lambda: kt.ssh_audit(**args),
            "http_headers_check": lambda: kt.http_headers_check(**args),
            "nikto_scan":         lambda: kt.nikto_scan(**args),
            "smb_check":          lambda: kt.smb_check(**args),
            "ftp_check":          lambda: kt.ftp_check(**args),
            "brute_force_ssh":    lambda: kt.brute_force_ssh(**args),
            "run_metasploit_module": lambda: kt.run_metasploit_module(**args),
        }

        fn = fn_map.get(tool_name)
        if fn:
            try:
                result = await fn()
                obs = json.dumps(result, ensure_ascii=False)
                # Auto-extract findings
                self._harvest_findings(tool_name, result)
                return obs
            except Exception as e:
                return f"[ERROR] {tool_name}: {e}"

        return f"[UNKNOWN TOOL] {tool_name}"

    # ─────────────────────────────────────────────────────────
    #  Auto-harvest findings from tool results
    # ─────────────────────────────────────────────────────────
    def _harvest_findings(self, tool: str, result: dict):
        if not isinstance(result, dict):
            return
        if tool == "nmap_scan":
            for port_info in result.get("open_ports", []):
                self.findings.append({
                    "name": f"Open Port {port_info.get('port')}/{port_info.get('service','')}",
                    "severity": "info",
                    "host": result.get("target"),
                    "port": port_info.get("port"),
                    "source": "nmap",
                })
        elif tool == "check_ssl":
            for issue in result.get("issues", []):
                self.findings.append({
                    "name": f"SSL Issue: {issue}",
                    "severity": "medium",
                    "host": result.get("host"),
                    "port": result.get("port"),
                    "source": "ssl",
                })
        elif tool == "nikto_scan":
            for vuln in result.get("vulnerabilities", [])[:10]:
                self.findings.append({
                    "name": f"Web: {vuln[:80]}",
                    "severity": "medium",
                    "host": result.get("target"),
                    "source": "nikto",
                })

    # ─────────────────────────────────────────────────────────
    #  Prompt builder
    # ─────────────────────────────────────────────────────────
    def _build_prompt(self, goal: str, target: str, last_obs: str, extra: str) -> str:
        tools_json = json.dumps(
            [{"name": t["name"], "description": t["description"], "parameters": t.get("parameters", {})}
             for t in self.TOOLS],
            indent=2, ensure_ascii=False
        )
        history = "\n".join(
            f"Step {s['step']}: {s['action']}({s['action_input']}) → {s['observation'][:200]}"
            for s in self.steps[-5:]
        )
        return f"""You are {self.EMOJI} {self.NAME} — {self.ROLE}.

GOAL: {goal}
TARGET: {target or 'use loaded scan data'}
{f'CONTEXT: {extra}' if extra else ''}

AVAILABLE TOOLS:
{tools_json}

STEP HISTORY (last 5):
{history or 'None yet'}

LAST OBSERVATION:
{last_obs[:500] if last_obs else 'None'}

FINDINGS SO FAR: {len(self.findings)}

Respond ONLY with valid JSON:
{{
  "thought": "reasoning about what to do next",
  "action": "tool_name_or_finish",
  "action_input": {{"param": "value"}}
}}

Use "finish" action when goal is complete:
{{"thought": "done", "action": "finish", "action_input": {{"answer": "summary"}}}}"""

    # ─────────────────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────────────────
    async def _emit(self, cb: Callable, event: dict):
        try:
            await cb(event)
        except Exception:
            pass
