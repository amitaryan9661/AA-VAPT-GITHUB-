# -*- coding: utf-8 -*-
"""
ReAct Loop — Reason + Act + Observe, repeat until done.
========================================================

Uses Ollama's native tool-calling format (OpenAI-compatible):
  - Tools are passed as JSON schemas via the `tools` parameter
  - The model returns structured `tool_calls` instead of raw JSON text
  - Falls back to JSON-in-text extraction if model doesn't support tool_calls

Each iteration:
  1. THINK  — LLM reads goal + history + tool schemas → picks a tool
  2. ACT    — We execute the chosen tool
  3. OBSERVE— We feed the result back as a "tool" role message
  4. REPEAT — Until action == "finish" or max_steps reached
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Any, Callable, Awaitable, Optional

from backend.agent import tool_registry as registry
from backend.agent import memory as mem
from backend.agent import hitl
from backend.agent import kali_tools
from backend.agent.planner import parse_goal
from backend.ai import ollama_client as ai
from backend.ai import chromadb_memory as chroma_mem
from backend import findings_store

log = logging.getLogger("aavapt.agent.react")

MAX_STEPS = 20
MAX_LLM_RETRIES = 2
AGENT_TIMEOUT = 300  # 5 minutes max per agent run

# ─────────────────────────────────────────────────────────────
#  System prompt
# ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are AA-VAPT, an expert autonomous penetration testing AI agent running on Kali Linux.
You have access to REAL security tools that execute against the target. Follow this workflow:

PENTEST METHODOLOGY:
1. RECON    → nmap_scan (always first), subfinder_scan (if domain)
2. ENUM     → check_ssl (if 443), ssh_audit (if 22), smb_check (if 445), ftp_check (if 21)
             → http_headers_check, whatweb_scan (if HTTP found)
3. WEB SCAN → gobuster_scan or ffuf_scan (find hidden paths), nikto_scan, nuclei_scan
4. VULN TEST→ xss_test, sqli_test, lfi_test, ssrf_test, cors_test, cmd_injection_test
5. EXPLOIT  → brute_force_ssh (HITL), sqlmap_scan (HITL), run_metasploit_module (HITL)
6. ANALYZE  → detect_attack_chains, epss_check (if CVEs found), analyze_finding
7. REPORT   → generate_report (always last)

STRICT RULES:
- ALWAYS call a tool. NEVER reply with plain text only.
- NEVER repeat the same tool+args you already ran.
- Use "think" tool to reason when planning next steps.
- Call "finish" ONLY after generating_report or when all tasks are done.
- If a tool errors, try an alternative or skip it with think+explanation.
- For web targets: always run whatweb_scan then gobuster_scan then nuclei_scan.
- Dangerous tools (brute_force_ssh, sqlmap_scan, run_metasploit_module) require human approval.

CURRENT GOAL: {goal}
TARGET: {target}

STEP HISTORY:
{history}

FINDINGS SO FAR:
{findings}"""


# ─────────────────────────────────────────────────────────────
#  Tool schemas (OpenAI / Ollama tool-calling format)
# ─────────────────────────────────────────────────────────────

def _build_tool_schemas() -> list:
    """Convert tool_registry TOOLS list → Ollama/OpenAI tool schema format."""
    schemas = []
    for t in registry.get_all_tools():
        props = {}
        required = []
        for param_name, param_info in t.get("parameters", {}).items():
            if isinstance(param_info, dict):
                ptype = param_info.get("type", "string")
                # Map registry types → JSON Schema types
                if ptype == "integer":
                    json_type = "integer"
                elif ptype == "boolean":
                    json_type = "boolean"
                elif ptype == "array":
                    json_type = "array"
                elif ptype == "object":
                    json_type = "object"
                else:
                    json_type = "string"
                props[param_name] = {
                    "type": json_type,
                    "description": param_info.get("description", ""),
                }
                if ptype == "array":
                    props[param_name]["items"] = {"type": "string"}
                if param_info.get("required"):
                    required.append(param_name)
            else:
                # Simple string description (old format)
                props[param_name] = {"type": "string", "description": str(param_info)}
        schemas.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"]
                    + (" [DANGEROUS — requires human approval]" if t.get("dangerous") else ""),
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        })
    return schemas


_TOOL_SCHEMAS: list = []  # built lazily on first use

# Tools grouped by phase — send only relevant subset to LLM each step
_PHASE_TOOLS = {
    "recon":   ["nmap_scan", "check_ssl", "ssh_audit", "http_headers_check",
                "smb_check", "ftp_check", "subfinder_scan", "whatweb_scan",
                "think", "finish"],
    "enum":    ["whatweb_scan", "gobuster_scan", "ffuf_scan", "http_headers_check",
                "check_ssl", "ssh_audit", "smb_check", "ftp_check",
                "think", "finish"],
    "vuln":    ["nikto_scan", "nuclei_scan", "http_headers_check",
                "xss_test", "sqli_test", "lfi_test", "ssrf_test",
                "cors_test", "cmd_injection_test", "jwt_analyze",
                "detect_attack_chains", "epss_check", "analyze_finding",
                "search_memory", "think", "finish"],
    "exploit": ["brute_force_ssh", "run_metasploit_module", "sqlmap_scan",
                "generate_poc_script", "detect_attack_chains", "think", "finish"],
    "report":  ["generate_report", "executive_summary", "get_loaded_findings",
                "detect_attack_chains", "think", "finish"],
    "general": ["nmap_scan", "whatweb_scan", "gobuster_scan", "nikto_scan",
                "nuclei_scan", "http_headers_check", "check_ssl",
                "xss_test", "sqli_test", "detect_attack_chains",
                "generate_report", "think", "finish"],
}

def _select_tools(goal: str, step: int, done_actions: set) -> list:
    """Return a relevant subset of tool schemas based on context."""
    g = goal.lower()

    # Full pentest / assessment — return ALL tools so LLM has complete access
    if any(w in g for w in ["pentest", "vapt", "full", "all", "assessment", "audit all"]):
        phase = None  # all tools

    elif any(w in g for w in ["report","summary","executive"]):
        phase = "report"
    elif any(w in g for w in ["exploit","metasploit","brute","crack","sqlmap"]):
        phase = "exploit"
    elif any(w in g for w in ["enum","directory","gobuster","ffuf","whatweb","fingerprint"]):
        phase = "enum"
    elif any(w in g for w in ["xss","sqli","lfi","ssrf","cors","inject","vuln","nikto","nuclei"]):
        phase = "vuln"
    elif any(w in g for w in ["nmap","port","recon","ssh","smb","ssl","ftp","subdomain"]):
        phase = "recon"
    else:
        phase = "general"

    if phase is None:
        # All tools available
        wanted = {s["function"]["name"] for s in _TOOL_SCHEMAS}
    else:
        wanted = set(_PHASE_TOOLS[phase])

    # Always add generate_report after step 4 if not yet done
    if step > 4 and "generate_report" not in done_actions:
        wanted.add("generate_report")
    # Always include finish and think
    wanted.update(["think", "finish"])

    return [s for s in _TOOL_SCHEMAS if s["function"]["name"] in wanted]


# ─────────────────────────────────────────────────────────────
#  Main agent runner
# ─────────────────────────────────────────────────────────────

async def run_agent(
    user_input: str,
    session_id: Optional[str] = None,
    stream_cb: Optional[Callable[[dict], Awaitable[None]]] = None,
) -> dict:
    """
    Run the full ReAct agent loop using Ollama tool-calling format.

    Conversation history is maintained as a messages[] list:
      system → user → assistant (tool_call) → tool (observation) → repeat
    """
    global _TOOL_SCHEMAS
    if not _TOOL_SCHEMAS:
        _TOOL_SCHEMAS = _build_tool_schemas()

    # ── Parse goal ────────────────────────────────────────
    plan = parse_goal(user_input)
    goal = plan["goal"]
    target = plan.get("target", "")

    if not session_id:
        session_id = mem.new_session(goal, target)

    await _emit(stream_cb, {
        "event": "agent_start",
        "session_id": session_id,
        "goal": goal,
        "target": target,
        "planned_tools": [t["tool"] for t in plan["initial_tools"]],
    })

    # ── Build initial messages ────────────────────────────
    history_ctx = mem.build_step_history(session_id)
    findings_ctx = mem.build_findings_context(session_id)
    system_text = _SYSTEM_PROMPT.format(
        goal=goal,
        target=target or "not specified",
        history=history_ctx or "No steps yet.",
        findings=findings_ctx,
    )
    messages: list[dict] = [
        {"role": "system", "content": system_text},
        {"role": "user",   "content": f"Begin the penetration test. Target: {target or user_input}"},
    ]

    step_num = 0
    final_answer = ""
    done_actions: set = set()          # tracks which tools were called
    done_action_args: list = []        # tracks (action, args_hash) to prevent duplicate calls
    _agent_start = asyncio.get_running_loop().time()

    # ── Hardcoded bootstrap steps (LLM-independent) ──────
    _bootstrap = _build_bootstrap_steps(goal, target, raw=user_input)
    _bootstrap_only = len(_bootstrap) > 0  # will auto-finish if bootstrap covers the whole request

    while step_num < MAX_STEPS:
        step_num += 1

        # ── Watchdog: abort if over time limit ────────────
        elapsed = asyncio.get_running_loop().time() - _agent_start
        if elapsed > AGENT_TIMEOUT:
            log.warning("Agent watchdog: exceeded %ds — force finishing", AGENT_TIMEOUT)
            break

        # ── Bootstrap: run deterministic steps first ──────
        if _bootstrap:
            action, action_input, thought = _bootstrap.pop(0)
            log.info("Bootstrap step %d: %s", step_num, action)

            # After last bootstrap step, auto-finish check happens
            # at the bottom of the loop (after observation is recorded)

        else:
            # ── LLM decides next step ─────────────────────
            await _emit(stream_cb, {
                "event": "agent_thinking",
                "session_id": session_id,
                "step": step_num,
            })

            active_schemas = _select_tools(goal, step_num, done_actions)
            result = await _llm_decide_tools(messages, step_num, active_schemas)
            if not result:
                log.error("LLM failed after retries at step %d", step_num)
                break

            tool_call = result.get("tool_call")
            thought   = result.get("content", "")

            if not tool_call:
                final_answer = thought or "Task complete."
                break

            action       = tool_call["name"]
            action_input = tool_call.get("arguments", {})

            # ── Block duplicate tool+args calls ──────────
            _arg_sig = f"{action}:{sorted(action_input.items())}"
            if _arg_sig in done_action_args:
                log.warning("Skipping duplicate call: %s", action)
                # Force finish
                final_answer = f"Completed — {action} already ran with same args."
                break
            done_action_args.append(_arg_sig)

        await _emit(stream_cb, {
            "event": "agent_step",
            "session_id": session_id,
            "step": step_num,
            "thought": thought,
            "action": action,
            "action_input": action_input,
        })

        # ── Terminal action ───────────────────────────────
        done_actions.add(action)

        if action == "finish":
            final_answer = action_input.get("answer", "Task complete.")
            mem.record_step(session_id, thought, action, action_input, final_answer)
            messages.append({"role": "assistant", "content": final_answer})
            break

        # ── Execute tool ──────────────────────────────────
        observation = await _execute(
            session_id=session_id,
            tool_name=action,
            args=action_input,
            stream_cb=stream_cb,
        )
        # Truncate observation for LLM context — keeps prompts small and fast
        obs_str = _preview(observation, max_len=400)

        # Record step in memory
        mem.record_step(session_id, thought, action, action_input, observation)
        _auto_record_findings(session_id, action, observation, target)

        await _emit(stream_cb, {
            "event": "agent_observation",
            "session_id": session_id,
            "step": step_num,
            "action": action,
            "observation_preview": _preview(observation),
        })

        # ── Append to conversation history ────────────────
        # assistant said: call this tool
        messages.append({
            "role": "assistant",
            "content": thought,
            "tool_calls": [{
                "id": f"call_{step_num}",
                "type": "function",
                "function": {"name": action, "arguments": json.dumps(action_input)},
            }],
        })
        # tool returned: observation
        messages.append({
            "role": "tool",
            "tool_call_id": f"call_{step_num}",
            "content": obs_str,
        })

        # Keep conversation window bounded (last 20 messages + system)
        if len(messages) > 42:
            messages = messages[:1] + messages[-40:]

        # ── Auto-finish: bootstrap done + simple request ──
        # If all bootstrap steps ran and no more bootstrap left,
        # and this was a simple single-tool request → build summary offline
        if not _bootstrap and _bootstrap_only:
            g_low = (goal + " " + user_input).lower()
            _simple = any(w in g_low for w in
                          ["nikto","ssl","header","smb","ftp","ssh audit"])
            if _simple:
                final_answer = _offline_summary(session_id, goal, target)
                log.info("Auto-finish after bootstrap (simple request)")
                break

    # ── No explicit finish → auto-summarize ──────────────
    if not final_answer:
        final_answer = await _auto_summarize(session_id, goal)

    mem.complete_session(session_id, final_answer)
    sess = mem.get_session(session_id) or {}

    await _emit(stream_cb, {
        "event": "agent_done",
        "session_id": session_id,
        "final_answer": final_answer,
        "step_count": step_num,
        "finding_count": len(sess.get("findings", [])),
    })

    return {
        "session_id":   session_id,
        "goal":         goal,
        "target":       target,
        "steps":        sess.get("steps", []),
        "findings":     sess.get("findings", []),
        "final_answer": final_answer,
        "status":       "completed",
    }


# ─────────────────────────────────────────────────────────────
#  LLM decision (tool-calling format)
# ─────────────────────────────────────────────────────────────

async def _llm_decide_tools(messages: list, step: int,
                            schemas: list | None = None) -> dict | None:
    """
    Ask the LLM which tool to call next.
    schemas: filtered subset of tools (smaller = faster LLM response).
    """
    use_schemas = schemas if schemas is not None else _TOOL_SCHEMAS
    for attempt in range(MAX_LLM_RETRIES):
        try:
            result = await ai.chat_with_tools_async(messages, use_schemas)
            tc = result.get("tool_call")
            if tc and tc.get("name"):
                return result
            if result.get("content"):
                return result
            log.warning("LLM step %d attempt %d: empty response", step, attempt + 1)
        except Exception as e:
            log.error("LLM tool-call error step %d attempt %d: %s", step, attempt + 1, e)
        await asyncio.sleep(1)
    return None


# ─────────────────────────────────────────────────────────────
#  Tool execution dispatcher
# ─────────────────────────────────────────────────────────────

async def _execute(session_id: str, tool_name: str, args: dict,
                   stream_cb) -> Any:
    """Execute a tool. Checks HITL for dangerous tools."""

    # ── HITL check ────────────────────────────────────────
    if registry.is_dangerous(tool_name):
        approved = await hitl.request_approval(
            session_id=session_id,
            tool_name=tool_name,
            args=args,
            reason=f"'{tool_name}' may cause harm to target systems.",
        )
        await _emit(stream_cb, {
            "event": "agent_hitl_result",
            "session_id": session_id,
            "tool_name": tool_name,
            "approved": approved,
        })
        if not approved:
            return {"skipped": True, "reason": "Human denied this action.", "tool": tool_name}

    # ── Route to handler ──────────────────────────────────
    await _emit(stream_cb, {
        "event": "agent_tool_start",
        "session_id": session_id,
        "tool": tool_name,
        "args": args,
    })

    try:
        result = await _dispatch(tool_name, args, session_id)
    except Exception as e:
        log.error("Tool %s error: %s", tool_name, e)
        result = {"error": str(e), "tool": tool_name}

    await _emit(stream_cb, {
        "event": "agent_tool_done",
        "session_id": session_id,
        "tool": tool_name,
        "ok": not (isinstance(result, dict) and "error" in result),
    })

    return result


async def _dispatch(tool_name: str, args: dict, session_id: str) -> Any:
    """Map tool name → actual function call."""

    # ── Kali tools ────────────────────────────────────────
    if tool_name == "nmap_scan":
        return await kali_tools.nmap_scan(**_pick(args, ["target","ports","flags","timeout"]))

    if tool_name == "check_ssl":
        return await kali_tools.check_ssl(**_pick(args, ["host","port","timeout"]))

    if tool_name == "ssh_audit":
        return await kali_tools.ssh_audit(**_pick(args, ["host","port"]))

    if tool_name == "http_headers_check":
        return await kali_tools.http_headers_check(**_pick(args, ["url","timeout"]))

    if tool_name == "nikto_scan":
        return await kali_tools.nikto_scan(**_pick(args, ["url","timeout"]))

    if tool_name == "smb_check":
        return await kali_tools.smb_check(**_pick(args, ["host"]))

    if tool_name == "ftp_check":
        return await kali_tools.ftp_check(**_pick(args, ["host","port"]))

    if tool_name == "brute_force_ssh":
        return await kali_tools.brute_force_ssh(**_pick(args, ["host","port","wordlist","username"]))

    if tool_name == "run_metasploit_module":
        return await kali_tools.run_metasploit_module(**_pick(args, ["module","target","port","options"]))

    # ── AI / analysis tools ───────────────────────────────
    if tool_name == "analyze_finding":
        if not ai.is_ollama_running():
            return {"error": "Ollama not running"}
        from backend.ai import chromadb_memory as mem_mod
        similar = mem_mod.search_similar(
            f"{args.get('finding_name','')} {args.get('plugin_id','')}", n_results=3)
        ctx = mem_mod.build_memory_context(similar)
        return await ai.analyze_output(
            host=args.get("host", "unknown"),
            finding_name=args.get("finding_name", ""),
            plugin_id=args.get("plugin_id", ""),
            severity=args.get("severity", "info"),
            synopsis=args.get("synopsis", ""),
            plugin_output=args.get("plugin_output", ""),
            command="agent-analyze",
            raw_output=args.get("plugin_output", ""),
            memory_context=ctx,
        )

    if tool_name == "detect_attack_chains":
        from backend.attack_chain_engine import run_chain_detection
        fdings = findings_store.get_all()
        if not fdings:
            return {"error": "No findings loaded. Use /api/findings/sync first."}
        return await run_chain_detection(fdings, narrate=args.get("narrate", True))

    if tool_name == "epss_check":
        from backend.ai import exploit_intel as intel
        return intel.enrich(args.get("cves", []))

    # ── Memory tools ─────────────────────────────────────
    if tool_name == "search_memory":
        results = chroma_mem.search_similar(
            args.get("query", ""), n_results=args.get("n_results", 5))
        return {"results": results, "count": len(results)}

    if tool_name == "get_loaded_findings":
        fdings = findings_store.get_all()
        sev = args.get("severity_filter", "all")
        if sev != "all":
            fdings = [f for f in fdings if f.get("severity") == sev]
        fdings = fdings[:args.get("limit", 50)]
        sev_count: dict = {}
        for f in findings_store.get_all():
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
        return {
            "total": len(findings_store.get_all()),
            "severity_breakdown": sev_count,
            "findings": fdings,
            "filter": sev,
        }

    if tool_name == "search_findings":
        results = findings_store.search(
            args.get("query", ""), limit=args.get("limit", 20))
        return {"results": results, "count": len(results)}

    # ── Report tools ──────────────────────────────────────
    if tool_name == "generate_report":
        fdings = findings_store.get_all()
        sess = mem.get_session(session_id) or {}
        from backend.ai import ollama_client as ai_mod
        summary = ""
        if ai_mod.is_ollama_running() and fdings:
            summary = await ai_mod.generate_executive_summary(
                json.dumps(fdings[:30], ensure_ascii=False))
        chains_result = {}
        try:
            from backend.attack_chain_engine import run_chain_detection
            chains_result = await run_chain_detection(fdings, narrate=False)
        except Exception:
            pass
        report = _build_markdown_report(
            sess, fdings, chains_result, summary,
            scan_name=args.get("scan_name", "VAPT Report"))
        return {"report": report, "format": args.get("format", "markdown"),
                "finding_count": len(fdings)}

    if tool_name == "executive_summary":
        fdings = findings_store.get_all()
        if not ai.is_ollama_running():
            return {"error": "Ollama not running"}
        summary = await ai.generate_executive_summary(json.dumps(fdings[:30], ensure_ascii=False))
        return {"summary": summary}

    # ── Utility ───────────────────────────────────────────
    if tool_name == "generate_poc_script":
        chain_id = args.get("chain_id", args.get("vulnerability", args.get("finding", "unknown")))
        hosts = args.get("affected_hosts", [args.get("host", args.get("target", "TARGET_IP"))])
        host = hosts[0] if hosts else "TARGET_IP"
        # Chain-specific PoC templates
        poc_map = {
            "smb_relay_ntlm": (
                "#!/bin/bash\n# SMB Relay / NTLM Capture PoC\n"
                f"TARGET='{host}'\n"
                "# Step 1: Start Responder (capture hashes)\n"
                "sudo responder -I eth0 -rdwv &\n"
                "# Step 2: Relay to target\n"
                f"sudo ntlmrelayx.py -t smb://$TARGET -smb2support\n"
            ),
            "kerberoasting_path": (
                "#!/bin/bash\n# Kerberoasting PoC\n"
                f"TARGET='{host}'\n"
                "# Get SPNs and request tickets\n"
                "python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py "
                "-request DOMAIN/user:pass -dc-ip $TARGET -outputfile hashes.txt\n"
                "# Crack with hashcat\n"
                "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt\n"
            ),
        }
        poc = poc_map.get(chain_id,
            f"#!/bin/bash\n# PoC for: {chain_id}\n# Target: {host}\n"
            f"echo '[*] Testing {host} for {chain_id}'\n"
            f"nmap -Pn -sV --script vuln {host}\n"
        )
        return {"script": poc, "language": "bash", "chain_id": chain_id,
                "affected_hosts": hosts}

    if tool_name == "think":
        return {"thought_recorded": args.get("thought", ""), "status": "ok"}

    if tool_name == "ask_human":
        return {
            "question": args.get("question", ""),
            "options": args.get("options", []),
            "note": "Question sent to human operator via WebSocket.",
        }

    # ── Web app attack tools ──────────────────────────────
    if tool_name == "whatweb_scan":
        return await kali_tools.whatweb_scan(**_pick(args, ["url", "timeout"]))

    if tool_name == "gobuster_scan":
        # gobuster_scan(url, mode, wordlist, timeout, proxy) — no extensions/threads params
        return await kali_tools.gobuster_scan(**_pick(args, ["url", "mode", "wordlist", "timeout", "proxy"]))

    if tool_name == "ffuf_scan":
        # ffuf_scan(url, wordlist, extensions, timeout, proxy) — no 'method' param
        return await kali_tools.ffuf_scan(**_pick(args, ["url", "wordlist", "extensions", "timeout", "proxy"]))

    if tool_name == "nuclei_scan":
        return await kali_tools.nuclei_scan(**_pick(args, ["target", "templates", "timeout"]))

    if tool_name == "subfinder_scan":
        return await kali_tools.subfinder_scan(**_pick(args, ["domain", "timeout"]))

    if tool_name == "sqlmap_scan":
        return await kali_tools.sqlmap_scan(**_pick(args, ["url", "data", "level", "timeout"]))

    if tool_name == "xss_test":
        return await kali_tools.xss_test(**_pick(args, ["url", "param", "proxy"]))

    if tool_name == "sqli_test":
        return await kali_tools.sqli_test(**_pick(args, ["url", "param", "proxy"]))

    if tool_name == "lfi_test":
        return await kali_tools.lfi_test(**_pick(args, ["url", "param", "proxy"]))

    if tool_name == "ssrf_test":
        return await kali_tools.ssrf_test(**_pick(args, ["url", "param", "proxy"]))

    if tool_name == "cors_test":
        return await kali_tools.cors_misconfiguration_test(**_pick(args, ["url", "proxy"]))

    if tool_name == "cmd_injection_test":
        return await kali_tools.command_injection_test(**_pick(args, ["url", "param", "proxy"]))

    if tool_name == "jwt_analyze":
        return await kali_tools.jwt_analyze(**_pick(args, ["token"]))

    return {"error": f"Unknown tool: {tool_name}"}


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _build_bootstrap_steps(goal: str, target: str, raw: str = "") -> list:
    """
    Return hardcoded tool steps based on what the user asked for.
    Checks BOTH parsed goal and raw user input so specific tool keywords aren't lost.
    Each entry: (action_name, action_input_dict, thought_str)
    """
    # Check both the parsed goal and the original user message
    g = (goal + " " + raw).lower()
    t = target or "unknown"
    url = f"http://{t}"

    # ── User explicitly asked for a specific tool ──────────────────────
    if "nikto" in g:
        return [
            ("nmap_scan",
             {"target": t, "flags": "-Pn --open -T4 --top-ports 20", "timeout": 60},
             f"Quick port check on {t} before Nikto."),
            ("nikto_scan",
             {"url": url, "timeout": 180},
             f"Running Nikto web vulnerability scan on {t} as requested."),
        ]

    if "ssh" in g and any(w in g for w in ["audit","check","scan"]):
        return [
            ("nmap_scan",
             {"target": t, "flags": "-Pn -p 22 -sV", "timeout": 30},
             f"Checking SSH port on {t}."),
            ("ssh_audit",
             {"host": t, "port": 22},
             f"SSH audit on {t} as requested."),
        ]

    if any(w in g for w in ["ssl", "tls", "cert", "certificate", "https"]):
        return [
            ("check_ssl",
             {"host": t, "port": 443},
             f"Checking SSL/TLS on {t} as requested."),
        ]

    if any(w in g for w in ["header", "http header"]):
        return [
            ("http_headers_check",
             {"url": url},
             f"Checking HTTP headers on {t} as requested."),
        ]

    if "smb" in g:
        return [
            ("nmap_scan",
             {"target": t, "flags": "-Pn -p 445,139 -sV", "timeout": 30},
             f"Checking SMB ports on {t}."),
            ("smb_check",
             {"host": t},
             f"SMB check on {t} as requested."),
        ]

    if "ftp" in g:
        return [
            ("ftp_check",
             {"host": t, "port": 21},
             f"FTP check on {t} as requested."),
        ]

    # ── Generic / full pentest — comprehensive bootstrap ──────────────
    steps = [
        ("nmap_scan",
         {"target": t, "flags": "-sV -sC --open -T4", "timeout": 120},
         f"Starting recon — full port scan with service detection on {t}."),
        ("http_headers_check",
         {"url": url},
         f"Checking HTTP security headers on {t}."),
        ("whatweb_scan",
         {"url": url, "timeout": 30},
         f"Fingerprinting web technologies on {t}."),
    ]
    if any(w in g for w in ["full", "all", "pentest", "vapt", "web", "vuln",
                             "scan", "audit", "assess"]):
        steps += [
            ("gobuster_scan",
             {"url": url, "timeout": 120},
             f"Discovering hidden directories and files on {t}."),
            ("nikto_scan",
             {"url": url, "timeout": 180},
             f"Running Nikto web vulnerability scan on {t}."),
            ("nuclei_scan",
             {"target": url, "templates": "cves,misconfiguration", "timeout": 180},
             f"Running Nuclei CVE and misconfiguration scan on {t}."),
        ]
    return steps


def _pick(d: dict, keys: list) -> dict:
    """Pick only defined keys from dict, skip None values."""
    return {k: d[k] for k in keys if k in d and d[k] is not None}


def _preview(obs: Any, max_len: int = 300) -> str:
    if isinstance(obs, dict):
        return json.dumps(obs, ensure_ascii=False)[:max_len]
    return str(obs)[:max_len]


async def _emit(cb, data: dict):
    if cb:
        try:
            await cb(data)
        except Exception as e:
            log.debug("stream_cb error: %s", e)


def _auto_record_findings(session_id: str, action: str, obs: Any, target: str):
    """If a tool returned port/vulnerability data, auto-record as findings."""
    if not isinstance(obs, dict):
        return
    # nmap findings
    if action == "nmap_scan" and "open_ports" in obs:
        for p in obs.get("open_ports", []):
            if p.get("state") == "open":
                mem.record_finding(session_id, {
                    "name": f"Open Port: {p['port']}/{p['proto']} ({p.get('service','')})",
                    "host": obs.get("target", target),
                    "port": str(p["port"]),
                    "severity": "info",
                    "source": "nmap",
                    "version": p.get("version", ""),
                })
    # SSL issues
    if action == "check_ssl" and obs.get("issues"):
        for issue in obs["issues"][:5]:
            mem.record_finding(session_id, {
                "name": f"SSL Issue: {issue[:80]}",
                "host": obs.get("target", target),
                "port": "443",
                "severity": "medium",
                "source": "ssl_check",
            })
    # Attack chains
    if action == "detect_attack_chains" and isinstance(obs, dict):
        for chain in obs.get("chains", []):
            mem.record_finding(session_id, {
                "name": f"Attack Chain: {chain.get('name','')}",
                "host": target,
                "port": "",
                "severity": chain.get("upgraded_risk", "HIGH").lower(),
                "source": "chain_detection",
                "chain_id": chain.get("chain_id"),
            })
    # Nuclei findings
    if action == "nuclei_scan" and isinstance(obs, dict):
        for finding in obs.get("findings", [])[:10]:
            sev = finding.get("severity", "medium").lower()
            mem.record_finding(session_id, {
                "name": f"Nuclei: {finding.get('name', finding.get('template_id', 'unknown'))}",
                "host": obs.get("target", target),
                "port": str(finding.get("port", "")),
                "severity": sev if sev in ("critical","high","medium","low","info") else "medium",
                "source": "nuclei",
                "cve": finding.get("cve", ""),
            })
    # XSS/SQLi/LFI/SSRF/CORS/CMDi findings
    if action in ("xss_test","sqli_test","lfi_test","ssrf_test","cors_test","cmd_injection_test"):
        if isinstance(obs, dict) and obs.get("vulnerable"):
            sev = obs.get("severity", "high")
            mem.record_finding(session_id, {
                "name": f"{action.replace('_test','').replace('_',' ').upper()} Vulnerability: {obs.get('url', target)}",
                "host": target,
                "port": "",
                "severity": sev if sev in ("critical","high","medium","low","info") else "high",
                "source": action,
                "detail": obs.get("finding", ""),
            })
    # SSH audit findings
    if action == "ssh_audit" and isinstance(obs, dict) and obs.get("issues"):
        for issue in obs["issues"][:5]:
            mem.record_finding(session_id, {
                "name": f"SSH Issue: {issue[:80]}",
                "host": obs.get("target", target).split(":")[0],
                "port": str(obs.get("target", ":22").split(":")[-1]) if ":" in str(obs.get("target","")) else "22",
                "severity": "medium",
                "source": "ssh_audit",
            })
    # Nikto findings
    if action == "nikto_scan" and isinstance(obs, dict) and obs.get("findings"):
        for finding in obs["findings"][:10]:
            mem.record_finding(session_id, {
                "name": f"Nikto: {finding[:100]}",
                "host": target,
                "port": "80",
                "severity": "medium",
                "source": "nikto",
            })
    # Gobuster / ffuf discovered paths
    if action in ("gobuster_scan", "ffuf_scan") and isinstance(obs, dict):
        paths = obs.get("found", obs.get("results", []))
        interesting = [p for p in paths
                       if str(p.get("status", 0)) in ("200", "301", "302", "403", "401")][:5]
        if interesting:
            names = ", ".join(p.get("path", p.get("url", "?")) for p in interesting[:3])
            mem.record_finding(session_id, {
                "name": f"Hidden paths found: {names}",
                "host": target,
                "port": "80",
                "severity": "low",
                "source": action,
                "count": len(paths),
            })
    # WhatWeb version exposure
    if action == "whatweb_scan" and isinstance(obs, dict) and obs.get("versions"):
        versions_str = ", ".join(f"{k} {v}" for k, v in list(obs["versions"].items())[:5])
        if versions_str:
            mem.record_finding(session_id, {
                "name": f"Technology versions exposed: {versions_str}",
                "host": target,
                "port": "80",
                "severity": "info",
                "source": "whatweb",
            })


# ─────────────────────────────────────────────────────────────
#  Report builder
# ─────────────────────────────────────────────────────────────

def _build_markdown_report(sess: dict, findings: list, chains: dict,
                            summary: str, scan_name: str = "VAPT Report") -> str:
    """Build a markdown pentest report from session + findings + chains."""
    from datetime import datetime as _dt

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda x: sev_order.get(x.get("severity","info"), 5))

    # Count by severity
    counts = {}
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    lines = [
        f"# {scan_name}",
        f"**Generated:** {_dt.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Target:** {sess.get('target', 'N/A')}",
        f"**Goal:** {sess.get('goal', 'N/A')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        summary or "_No AI summary available — Ollama not running._",
        "",
        "### Severity Breakdown",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev, 0):
            lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

    lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(sorted_f[:50], 1):
        lines.append(f"### {i}. {f.get('name', 'Unknown Finding')}")
        lines.append(f"- **Severity:** {f.get('severity', 'info').upper()}")
        lines.append(f"- **Host:** {f.get('host', 'N/A')}  **Port:** {f.get('port', 'N/A')}")
        if f.get("source"):
            lines.append(f"- **Source:** {f['source']}")
        if f.get("detail"):
            lines.append(f"- **Detail:** {str(f['detail'])[:300]}")
        lines.append("")

    # Attack chains
    chain_list = chains.get("chains", []) if isinstance(chains, dict) else []
    if chain_list:
        lines += ["---", "", "## Attack Chains", ""]
        for c in chain_list[:10]:
            lines.append(f"### {c.get('name', 'Unknown Chain')}")
            lines.append(f"- **Risk:** {c.get('upgraded_risk', 'HIGH')}")
            lines.append(f"- **Steps:** {' → '.join(c.get('steps', []))}")
            if c.get("description"):
                lines.append(f"- **Description:** {c['description']}")
            lines.append("")

    lines += ["---", "", "## Recommendations", "",
              "1. Patch all Critical and High severity findings immediately.",
              "2. Review Medium severity findings within 30 days.",
              "3. Re-test after remediation to verify fixes.",
              "4. Implement network segmentation to limit lateral movement.",
              "5. Enable logging and alerting on all critical assets.",
              ""]

    return "\n".join(lines)
