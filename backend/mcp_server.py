"""
MCP (Model Context Protocol) Server — exposes Nessus Analyzer tools
to Claude Desktop, Cursor, Cline, and any MCP-compatible client.

Endpoint: POST /mcp
Protocol: JSON-RPC 2.0

Available tools:
  - analyze_nessus_finding
  - suggest_commands
  - search_similar_findings
  - calculate_cvss
  - get_memory_stats
  - clear_memory
"""
import json, logging
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.ai import ollama_client as ai
from backend.ai import chromadb_memory as mem
from backend import findings_store
from backend.config import MCP_SERVER_NAME, MCP_SERVER_VERSION

log = logging.getLogger("aavapt.mcp")
router = APIRouter(prefix="/mcp", tags=["MCP"])

# ── Tool definitions (returned on tools/list) ──────────────────
TOOLS = [
    {
        "name": "analyze_nessus_finding",
        "description": (
            "Analyze raw command output against a Nessus finding using DeepSeek AI. "
            "Returns verdict (confirmed/fp/needs-more), confidence, indicators, "
            "next commands, and exploit links."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["host", "finding_name", "plugin_id", "command", "raw_output"],
            "properties": {
                "host":         {"type": "string", "description": "Target IP/hostname"},
                "finding_name": {"type": "string", "description": "Nessus finding name"},
                "plugin_id":    {"type": "string", "description": "Nessus plugin ID"},
                "severity":     {"type": "string", "description": "critical/high/medium/low/info"},
                "synopsis":     {"type": "string", "description": "Nessus synopsis text"},
                "plugin_output":{"type": "string", "description": "Nessus plugin output"},
                "command":      {"type": "string", "description": "Command that was run"},
                "raw_output":   {"type": "string", "description": "Terminal output to analyze"}
            }
        }
    },
    {
        "name": "suggest_commands",
        "description": "Get AI-powered command suggestions for verifying a Nessus finding on Kali Linux.",
        "inputSchema": {
            "type": "object",
            "required": ["finding_name", "plugin_id", "host"],
            "properties": {
                "finding_name": {"type": "string"},
                "plugin_id":    {"type": "string"},
                "port":         {"type": "string"},
                "service":      {"type": "string"},
                "host":         {"type": "string"},
                "context":      {"type": "string", "description": "Additional context"}
            }
        }
    },
    {
        "name": "search_similar_findings",
        "description": "Search ChromaDB memory for similar past vulnerability findings and their verdicts.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query":     {"type": "string", "description": "Finding name, CVE, or description"},
                "n_results": {"type": "integer", "description": "Max results (default 3)"}
            }
        }
    },
    {
        "name": "calculate_cvss",
        "description": "Calculate CVSS v3.1 base score from metric vector string or individual metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vector": {"type": "string",
                           "description": "CVSS vector e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                "AV": {"type": "string", "enum": ["N","A","L","P"]},
                "AC": {"type": "string", "enum": ["L","H"]},
                "PR": {"type": "string", "enum": ["N","L","H"]},
                "UI": {"type": "string", "enum": ["N","R"]},
                "S":  {"type": "string", "enum": ["U","C"]},
                "C":  {"type": "string", "enum": ["N","L","H"]},
                "I":  {"type": "string", "enum": ["N","L","H"]},
                "A":  {"type": "string", "enum": ["N","L","H"]}
            }
        }
    },
    {
        "name": "get_memory_stats",
        "description": "Get ChromaDB memory statistics — total stored findings, verdict breakdown.",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "clear_memory",
        "description": "Clear all stored findings from ChromaDB memory. Use with caution.",
        "inputSchema": {"type": "object", "properties": {}}
    }
,
    {
        "name": "search_findings",
        "description": "Search the currently loaded scan by keyword, IP, port, CVE or plugin ID.",
        "inputSchema": {"type": "object", "required": ["query"],
            "properties": {"query": {"type": "string"},
                           "limit": {"type": "integer", "description": "Max results (default 50)"}}}
    },
    {
        "name": "get_host_summary",
        "description": "Return all findings, ports, services and severity breakdown for one IP.",
        "inputSchema": {"type": "object", "required": ["ip"],
            "properties": {"ip": {"type": "string", "description": "Target IP address"}}}
    },
    {
        "name": "get_commands_for_finding",
        "description": "Return ready-to-run nmap-first verification commands (real IP/port/service) for a finding.",
        "inputSchema": {"type": "object", "required": ["finding_name", "host"],
            "properties": {"finding_name": {"type": "string"}, "plugin_id": {"type": "string"},
                           "host": {"type": "string"}, "port": {"type": "string"},
                           "service": {"type": "string"}}}
    },
    {
        "name": "check_memory",
        "description": "Return similar past VERIFIED findings from ChromaDB for a finding name + plugin id.",
        "inputSchema": {"type": "object", "required": ["finding_name"],
            "properties": {"finding_name": {"type": "string"}, "plugin_id": {"type": "string"},
                           "n_results": {"type": "integer"}}}
    },
    {
        "name": "store_result",
        "description": "Save a verification result (command + output + verdict) into ChromaDB memory.",
        "inputSchema": {"type": "object",
            "required": ["finding_name", "host", "command", "output", "verdict"],
            "properties": {"finding_name": {"type": "string"}, "plugin_id": {"type": "string"},
                           "host": {"type": "string"}, "command": {"type": "string"},
                           "output": {"type": "string"},
                           "verdict": {"type": "string", "description": "confirmed/fp/needs-more"}}}
    },
]


# ── CVSS calculation helper ────────────────────────────────────
def _calc_cvss(params: dict) -> dict:
    """Pure Python CVSS v3.1 base score calculation."""
    v = {}
    vector_str = params.get("vector", "")
    if vector_str:
        for part in vector_str.replace("CVSS:3.1/","").split("/"):
            if ":" in part:
                k, val = part.split(":", 1)
                v[k] = val
    else:
        for k in ["AV","AC","PR","UI","S","C","I","A"]:
            if k in params:
                v[k] = params[k]

    if len(v) < 8:
        return {"error": "Need all 8 metrics or a valid vector string"}

    sc = v.get("S") == "C"
    AV = {"N":.85,"A":.62,"L":.55,"P":.2}.get(v.get("AV"),0)
    AC = {"L":.77,"H":.44}.get(v.get("AC"),0)
    PR = ({"N":.85,"L":.68,"H":.50} if sc else {"N":.85,"L":.62,"H":.27}).get(v.get("PR"),0)
    UI = {"N":.85,"R":.62}.get(v.get("UI"),0)
    C  = {"N":0,"L":.22,"H":.56}.get(v.get("C"),0)
    I  = {"N":0,"L":.22,"H":.56}.get(v.get("I"),0)
    A  = {"N":0,"L":.22,"H":.56}.get(v.get("A"),0)

    ISS = 1 - (1-C)*(1-I)*(1-A)
    imp = 7.52*(ISS-.029)-3.25*((ISS-.02)**15) if sc else 6.42*ISS
    exp = 8.22*AV*AC*PR*UI
    score = 0.0
    if imp > 0:
        raw = 1.08*(imp+exp) if sc else imp+exp
        score = round(min(10.0, round(raw * 10) / 10), 1)

    label = ("CRITICAL" if score>=9 else "HIGH" if score>=7
             else "MEDIUM" if score>=4 else "LOW" if score>0 else "NONE")
    vec = f"CVSS:3.1/AV:{v.get('AV','?')}/AC:{v.get('AC','?')}/PR:{v.get('PR','?')}/UI:{v.get('UI','?')}/S:{v.get('S','?')}/C:{v.get('C','?')}/I:{v.get('I','?')}/A:{v.get('A','?')}"
    return {"score": score, "severity": label, "vector": vec}


# ── JSON-RPC helpers ───────────────────────────────────────────
def _ok(req_id, result):
    return {"jsonrpc":"2.0","id":req_id,"result":result}

def _err(req_id, code, message):
    return {"jsonrpc":"2.0","id":req_id,"error":{"code":code,"message":message}}


# ── Main MCP handler ───────────────────────────────────────────
@router.post("")
async def mcp_handler(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_err(None, -32700, "Parse error"))

    req_id  = body.get("id")
    method  = body.get("method","")
    params  = body.get("params", {})

    log.info(f"MCP method={method} id={req_id}")

    # ── initialize ──
    if method == "initialize":
        return JSONResponse(_ok(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": MCP_SERVER_NAME, "version": MCP_SERVER_VERSION}
        }))

    # ── tools/list ──
    if method == "tools/list":
        return JSONResponse(_ok(req_id, {"tools": TOOLS}))

    # ── tools/call ──
    if method == "tools/call":
        tool_name = params.get("name","")
        args      = params.get("arguments", {})
        log.info("[MCP] tool call: %s | args=%s", tool_name, json.dumps(args)[:300])

        # analyze_nessus_finding
        if tool_name == "analyze_nessus_finding":
            host    = args.get("host","unknown")
            similar = mem.search_similar(
                f"{args.get('finding_name','')} {args.get('plugin_id','')}", n_results=3
            )
            mem_ctx = mem.build_memory_context(similar)
            try:
                result  = await ai.analyze_output(
                    host=host,
                    finding_name=args.get("finding_name",""),
                    plugin_id=args.get("plugin_id",""),
                    severity=args.get("severity","info"),
                    synopsis=args.get("synopsis",""),
                    plugin_output=args.get("plugin_output",""),
                    command=args.get("command",""),
                    raw_output=args.get("raw_output",""),
                    memory_context=mem_ctx
                )
            except Exception as e:
                log.exception("analyze_nessus_finding failed")
                return JSONResponse(_err(req_id, -32603, f"AI analyze failed (Ollama offline?): {e}"))
            # Auto-store in ChromaDB
            if result.get("confidence",0) > 70:  # TASK 5 threshold
                mem.store_finding(
                    host=host,
                    finding_name=args.get("finding_name",""),
                    plugin_id=args.get("plugin_id",""),
                    severity=args.get("severity","info"),
                    command=args.get("command",""),
                    raw_output=args.get("raw_output",""),
                    verdict=result.get("verdict","needs-more"),
                    confidence=result.get("confidence",0),
                    summary=result.get("summary",""),
                    indicators=result.get("indicators",[])
                )
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps(result, indent=2)}]
            }))

        # suggest_commands
        if tool_name == "suggest_commands":
            try:
                cmds = await ai.suggest_commands(
                    finding_name=args.get("finding_name",""),
                    plugin_id=args.get("plugin_id",""),
                    port=args.get("port",""),
                    service=args.get("service",""),
                    host=args.get("host","TARGET"),
                    context=args.get("context","")
                )
            except Exception as e:
                log.exception("suggest_commands failed")
                return JSONResponse(_err(req_id, -32603, f"suggest_commands failed: {e}"))
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps(cmds, indent=2)}]
            }))

        # search_similar_findings
        if tool_name == "search_similar_findings":
            similar = mem.search_similar(
                args.get("query",""), n_results=int(args.get("n_results") or 3)
            )
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps(similar, indent=2)}]
            }))

        # calculate_cvss
        if tool_name == "calculate_cvss":
            result = _calc_cvss(args)
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps(result, indent=2)}]
            }))

        # get_memory_stats
        if tool_name == "get_memory_stats":
            stats = mem.get_stats()
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps(stats, indent=2)}]
            }))

        # clear_memory
        if tool_name == "clear_memory":
            ok = mem.clear_memory()
            return JSONResponse(_ok(req_id, {
                "content": [{"type":"text","text":json.dumps({"success": ok})}]
            }))

        # search_findings
        if tool_name == "search_findings":
            res = findings_store.search(args.get("query",""), args.get("limit",50))
            return JSONResponse(_ok(req_id, {"content": [{"type":"text",
                "text": json.dumps({"count": len(res), "results": res}, indent=2)}]}))

        # get_host_summary
        if tool_name == "get_host_summary":
            res = findings_store.host_summary(args.get("ip",""))
            return JSONResponse(_ok(req_id, {"content": [{"type":"text",
                "text": json.dumps(res, indent=2)}]}))

        # get_commands_for_finding
        if tool_name == "get_commands_for_finding":
            try:
                cmds = await ai.suggest_commands(
                    finding_name=args.get("finding_name",""),
                    plugin_id=args.get("plugin_id",""),
                    port=args.get("port",""),
                    service=args.get("service",""),
                    host=args.get("host","TARGET_IP"),
                    context=args.get("context",""))
            except Exception as e:
                log.exception("get_commands_for_finding failed")
                return JSONResponse(_err(req_id, -32603, f"get_commands_for_finding failed: {e}"))
            return JSONResponse(_ok(req_id, {"content": [{"type":"text",
                "text": json.dumps(cmds, indent=2)}]}))

        # check_memory
        if tool_name == "check_memory":
            q = (args.get("finding_name","") + " " + args.get("plugin_id","")).strip()
            similar = mem.search_similar(q, n_results=int(args.get("n_results") or 3))
            return JSONResponse(_ok(req_id, {"content": [{"type":"text",
                "text": json.dumps({"count": len(similar), "similar": similar}, indent=2)}]}))

        # store_result
        if tool_name == "store_result":
            verdict = args.get("verdict","needs-more")
            conf = 90 if verdict == "confirmed" else (20 if verdict == "fp" else 50)
            doc_id = mem.store_finding(
                host=args.get("host","unknown"),
                finding_name=args.get("finding_name",""),
                plugin_id=args.get("plugin_id",""),
                severity=args.get("severity","info"),
                command=args.get("command",""),
                raw_output=args.get("output",""),
                verdict=verdict, confidence=conf,
                summary=args.get("output","")[:200],
                indicators=[])
            return JSONResponse(_ok(req_id, {"content": [{"type":"text",
                "text": json.dumps({"stored": bool(doc_id), "id": doc_id, "verdict": verdict})}]}))

        return JSONResponse(_err(req_id, -32601, f"Unknown tool: {tool_name}"))

    # ── notifications (no response needed) ──
    if method.startswith("notifications/"):
        return JSONResponse({})

    return JSONResponse(_err(req_id, -32601, f"Method not found: {method}"))


# ── SSE endpoint for MCP (some clients need it) ───────────────
@router.get("/sse")
async def mcp_sse():
    from fastapi.responses import StreamingResponse
    async def event_stream():
        info = json.dumps({
            "server": MCP_SERVER_NAME,
            "version": MCP_SERVER_VERSION,
            "tools": len(TOOLS),
            "endpoint": "POST /mcp"
        })
        yield f"data: {info}\n\n"
    return StreamingResponse(event_stream(), media_type="text/event-stream")
