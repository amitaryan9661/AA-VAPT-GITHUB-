# -*- coding: utf-8 -*-
"""
AA-VAPT Nessus Analyzer — FastAPI Backend v2
Includes: AI analysis, ChromaDB memory, MCP server,
          SOAR orchestrator, WebSocket real-time, multi-model support,
          API authentication, rate limiting
"""
import logging, json, os, uuid
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, Any

# ENH-01: Authentication
from backend.auth import require_auth, auth_status

# ENH-02: Rate Limiting via slowapi
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    _limiter = Limiter(key_func=get_remote_address)
    _RATE_LIMIT_OK = True
except ImportError:
    _limiter = None
    _RATE_LIMIT_OK = False
    logging.getLogger("aavapt.main").warning(
        "slowapi not installed — rate limiting disabled. Run: pip install slowapi --break-system-packages"
    )

HISTORY_DIR = os.path.join(os.path.dirname(__file__), '..', 'history')
os.makedirs(HISTORY_DIR, exist_ok=True)

from backend.config import API_HOST, API_PORT, FRONTEND_PORT
from backend.ai import ollama_client as ai
from backend.ai import chromadb_memory as mem
from backend import mcp_server
from backend.soar.orchestrator import orchestrator
from backend import script_generator
from backend import findings_store
from backend.ws_manager import ws_manager

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("aavapt.main")


# ── Lifespan ───────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio as _asyncio
    log.info("Starting AA-VAPT Nessus Analyzer Backend v2...")
    # FIX B8: Use get_running_loop() instead of deprecated get_event_loop()
    loop = _asyncio.get_running_loop()
    loop.run_in_executor(None, mem.get_collection)
    if ai.is_ollama_running():
        log.info(f"Ollama ready | Model: {ai.get_available_model()}")
    else:
        log.warning("Ollama offline — AI features disabled")
    orchestrator.set_broadcast(ws_manager.broadcast)
    await orchestrator.start()
    log.info("SOAR Orchestrator started")
    yield
    await orchestrator.stop()
    log.info("Backend shutdown complete")


app = FastAPI(title="AA-VAPT Nessus Analyzer API", version="2.1.0", lifespan=lifespan)

# ENH-02: Register rate limiter if available
if _RATE_LIMIT_OK and _limiter:
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow same server (8000) + legacy frontend port (8181)
app.add_middleware(CORSMiddleware,
    allow_origins=[
        "http://localhost:8000", "http://127.0.0.1:8000",
        f"http://localhost:{FRONTEND_PORT}", f"http://127.0.0.1:{FRONTEND_PORT}",
        "http://localhost:8181", "http://127.0.0.1:8181",
    ],
    allow_methods=["*"], allow_headers=["*"]
)
app.include_router(mcp_server.router)

# ── Static file serving ─────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(__file__))   # project root

@app.get("/", include_in_schema=False)
async def serve_index():
    return FileResponse(os.path.join(_ROOT, "nessus-analyzer.html"))

@app.get("/nessus-analyzer.html", include_in_schema=False)
async def serve_nessus():
    return FileResponse(os.path.join(_ROOT, "nessus-analyzer.html"))

@app.get("/nmap-output-analyzer.html", include_in_schema=False)
async def serve_nmap_output():
    return FileResponse(os.path.join(_ROOT, "nmap-output-analyzer.html"))

@app.get("/nmap-pt.html", include_in_schema=False)
async def serve_nmap():
    return FileResponse(os.path.join(_ROOT, "nmap-pt.html"))

@app.get("/webapp-pt.html", include_in_schema=False)
async def serve_webapp():
    return FileResponse(os.path.join(_ROOT, "webapp-pt.html"))

@app.get("/agent.html", include_in_schema=False)
async def serve_agent():
    return FileResponse(os.path.join(_ROOT, "frontend", "agent.html"))

# ── Agent System (AI autonomous agent with ReAct loop) ──────────
try:
    from backend.agent.router import router as _agent_router
    from backend.agent.router import agent_ws as _agent_ws_handler
    app.include_router(_agent_router)
    # Register agent WebSocket separately (prefix override)
    @app.websocket("/ws/agent/{session_id}")
    async def websocket_agent(ws: WebSocket, session_id: str):
        await _agent_ws_handler(ws, session_id)
    log.info("AI Agent system loaded — /api/agent/* + /ws/agent/{session_id}")
except Exception as _agent_err:
    log.warning("Agent system unavailable: %s", _agent_err)

# ── Multi-Agent VAPT Pipeline ────────────────────────────────────
try:
    from backend.vapt_pipeline import router as _pipeline_router
    app.include_router(_pipeline_router)
    log.info("VAPT Pipeline loaded — /api/vapt/pipeline/*")
except Exception as _pipe_err:
    log.warning("VAPT Pipeline unavailable: %s", _pipe_err)

# ── Report serving ───────────────────────────────────────────────
@app.get("/reports/{session_id}.html", include_in_schema=False)
async def serve_report(session_id: str):
    import os as _os
    report_path = _os.path.join(_ROOT, "reports", f"report_{session_id}.html")
    if _os.path.exists(report_path):
        return FileResponse(report_path, media_type="text/html")
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<h2>Report not found</h2>", status_code=404)


# ── Models ─────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    host: str; finding_name: str; plugin_id: str
    severity: str = "info"; synopsis: str = ""
    plugin_output: str = ""; command: str; raw_output: str
    store_memory: bool = True

class ChatRequest(BaseModel):
    question: str; finding_name: str; plugin_id: str
    severity: str = "info"; synopsis: str = ""; plugin_output: str = ""

class CommandRequest(BaseModel):
    finding_name: str; plugin_id: str; port: str = ""
    service: str = ""; host: str = "TARGET"; context: str = ""

class SummaryRequest(BaseModel):
    findings: list[dict]

class SearchRequest(BaseModel):
    query: str; n_results: int = 5

class FeedbackRequest(BaseModel):
    memory_id: str; correct: bool; notes: str = ""

class ModelSelectRequest(BaseModel):
    model_id: str

class TriageRequest(BaseModel):
    host: str; findings: list[dict]


# ── WebSocket ──────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    log.info(f"WS connected. Total clients: {ws_manager.count}")
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
        log.info(f"WS disconnected. Total clients: {ws_manager.count}")


# ── Interactive PTY terminal (real WSL bash in the browser) — localhost only ──
# Import is fail-safe: a problem here must never take down the whole backend.
try:
    from backend import terminal_pty as _terminal_pty
except Exception as _term_imp_err:  # pragma: no cover
    _terminal_pty = None
    log.warning(f"terminal module unavailable: {_term_imp_err}")


@app.websocket("/ws/terminal")
async def websocket_terminal(ws: WebSocket):
    if _terminal_pty is None:
        try:
            await ws.accept()
            await ws.send_text("\r\n[!] Terminal module failed to load on the backend.\r\n")
            await ws.close()
        except Exception:
            pass
        return
    await _terminal_pty.terminal_session(ws)


# ── Status ──────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    ollama_ok = ai.is_ollama_running()
    model_info = ai.get_model_info() if ollama_ok else {"active": None, "available": []}
    chroma_ok  = mem.is_ready()
    mem_stats  = mem.get_stats()
    soar_sum   = orchestrator.get_summary()
    return {
        "status": "ok", "version": "2.1.0",
        "ollama":  {"running": ollama_ok, **model_info},
        "chromadb":{"ready": chroma_ok, **mem_stats},
        "mcp":     {"endpoint": "/mcp", "tools": len(mcp_server.TOOLS)},
        "soar":    soar_sum,
        "ws":      {"clients": ws_manager.count, "endpoint": "/ws"},
        "auth":    auth_status(),
        "rate_limiting": {"enabled": _RATE_LIMIT_OK},
    }

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/kali/status")
async def kali_status():
    """Check what execution environment is available for Kali tools."""
    import sys, shutil, subprocess
    is_win = sys.platform.startswith("win")

    # Defined in outer scope so message-builder can reference it
    kali_tools_list = ["nmap","nikto","ffuf","nuclei","subfinder","whatweb",
                       "ssh-audit","hydra","msfconsole","sqlmap"]

    # Run all blocking subprocess.run calls in executor so the event loop isn't blocked
    loop = asyncio.get_running_loop()

    def _check_sync():
        _wsl_ok = False
        _wsl_distro = ""
        _tools_found = []
        _tools_missing = []
        if is_win:
            wsl_bin = shutil.which("wsl")
            if wsl_bin:
                try:
                    r = subprocess.run(["wsl", "--list", "--quiet"],
                                       capture_output=True, timeout=5)
                    _wsl_distro = r.stdout.decode("utf-16-le","replace").strip().split("\n")[0].strip()
                    _wsl_ok = True
                except Exception:
                    pass
            for tool in kali_tools_list:
                try:
                    r = subprocess.run(["wsl","-e","which",tool],
                                       capture_output=True, timeout=4)
                    (_tools_found if r.returncode==0 else _tools_missing).append(tool)
                except Exception:
                    _tools_missing.append(tool)
        else:
            for tool in kali_tools_list:
                (_tools_found if shutil.which(tool) else _tools_missing).append(tool)
        return _wsl_ok, _wsl_distro, _tools_found, _tools_missing

    try:
        wsl_ok, wsl_distro, tools_found, tools_missing = await loop.run_in_executor(None, _check_sync)
    except Exception as e:
        log.error("kali_status check failed: %s", e)
        wsl_ok, wsl_distro, tools_found, tools_missing = False, "", [], kali_tools_list

    mode = ("wsl" if (is_win and wsl_ok) else
            "native_linux" if not is_win else
            "windows_no_wsl")
    total = len(kali_tools_list)
    return {
        "platform": sys.platform,
        "mode": mode,
        "wsl_available": wsl_ok,
        "wsl_distro": wsl_distro,
        "tools_found": tools_found,
        "tools_missing": tools_missing,
        "ready": len(tools_found) > 0,
        "message": (
            f"WSL ({wsl_distro}) connected — {len(tools_found)}/{total} tools found"
            if wsl_ok else
            f"Native Linux — {len(tools_found)}/{total} tools found"
            if not is_win else
            "Windows without WSL — install WSL + Kali Linux"
        )
    }


# ── Live log tail endpoint ─────────────────────────────────────
import collections as _collections
_LOG_BUFFER: _collections.deque = _collections.deque(maxlen=200)

class _BufferHandler(logging.Handler):
    _fmt = logging.Formatter()
    def emit(self, record):
        _LOG_BUFFER.append({
            "t": self._fmt.formatTime(record, "%H:%M:%S"),
            "level": record.levelname,
            "name": record.name.replace("aavapt.", ""),
            "msg": record.getMessage(),
        })

_buf_handler = _BufferHandler()
_buf_handler.setLevel(logging.DEBUG)
logging.getLogger("aavapt").addHandler(_buf_handler)

@app.get("/api/logs")
async def get_logs(n: int = 100):
    """Return last N log lines from the in-memory buffer."""
    return {"logs": list(_LOG_BUFFER)[-n:]}


# ── AI Analysis ────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, _auth=Depends(require_auth)):
    if not ai.is_ollama_running():
        raise HTTPException(503, "Ollama not running — run: bash install.sh && ollama serve")
    similar  = mem.search_similar(f"{req.finding_name} {req.plugin_id} {req.synopsis}", n_results=3)
    mem_ctx  = mem.build_memory_context(similar)
    result   = await ai.analyze_output(
        host=req.host, finding_name=req.finding_name, plugin_id=req.plugin_id,
        severity=req.severity, synopsis=req.synopsis, plugin_output=req.plugin_output,
        command=req.command, raw_output=req.raw_output, memory_context=mem_ctx
    )
    # TASK 5: auto-store only high-confidence verified analyses (>70)
    if req.store_memory and result.get("confidence", 0) > 70:
        doc_id = mem.store_finding(
            host=req.host, finding_name=req.finding_name, plugin_id=req.plugin_id,
            severity=req.severity, command=req.command, raw_output=req.raw_output,
            verdict=result.get("verdict","needs-more"), confidence=result.get("confidence",0),
            summary=result.get("summary",""), indicators=result.get("indicators",[])
        )
        result["memory_id"] = doc_id
        await ws_manager.broadcast({"event": "memory_updated",
                                     "data": mem.get_stats()})
    result["similar_findings"] = similar
    return JSONResponse(result)


# ── Chat ────────────────────────────────────────────────────────
@app.post("/api/chat")
async def chat(req: ChatRequest):
    if not ai.is_ollama_running():
        raise HTTPException(503, "Ollama not running")
    context = (f"Finding: {req.finding_name}\nPlugin: {req.plugin_id}\n"
               f"Severity: {req.severity}\nSynopsis: {req.synopsis}\n"
               f"Plugin Output: {req.plugin_output[:500]}")
    answer = await ai.chat_finding(req.question, context)
    return {"answer": answer, "model": ai.get_available_model()}


# ── AI Commands ─────────────────────────────────────────────────
@app.post("/api/commands")
async def suggest_commands(req: CommandRequest):
    if not ai.is_ollama_running():
        raise HTTPException(503, "Ollama not running")
    cmds = await ai.suggest_commands(
        finding_name=req.finding_name, plugin_id=req.plugin_id,
        port=req.port, service=req.service, host=req.host, context=req.context
    )
    return {"commands": cmds, "count": len(cmds)}


# ── Executive Summary ───────────────────────────────────────────
@app.post("/api/summary")
async def executive_summary(req: SummaryRequest):
    if not ai.is_ollama_running():
        raise HTTPException(503, "Ollama not running")
    summary = await ai.generate_executive_summary(json.dumps(req.findings, indent=2))
    return {"summary": summary}


# ── SOAR Triage ─────────────────────────────────────────────────
@app.post("/api/soar/triage")
async def soar_triage(req: TriageRequest, _auth=Depends(require_auth)):
    """Auto-triage all findings via SOAR orchestrator.
    ENH-12: Max 500 findings per request to prevent system overload."""
    # ENH-12: Hard limit to prevent memory/CPU exhaustion
    MAX_TRIAGE_FINDINGS = 500
    if len(req.findings) > MAX_TRIAGE_FINDINGS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many findings ({len(req.findings)}). Max per triage request: {MAX_TRIAGE_FINDINGS}. "
                   f"Split your scan into batches."
        )
    orchestrator.clear()
    job_ids = await orchestrator.submit(req.findings, req.host)
    return {"job_ids": job_ids, "total": len(job_ids),
            "message": f"Triage started for {len(job_ids)} findings"}

@app.get("/api/soar/status")
async def soar_status():
    return orchestrator.get_summary()

@app.get("/api/soar/results")
async def soar_results():
    return {"results": orchestrator.get_all_statuses()}

@app.get("/api/soar/result/{job_id}")
async def soar_result(job_id: str):
    r = orchestrator.get_status(job_id)
    if not r:
        raise HTTPException(404, f"Job {job_id} not found")
    return r

@app.get("/api/soar/playbooks")
async def list_playbooks():
    from backend.soar.playbooks import PLAYBOOKS
    return {"playbooks": [
        {"key": k, "name": v["name"], "icon": v.get("icon",""),
         "risk_level": v.get("risk_level",""), "steps": len(v.get("steps",[]))}
        for k, v in PLAYBOOKS.items()
    ]}


# ── Multi-Model ─────────────────────────────────────────────────
@app.get("/api/models")
async def get_models():
    return ai.get_model_info()

@app.post("/api/models/select")
async def select_model(req: ModelSelectRequest):
    ai.set_active_model(req.model_id)
    await ws_manager.broadcast({"event": "model_changed",
                                 "data": {"model": req.model_id}})
    return {"active": req.model_id, "message": f"Switched to {req.model_id}"}


# ── Memory ──────────────────────────────────────────────────────
@app.post("/api/memory/search")
async def memory_search(req: SearchRequest):
    results = mem.search_similar(req.query, req.n_results)
    return {"results": results, "count": len(results)}

@app.get("/api/memory/stats")
async def memory_stats():
    return mem.get_stats()

@app.delete("/api/memory")
async def memory_clear():
    ok = mem.clear_memory()
    return {"success": ok}

@app.post("/api/memory/feedback")
async def memory_feedback(req: FeedbackRequest):
    """FIX B9: Actually persist feedback into ChromaDB as a correction note."""
    try:
        col = mem.get_collection()
        if col is None:
            raise HTTPException(503, "ChromaDB not available")

        # Try to locate the original entry to embed correction context
        existing = None
        try:
            existing = col.get(ids=[req.memory_id], include=["metadatas", "documents"])
        except Exception:
            pass

        if existing and existing.get("ids"):
            orig_meta = existing["metadatas"][0] if existing.get("metadatas") else {}
            orig_doc  = existing["documents"][0] if existing.get("documents") else ""
            feedback_doc = (
                f"FEEDBACK_CORRECTION {orig_doc} "
                f"user_correct={req.correct} notes={req.notes}"
            )
            feedback_meta = {
                **orig_meta,
                "feedback_correct": str(req.correct),
                "feedback_notes": req.notes[:300],
                "feedback_for": req.memory_id,
                "timestamp": datetime.utcnow().isoformat(),
            }
            # Adjust verdict based on feedback
            if not req.correct:
                feedback_meta["verdict"] = "fp"
                feedback_meta["confidence"] = 10
            feedback_id = f"fb_{uuid.uuid4().hex[:12]}"
            col.add(
                documents=[feedback_doc],
                metadatas=[feedback_meta],
                ids=[feedback_id]
            )
            log.info(f"Feedback stored: {feedback_id} for memory {req.memory_id} correct={req.correct}")
            await ws_manager.broadcast({"event": "memory_updated", "data": mem.get_stats()})
            return {"recorded": True, "memory_id": req.memory_id, "feedback_id": feedback_id}
        else:
            log.warning(f"Memory ID {req.memory_id} not found for feedback")
            return {"recorded": False, "memory_id": req.memory_id,
                    "reason": "Original memory entry not found"}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Feedback error: {e}")
        raise HTTPException(500, f"Feedback storage failed: {e}")


# ── History ─────────────────────────────────────────────────────
class HistorySaveRequest(BaseModel):
    name: str
    target: str
    scan_date: str = ""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    issues: list[Any] = []
    outputs: dict = {}

@app.post("/api/history/save")
async def history_save(req: HistorySaveRequest):
    # FIX BUG-08: Use 12 chars instead of 8 to reduce collision probability
    hid = str(uuid.uuid4())[:12]
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in req.name)[:40].strip()
    fname = f"{hid}_{safe_name.replace(' ','_')}.json"
    meta = {
        "id": hid, "name": req.name, "target": req.target,
        "scan_date": req.scan_date, "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total": req.total, "critical": req.critical, "high": req.high,
        "medium": req.medium, "low": req.low, "info": req.info, "file": fname
    }
    path = os.path.join(HISTORY_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "issues": req.issues, "outputs": req.outputs}, f)
    log.info(f"History saved: {fname}")
    return {"id": hid, "name": req.name, "saved": True}

@app.get("/api/history/list")
async def history_list():
    scans = []
    for fname in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(HISTORY_DIR, fname), encoding="utf-8") as f:
                    d = json.load(f)
                    scans.append(d.get("meta", {}))
            except Exception:
                pass
    return {"scans": scans}

@app.get("/api/history/load/{hid}")
async def history_load(hid: str):
    # FIX B10: Reject empty or suspicious hid values before scanning directory
    if not hid or not hid.replace("-", "").isalnum() or len(hid) > 64:
        raise HTTPException(400, "Invalid scan ID")
    for fname in os.listdir(HISTORY_DIR):
        if fname.startswith(hid + "_") and fname.endswith(".json"):
            try:
                with open(os.path.join(HISTORY_DIR, fname), encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                log.error(f"Failed to load history file {fname}: {e}")
                raise HTTPException(500, f"Scan file corrupted: {fname}")
    raise HTTPException(404, f"Scan {hid} not found")

@app.delete("/api/history/{hid}")
async def history_delete(hid: str):
    # FIX B10: Same guard as history_load
    if not hid or not hid.replace("-", "").isalnum() or len(hid) > 64:
        raise HTTPException(400, "Invalid scan ID")
    for fname in os.listdir(HISTORY_DIR):
        if fname.startswith(hid + "_") and fname.endswith(".json"):
            os.remove(os.path.join(HISTORY_DIR, fname))
            return {"deleted": True}
    raise HTTPException(404, f"Scan {hid} not found")


# ── Script Generation ──────────────────────────────────────────────
class ScriptGenRequest(BaseModel):
    findings: list[dict]
    scan_name: str = "scan"

@app.post("/api/generate-scripts")
async def generate_scripts(req: ScriptGenRequest):
    """Auto-generate SSL, Server-Version, and Weak-SSH verification scripts from findings."""
    # FIX B17: Sanitize scan_name before passing to script generator
    safe_scan_name = "".join(
        c if c.isalnum() or c in "-_ " else "_" for c in req.scan_name
    )[:60].strip() or "scan"
    result = script_generator.generate_all_scripts(req.findings, safe_scan_name)
    return {
        "ssl_script":            result["ssl_script"],
        "server_version_script": result["server_version_script"],
        "ssh_script":            result["ssh_script"],
        "ssl_count":             result["ssl_count"],
        "server_version_count":  result["server_version_count"],
        "ssh_count":             result["ssh_count"],
        "ssl_hosts":             result["ssl_hosts"],
        "server_hosts":          result["server_hosts"],
        "ssh_hosts":             result["ssh_hosts"],
    }

@app.get("/api/generate-scripts/download/{script_type}")
async def download_script(script_type: str, scan_name: str = "scan"):
    """Download a generated script - pass findings via POST /api/generate-scripts first."""
    raise HTTPException(400, "Use POST /api/generate-scripts with your findings JSON to generate scripts.")


# ── Findings sync + Global Search/Ask (Task 2/3 unified pipeline) ───
class FindingsSyncRequest(BaseModel):
    findings: list[dict] = []
    target: str = ""
    scan_date: str = ""

@app.post("/api/findings/sync")
async def findings_sync(req: FindingsSyncRequest):
    """Frontend pushes the currently loaded scan so MCP tools + chat share it.
    Also indexes the findings into ChromaDB (RAG) in the background so chat /
    similar-search / MCP can retrieve from the current scan."""
    n = findings_store.set_findings(req.findings, {"target": req.target, "scan_date": req.scan_date})
    # Fire-and-forget RAG indexing (embedding can be slow — don't block the response)
    try:
        import asyncio as _aio
        _aio.get_running_loop().run_in_executor(None, mem.index_findings, list(req.findings or []))
    except Exception as _e:
        log.warning(f"RAG index dispatch failed: {_e}")
    return {"loaded": n, "target": req.target, "rag_indexing": True}

@app.get("/api/findings/search")
async def findings_search(q: str, limit: int = 50):
    """Offline-safe keyword / IP / port / CVE search across the loaded scan."""
    return {"query": q, "results": findings_store.search(q, limit)}


@app.get("/api/findings/page")
async def findings_page(page: int = 0, per_page: int = 100):
    """ENH-06: Paginated findings access — use for large scans instead of /api/findings/search."""
    return findings_store.get_page(page, per_page)


# ── Machine Learning: FP filter (supervised) + clustering (unsupervised) ──
from backend.ai import ml_engine as ml


class MLTrainRequest(BaseModel):
    findings: list[dict] = []      # each needs label/verdict (confirmed | fp)


class MLPredictRequest(BaseModel):
    findings: list[dict] = []      # if empty, uses the loaded scan


class MLClusterRequest(BaseModel):
    findings: list[dict] = []      # if empty, uses the loaded scan
    k: Optional[int] = None


@app.get("/api/ml/status")
async def ml_status():
    """Is ML available, is the FP model trained, on how many samples?"""
    return ml.status()


@app.post("/api/ml/train-fp")
async def ml_train_fp(req: MLTrainRequest):
    """Train the false-positive classifier from your Confirmed / FP verdicts."""
    return ml.train_fp(req.findings)


@app.post("/api/ml/predict-fp")
async def ml_predict_fp(req: MLPredictRequest):
    """Predict false-positive likelihood for findings (loaded scan if none sent)."""
    findings = req.findings or findings_store.get_all()
    return ml.predict_fp(findings)


@app.post("/api/ml/cluster")
async def ml_cluster(req: MLClusterRequest):
    """Group similar findings (loaded scan if none sent) to spot patterns."""
    findings = req.findings or findings_store.get_all()
    return ml.cluster(findings, req.k)


class MLRiskRequest(BaseModel):
    findings: list[dict] = []
    asset_weights: dict = {}      # {ip: multiplier} optional


@app.post("/api/ml/risk-rank")
async def ml_risk_rank(req: MLRiskRequest):
    """Explainable priority score (0-100) per finding — 'fix this first' order."""
    findings = req.findings or findings_store.get_all()
    return ml.risk_rank(findings, req.asset_weights)


class RemediationRequest(BaseModel):
    finding: dict = {}


@app.post("/api/ml/remediation")
async def ml_remediation(req: RemediationRequest):
    """AI remediation steps for one finding (offline -> Nessus solution / generic)."""
    f = req.finding or {}
    sol = str(f.get("solution", "") or "").strip()
    baseline = sol if sol and sol.lower() != "n/a" else ""
    if not ai.is_ollama_running():
        steps = baseline or ("No vendor solution provided. Apply latest vendor patches, "
                             "restrict network exposure, disable unused services, and re-test.")
        return {"ok": True, "source": "offline", "remediation": steps,
                "note": "Ollama offline — showing Nessus solution / generic guidance."}
    ctx = json.dumps({k: f.get(k) for k in
                      ("name", "severity", "synopsis", "solution", "service", "port", "cves")
                      if f.get(k)}, indent=2)
    q = ("Give concise, actionable remediation steps (numbered, max 6) for this vulnerability. "
         "Be specific about config/patch where known. End with one line starting 'Verify:'.")
    try:
        answer = await ai.chat_finding(q, ctx)
    except Exception as e:
        return {"ok": True, "source": "offline", "remediation": baseline or "AI error — see Nessus solution.",
                "note": "AI error: " + str(e)}
    return {"ok": True, "source": "ai", "model": ai.get_available_model(),
            "remediation": answer, "baseline": baseline}


# ── Live Exploit Intelligence (EPSS + CISA KEV) ──────────────────
from backend.ai import exploit_intel as intel


class IntelRequest(BaseModel):
    cves: list[str] = []


@app.post("/api/intel/enrich")
async def intel_enrich(req: IntelRequest):
    """Live EPSS (exploit probability) + CISA KEV (in-the-wild) for given CVEs."""
    import asyncio as _aio
    loop = _aio.get_running_loop()
    return await loop.run_in_executor(None, intel.enrich, req.cves)


@app.get("/api/intel/status")
async def intel_status():
    """KEV catalog size + EPSS cache size (warms KEV on first call)."""
    import asyncio as _aio
    loop = _aio.get_running_loop()
    await loop.run_in_executor(None, intel.load_kev)
    return intel.status()


# ── Cross-scan RAG knowledge ─────────────────────────────────────
class MemLookupRequest(BaseModel):
    findings: list[dict] = []


@app.post("/api/memory/lookup")
async def memory_lookup(req: MemLookupRequest):
    """For each finding, return the best PAST VERIFIED match (confirmed/fp) from memory."""
    import asyncio as _aio
    findings = req.findings or findings_store.get_all()
    loop = _aio.get_running_loop()
    res = await loop.run_in_executor(None, mem.lookup_findings, findings)
    return {"ok": True, "scanned": len(findings), "seen_before": len(res), "matches": res}


class StoreVerdictRequest(BaseModel):
    host: str = ""
    finding_name: str = ""
    plugin_id: str = ""
    severity: str = "info"
    command: str = ""
    raw_output: str = ""
    verdict: str = "needs-more"
    confidence: int = 0
    summary: str = ""
    indicators: list = []


@app.post("/api/memory/store-verdict")
async def memory_store_verdict(req: StoreVerdictRequest):
    """Persist a user/AI verdict into ChromaDB so future scans recognise it (RAG knowledge)."""
    import asyncio as _aio
    loop = _aio.get_running_loop()
    did = await loop.run_in_executor(None, lambda: mem.store_finding(
        host=req.host, finding_name=req.finding_name, plugin_id=req.plugin_id,
        severity=req.severity, command=req.command, raw_output=req.raw_output,
        verdict=req.verdict, confidence=req.confidence, summary=req.summary,
        indicators=req.indicators))
    return {"ok": bool(did), "id": did}


class AskRequest(BaseModel):
    question: str
    findings: list[dict] = []
    target: str = ""

@app.post("/api/ask")
async def ask(req: AskRequest):
    """Global chatbot: answer using ONLY the loaded scan + ChromaDB memory.
    Always returns local keyword matches; adds an AI answer when Ollama is up."""
    import re as _re
    if req.findings:
        findings_store.set_findings(req.findings, {"target": req.target})

    tokens = _re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|CVE-\d{4}-\d+|\b\w{3,}\b", req.question)
    matches, seen = [], set()
    for t in tokens:
        for f in findings_store.search(t, 40):
            key = (f["plugin_id"], tuple(f["hosts"]), f["port"])
            if key not in seen:
                seen.add(key); matches.append(f)
    for sev in ("critical", "high", "medium", "low"):
        if sev in req.question.lower():
            for f in findings_store.get_all():
                if f["severity"] == sev:
                    key = (f["plugin_id"], tuple(f["hosts"]), f["port"])
                    if key not in seen:
                        seen.add(key); matches.append(f)
    matches = matches[:40]

    memory = mem.search_similar(req.question, n_results=3)

    answer = None
    if ai.is_ollama_running():
        try:
            ctx_lines = [
                "- [" + m["severity"].upper() + "] " + m["name"] +
                " (plugin " + m["plugin_id"] + ", port " + m["port"] +
                ", hosts " + (", ".join(m["hosts"][:5]) or "n/a") + ")"
                for m in matches[:25]
            ]
            context = (
                "Loaded scan findings relevant to the question:\n" +
                ("\n".join(ctx_lines) if ctx_lines else "None matched.") +
                "\n\nPast memory:\n" + mem.build_memory_context(memory)
            )
            answer = await ai.chat_finding(req.question, context)
        except Exception as e:
            log.error("ask AI error: %s", e)

    return {
        "question": req.question,
        "answer": answer,
        "ollama": ai.is_ollama_running(),
        "match_count": len(matches),
        "matches": matches,
        "memory": memory,
    }


# ──────────────────────────────────────────────────────────────────────────────
#  /api/graphify/* — Knowledge Graph endpoints (powered by graphifyy)
#  71.5x token reduction vs reading raw findings
#  https://github.com/safishamsi/graphify
# ──────────────────────────────────────────────────────────────────────────────

from backend import graphify_integration as _gfy

class GraphBuildRequest(BaseModel):
    scan_label: str = "vapt_scan"
    mode: str = "standard"        # "standard" | "deep"
    extra_files: list[str] = []   # optional extra file paths to include in graph
    findings: list[dict] = []     # if empty, uses findings_store

class GraphQueryRequest(BaseModel):
    graph_json_path: str
    question: str

class GraphExplainRequest(BaseModel):
    graph_json_path: str
    node: str                     # CVE ID, hostname, plugin name, etc.


@app.get("/api/graphify/status")
async def graphify_status():
    """Check if graphify is installed and return version + list of built graphs."""
    available = _gfy.is_graphify_available()
    return {
        "available": available,
        "version": _gfy.get_graphify_version() if available else None,
        "install_cmd": "pip install graphifyy && graphify install",
        "graphs": _gfy.list_graphs(),
        "info": {
            "token_reduction": "71.5x vs reading raw findings",
            "extraction": "Tree-sitter AST + LLM semantic",
            "repo": "https://github.com/safishamsi/graphify",
        },
    }


@app.post("/api/graphify/build")
async def graphify_build(req: GraphBuildRequest):
    """
    Build a knowledge graph from current VAPT findings.

    Uses graphifyy to convert Nessus findings → interactive knowledge graph.
    Outputs: graph.json (queryable), graph.html (visual), GRAPH_REPORT.md (god nodes, surprises).
    Token reduction: ~71.5x vs naive file reading.
    """
    # Use provided findings or fall back to findings_store
    findings = req.findings if req.findings else findings_store.get_all()
    if not findings:
        raise HTTPException(status_code=400, detail="No findings loaded. Upload a Nessus scan first.")

    result = await _gfy.build_knowledge_graph(
        findings=findings,
        scan_label=req.scan_label,
        mode=req.mode,
        extra_files=req.extra_files or None,
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "graphify build failed"))

    return result


@app.post("/api/graphify/query")
async def graphify_query(req: GraphQueryRequest):
    """
    Query an existing knowledge graph using natural language.

    Example questions:
      - "what CVEs are related to OpenSSH?"
      - "which hosts have critical vulnerabilities?"
      - "what connects SSL issues to the authentication findings?"

    Uses 71.5x fewer tokens than re-reading raw findings files.
    """
    result = await _gfy.query_graph(req.graph_json_path, req.question)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/graphify/explain")
async def graphify_explain(req: GraphExplainRequest):
    """
    Get a deep explanation of a specific node in the knowledge graph.
    Node can be a CVE ID (e.g. CVE-2023-38408), hostname, service name, or plugin name.
    """
    result = await _gfy.explain_node(req.graph_json_path, req.node)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.get("/api/graphify/list")
async def graphify_list():
    """List all previously built knowledge graphs with their output paths."""
    return {"graphs": _gfy.list_graphs()}


# ══════════════════════════════════════════════════════════════════════════════
#  /api/chains/* — Attack Chain Detection Engine
#  Detects multi-step attack paths across loaded Nessus findings.
#  Individual Medium/Low findings → combined CRITICAL chain + PoC script.
# ══════════════════════════════════════════════════════════════════════════════

from backend.attack_chain_engine import run_chain_detection, generate_poc_script, CHAIN_RULES

class ChainDetectRequest(BaseModel):
    narrate: bool = True          # call Ollama for LLM narrative (set False for offline mode)
    findings: list[dict] = []     # optional: pass findings directly; empty = use findings_store


class PocDownloadRequest(BaseModel):
    chain_id: str
    affected_hosts: list[str] = []
    generates: str = ""


@app.post("/api/chains/detect")
async def chains_detect(req: ChainDetectRequest):
    """
    Run attack chain detection on loaded Nessus findings.

    Returns all detected multi-step attack paths with:
      - upgraded risk level (individual findings may be Medium, chain is CRITICAL)
      - LLM-generated attack narrative (Ollama)
      - step-by-step attack path
      - MITRE ATT&CK technique IDs
      - affected hosts
      - evidence (which findings triggered each condition)
      - ready-to-run PoC bash script
    """
    findings = req.findings if req.findings else findings_store.get_all()
    if not findings:
        raise HTTPException(status_code=400, detail="No findings loaded. Upload a Nessus scan first.")

    result = await run_chain_detection(findings, narrate=req.narrate)
    return result


@app.get("/api/chains/rules")
async def chains_rules():
    """List all available chain detection rules."""
    return {
        "total_rules": len(CHAIN_RULES),
        "rules": [
            {
                "id": r["id"],
                "name": r["name"],
                "upgraded_risk": r["upgraded_risk"],
                "mitre": r["mitre"],
                "conditions_required": len(r.get("requires", [])),
                "has_any_of": len(r.get("any_of", [])) > 0,
            }
            for r in CHAIN_RULES
        ],
    }


@app.post("/api/chains/poc")
async def chains_poc(req: PocDownloadRequest):
    """
    Generate / re-generate a PoC script for a specific chain.
    Pass chain_id + affected_hosts to customize the script.
    """
    # Find the rule
    rule = next((r for r in CHAIN_RULES if r["id"] == req.chain_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Chain rule not found: {req.chain_id}")

    chain = {
        "chain_id": req.chain_id,
        "generates": req.generates or rule.get("generates", ""),
        "affected_hosts": req.affected_hosts or [],
        "steps": rule.get("steps", []),
    }
    script = generate_poc_script(chain)
    return {
        "chain_id": req.chain_id,
        "chain_name": rule["name"],
        "script": script,
        "filename": f"poc_{req.chain_id}.sh",
    }


# =============================================

# ═══════════════════════════════════════════════════════════════════════════
# WEBAPP PT MODULE ROUTES
# All processing is localhost only — zero external API calls
# ═══════════════════════════════════════════════════════════════════════════

from backend.webapp_pt.session_manager import get_store, SessionState, TestResult
from backend.webapp_pt.crawler import WebAppCrawler
from backend.webapp_pt.test_engine import TestEngine, check_ollama_available
from backend.webapp_pt.burp_integration import (
    detect_burp_mode, set_api_key as burp_set_api_key,
    start_scan_pro, get_scan_status_pro, get_scan_issues_pro,
    import_burp_xml, analyze_manual_request, validate_scan_permission,
    start_burp_job, get_burp_job, import_burp_xml_unified, burp_available,
)
from backend.webapp_pt.report_generator import (
    generate_html_report, generate_json_report, generate_markdown_report,
)
# wstg_checklist imported locally inside get_wstg_checklist_api to avoid startup overhead


class WebAppStartRequest(BaseModel):
    target_url: str
    tester_name: Optional[str] = "Anonymous Tester"


class PermissionRequest(BaseModel):
    has_written_permission: bool
    is_authorized_tester: bool
    understands_scope: bool
    agrees_not_to_exploit: bool
    confirmed_target_url: str


class TestResultRequest(BaseModel):
    result: str
    notes: Optional[str] = ""
    evidence: Optional[str] = ""
    payload_used: Optional[str] = ""
    burp_request: Optional[str] = ""


class BurpApiKeyRequest(BaseModel):
    api_key: str


class BurpRawRequest(BaseModel):
    raw_request: str
    target_host: Optional[str] = ""


class BurpXmlRequest(BaseModel):
    xml_content: str


class BurpScanRequest(BaseModel):
    target_url: str
    scan_type: Optional[str] = "crawl_and_audit"
    username: Optional[str] = ""
    password: Optional[str] = ""


class BurpMemoryRequest(BaseModel):
    target: Optional[str] = ""
    findings: list = []


class CrawlRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    max_pages: Optional[int] = 50


@app.post("/api/webapp-pt/start-session")
async def webapp_pt_start(req: WebAppStartRequest):
    store = get_store()
    session = store.create(target_url=req.target_url, tester_name=req.tester_name)
    return {"session_id": session.session_id, "state": session.state,
            "target_url": session.target_url}


@app.post("/api/webapp-pt/{session_id}/request-permission")
async def webapp_pt_permissions(session_id: str, req: PermissionRequest):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    perms = req.dict()
    result = validate_scan_permission(perms, session.target_url)
    store.set_permissions(session_id, perms)
    return {**result, "session_id": session_id}


@app.post("/api/webapp-pt/{session_id}/crawl")
async def webapp_pt_crawl(session_id: str, req: CrawlRequest):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.permissions_granted():
        raise HTTPException(status_code=403, detail="Permission gate not passed.")
    store.update_state(session_id, SessionState.CRAWLING)

    async def broadcast(data: dict):
        data["session_id"] = session_id
        await ws_manager.broadcast(data)

    async def run_crawl():
        try:
            crawler = WebAppCrawler(max_pages=req.max_pages, broadcast_fn=broadcast)
            if req.username and req.password:
                result = await crawler.crawl_authenticated(
                    session.target_url, req.username, req.password)
            else:
                result = await crawler.crawl_unauthenticated(session.target_url)
            crawl_dict = result.to_dict()
            store.set_crawl_result(session_id, crawl_dict)
            store.set_checklist(session_id, [])
            await ws_manager.broadcast({
                "type": "webapp_crawl_complete",
                "session_id": session_id,
                "summary": result.summary(),
                "state": SessionState.CHECKLIST_READY,
                "stats": crawl_dict,
            })
        except Exception as e:
            await ws_manager.broadcast({
                "type": "webapp_crawl_error",
                "session_id": session_id,
                "error": str(e),
            })
            store.update_state(session_id, SessionState.ABORTED)

    import asyncio
    asyncio.create_task(run_crawl())
    return {"status": "crawl_started", "session_id": session_id}


@app.post("/api/webapp-pt/{session_id}/generate-checklist")
async def webapp_pt_generate_checklist(session_id: str):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.crawl_result:
        raise HTTPException(status_code=400, detail="Run crawl first")
    store.set_checklist(session_id, [])
    s = store.get(session_id)
    return {"session_id": session_id, "total_tests": s.total_tests, "state": s.state}


@app.get("/api/webapp-pt/sessions/list")
async def webapp_pt_list_sessions():
    store = get_store()
    return {"sessions": store.get_all()}


@app.get("/api/webapp-pt/ai/status")
async def webapp_pt_ai_status():
    return check_ollama_available()


# ───────── WebApp-PT: live tool runner (run real tools → merged results) ─────────
try:
    from backend.webapp_pt import tool_runner as _tool_runner
except Exception as _e:  # fail-safe: backend still boots if module has an issue
    _tool_runner = None
    log.warning("tool_runner unavailable: %s", _e)


class ToolRunRequest(BaseModel):
    target: str
    tools: Optional[list] = None
    oob: Optional[str] = None


@app.get("/api/webapp-pt/tools/available")
async def webapp_pt_tools_available():
    if _tool_runner is None:
        return {"ok": False, "error": "tool_runner unavailable", "tools": {}}
    return {"ok": True, "tools": _tool_runner.available_tools(),
            "default_suite": _tool_runner.DEFAULT_SUITE}


@app.post("/api/webapp-pt/tools/run")
async def webapp_pt_tools_run(req: ToolRunRequest):
    if _tool_runner is None:
        raise HTTPException(status_code=503, detail="tool_runner unavailable")
    ok, msg = _tool_runner.validate_target(req.target or "")
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    job_id = await _tool_runner.run_job(req.target.strip(), req.tools or [], req.oob)
    return {"ok": True, "job_id": job_id}


@app.get("/api/webapp-pt/tools/run/{job_id}")
async def webapp_pt_tools_run_status(job_id: str):
    if _tool_runner is None:
        raise HTTPException(status_code=503, detail="tool_runner unavailable")
    job = _tool_runner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return {"ok": True, "state": job.get("state"), "target": job.get("target"),
            "tools": job.get("tools"), "pending": job.get("pending", []),
            "stages": _tool_runner.STAGES,
            "per_tool": [{"tool": r.get("tool"), "ok": r.get("ok"),
                          "installed": r.get("installed", True),
                          "stage": r.get("stage"),
                          "count": r.get("count", 0), "error": r.get("error"),
                          "hint": r.get("hint"), "duration": r.get("duration")}
                         for r in job.get("per_tool", [])],
            "merged": job.get("merged", []),
            "duration": job.get("duration")}


@app.get("/api/webapp-pt/{session_id}/next-test")
async def webapp_pt_next_test(session_id: str):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    test = store.start_test(session_id)
    if not test:
        return {"completed": True, "message": "All tests completed"}
    try:
        engine = TestEngine(session_id)
        enriched = engine.get_enriched_test(test, session.crawl_result)
        store.set_ai_guidance(session_id, test["test_id"], enriched.get("ai_guidance", ""))
        return {"completed": False, "test": enriched, "progress": session.to_dict()}
    except Exception as e:
        return {"completed": False, "test": test, "progress": session.to_dict(),
                "ai_error": str(e)}


@app.post("/api/webapp-pt/{session_id}/submit-result")
async def webapp_pt_submit_result(session_id: str, req: TestResultRequest):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    valid_results = [TestResult.VULNERABLE, TestResult.NOT_VULN,
                     TestResult.SKIPPED, TestResult.NEED_MANUAL]
    if req.result not in valid_results:
        raise HTTPException(status_code=400,
                            detail=f"Invalid result. Must be one of: {valid_results}")
    if req.result == TestResult.VULNERABLE:
        current = session.current_test()
        if current:
            try:
                engine = TestEngine(session_id)
                engine.on_finding(current, req.notes, req.evidence,
                                  req.payload_used, current.get("severity", "medium"))
            except Exception:
                pass
    result = store.submit_result(
        session_id=session_id, result=req.result, notes=req.notes,
        evidence=req.evidence, payload=req.payload_used, burp_req=req.burp_request)
    return result


@app.post("/api/webapp-pt/{session_id}/skip-test")
async def webapp_pt_skip(session_id: str):
    store = get_store()
    if not store.get(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return store.skip_test(session_id)


@app.get("/api/webapp-pt/{session_id}")
async def webapp_pt_get_session(session_id: str):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.to_dict(include_sensitive=True)


@app.delete("/api/webapp-pt/{session_id}")
async def webapp_pt_delete_session(session_id: str):
    store = get_store()
    if not store.delete(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": True, "session_id": session_id}


@app.post("/api/webapp-pt/{session_id}/generate-report")
async def webapp_pt_generate_report(session_id: str, fmt: str = "html"):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    s_dict = session.to_dict(include_sensitive=False)
    crawl = session.crawl_result
    if fmt == "html":
        from fastapi.responses import HTMLResponse
        html = generate_html_report(s_dict, session.findings, session.checklist, crawl)
        return HTMLResponse(content=html)
    elif fmt == "json":
        return generate_json_report(s_dict, session.findings, session.checklist, crawl)
    elif fmt == "markdown":
        from fastapi.responses import PlainTextResponse
        md = generate_markdown_report(s_dict, session.findings, crawl)
        return PlainTextResponse(content=md)
    raise HTTPException(status_code=400, detail="fmt must be html, json, or markdown")


@app.post("/api/webapp-pt/{session_id}/parse-burp")
async def webapp_pt_parse_burp(session_id: str, req: BurpRawRequest):
    store = get_store()
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    host = req.target_host or session.target_url.split("//")[-1].split("/")[0]
    return analyze_manual_request(req.raw_request, host)


# ── Burp Suite Routes ──────────────────────────────

@app.get("/api/burp/detect")
async def burp_detect():
    return detect_burp_mode()


@app.post("/api/burp/set-api-key")
async def burp_set_key(req: BurpApiKeyRequest):
    burp_set_api_key(req.api_key)
    return {"success": True, "message": "Burp Pro API key configured"}


@app.get("/api/burp/available")
async def burp_is_available():
    """True if Burp Pro REST API + key are ready (used by Attack Flow auto-include)."""
    return {"available": burp_available()}


@app.post("/api/burp/run")
async def burp_run(req: BurpScanRequest):
    """Start an AUTOMATED Burp Pro scan job (Pro only). Returns {ok, job_id}."""
    ok, msg = _tool_runner.validate_target(req.target_url or "") if _tool_runner else (True, "")
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return start_burp_job((req.target_url or "").strip(), req.scan_type or "crawl_and_audit",
                          username=req.username or "", password=req.password or "")


@app.post("/api/burp/to-memory")
async def burp_to_memory(req: BurpMemoryRequest):
    """Save Burp findings into ChromaDB memory (so AI can reference / dedupe across scans)."""
    saved = 0
    for f in (req.findings or []):
        try:
            mem.store_finding(
                host=f.get("location") or req.target or "",
                finding_name=f.get("name") or "Burp issue",
                plugin_id="burp:" + (f.get("name") or "")[:40],
                severity=(f.get("severity") or "info"),
                command="Burp Suite scan",
                raw_output=(f.get("detail") or ""),
                verdict="confirmed",
                confidence=80,
                summary=(f.get("detail") or f.get("name") or ""),
                indicators=[f.get("source", "burp")],
            )
            saved += 1
        except Exception as e:
            log.warning("burp memory save failed: %s", e)
    return {"ok": True, "saved": saved, "stats": mem.get_stats()}


@app.get("/api/burp/run/{job_id}")
async def burp_run_status(job_id: str):
    """Poll a Burp scan job — returns state, status, issue_count, and unified findings."""
    job = get_burp_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return {"ok": True, "state": job.get("state"), "status": job.get("status"),
            "issue_count": job.get("issue_count", 0),
            "findings": job.get("findings", []),
            "error": job.get("error"), "duration": job.get("duration")}


@app.post("/api/burp/import-xml-merge")
async def burp_import_xml_merge(req: BurpXmlRequest):
    """Community path: parse a Burp XML export -> unified findings (merge into results)."""
    return import_burp_xml_unified(req.xml_content or "")


@app.post("/api/burp/start-scan")
async def burp_start_scan(req: BurpScanRequest):
    result = start_scan_pro(req.target_url, req.scan_type)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/burp/scan-status/{scan_id}")
async def burp_scan_status(scan_id: str):
    return get_scan_status_pro(scan_id)


@app.get("/api/burp/issues/{scan_id}")
async def burp_scan_issues(scan_id: str):
    issues = get_scan_issues_pro(scan_id)
    return {"scan_id": scan_id, "count": len(issues), "issues": issues}


@app.post("/api/burp/import-xml")
async def burp_import_xml(req: BurpXmlRequest):
    return import_burp_xml(req.xml_content)


@app.post("/api/burp/analyze-request")
async def burp_analyze_request(req: BurpRawRequest):
    return analyze_manual_request(req.raw_request, req.target_host)


@app.get("/api/webapp-pt/h1-patterns")
async def get_h1_patterns_api(test_type: str = "", category: str = "", q: str = ""):
    from backend.webapp_pt.h1_patterns import (
        get_all_patterns, search_patterns, get_patterns_by_category
    )
    if q:
        return {"patterns": search_patterns(q)}
    if category:
        return {"patterns": get_patterns_by_category(category)}
    if test_type:
        # test_type may be space-separated list — search each term and deduplicate
        terms = [t.strip().replace("_", " ") for t in test_type.split() if t.strip()]
        seen, results = set(), []
        for term in terms:
            for pat in search_patterns(term):
                if pat["id"] not in seen:
                    seen.add(pat["id"])
                    results.append(pat)
        # Sort by h1_count descending
        results.sort(key=lambda p: p.get("h1_count", 0), reverse=True)
        return {"patterns": results}
    return {"patterns": get_all_patterns()}


@app.get("/api/webapp-pt/wstg-checklist")
async def get_wstg_checklist_api():
    from backend.webapp_pt.wstg_checklist import get_all_tests, get_category_summary
    return {"tests": get_all_tests(), "summary": get_category_summary()}




# ══════════════════════════════════════════════════════════════
#  COMPLIANCE + DASHBOARD APIs
# ══════════════════════════════════════════════════════════════

def _get_all_findings() -> list:
    """Merge findings from findings_store and memory session."""
    return findings_store.get_all()


@app.get("/api/compliance/owasp")
async def compliance_owasp():
    """Map all loaded findings to OWASP Top 10 2021 categories."""
    from backend.compliance import owasp_analysis
    findings = _get_all_findings()
    return owasp_analysis(findings)


@app.get("/api/compliance/pci-dss")
async def compliance_pci():
    """PCI-DSS v4.0 gap analysis based on current findings."""
    from backend.compliance import pci_analysis
    findings = _get_all_findings()
    return pci_analysis(findings)


@app.get("/api/compliance/iso27001")
async def compliance_iso():
    """ISO 27001:2022 Annex A technological controls gap analysis."""
    from backend.compliance import iso27001_analysis
    findings = _get_all_findings()
    return iso27001_analysis(findings)


@app.get("/api/compliance/risk-score")
async def compliance_risk():
    """Calculate overall risk score (0-100) from current findings."""
    from backend.compliance import risk_score
    findings = _get_all_findings()
    return risk_score(findings)


@app.get("/api/compliance/topology")
async def compliance_topology():
    """Build D3-ready network topology graph from current findings."""
    from backend.compliance import build_topology
    findings = _get_all_findings()
    return build_topology(findings)


@app.post("/api/compliance/diff")
async def compliance_diff(body: dict):
    """
    Diff two finding sets.
    Body: {"old_session_id": "...", "new_session_id": "..."}
    or    {"old_findings": [...], "new_findings": [...]}
    """
    from backend.compliance import diff_scans
    from backend.agent import memory as mem_mod

    old_f = body.get("old_findings")
    new_f = body.get("new_findings")

    if old_f is None:
        old_sid = body.get("old_session_id", "")
        old_sess = mem_mod.get_session(old_sid) if old_sid else {}
        old_f = old_sess.get("findings", []) if old_sess else []

    if new_f is None:
        new_f = _get_all_findings()

    return diff_scans(old_f, new_f)


@app.get("/api/dashboard/summary")
async def dashboard_summary():
    """
    Single endpoint for dashboard -- returns everything needed to render
    the overview page without multiple round-trips.
    """
    from backend.compliance import owasp_analysis, risk_score, build_topology
    from backend.agent import memory as mem_mod

    findings = _get_all_findings()
    rs = risk_score(findings)
    owasp = owasp_analysis(findings)
    topo = build_topology(findings)

    hist = []
    try:
        hist_dir = __import__("pathlib").Path(_ROOT) / "data" / "history"
        if hist_dir.exists():
            import json as _json
            for hf in sorted(hist_dir.glob("*.json"), key=lambda p: p.stat().st_mtime):
                try:
                    meta = _json.loads(hf.read_text())
                    hist.append({
                        "id": hf.stem,
                        "name": meta.get("name", hf.stem),
                        "ts": meta.get("ts", ""),
                        "finding_count": len(meta.get("findings", [])),
                        "risk_score": meta.get("risk_score"),
                    })
                except Exception:
                    pass
    except Exception:
        pass

    return {
        "risk": rs,
        "owasp_coverage": owasp["coverage_pct"],
        "owasp_categories": [
            {"id": c["id"], "name": c["name"], "count": c["count"],
             "critical": c["critical"], "high": c["high"], "medium": c["medium"]}
            for c in owasp["categories"]
        ],
        "topology": topo,
        "history": hist[-20:],
        "findings_total": len(findings),
        "severity_counts": rs["severity_counts"],
        "affected_hosts": rs["affected_hosts"],
    }


@app.get("/dashboard.html")
async def serve_dashboard():
    return FileResponse(os.path.join(_ROOT, "dashboard.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT, reload=False)
