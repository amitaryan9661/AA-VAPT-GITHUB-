from __future__ import annotations
"""
SOAR Orchestrator — Security Orchestration, Automation & Response engine.

Workflow per finding:
  NEW → QUEUED → ENRICHING → AI_ANALYZING → VERIFIED → DONE

Features:
- Async task queue (asyncio, no Celery needed)
- Playbook-driven verification steps
- Circuit breaker on AI calls
- Real-time WebSocket broadcast
- Auto-verdict when confidence threshold hit
- Priority queue (Critical first)
- Retry logic with backoff
"""
import asyncio, logging, time, re, uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Awaitable

from backend.soar.playbooks import get_playbook
from backend.ai import ollama_client as ai
from backend.ai import chromadb_memory as mem

log = logging.getLogger("aavapt.soar.orchestrator")


# ── States ────────────────────────────────────────────────────
class State(str, Enum):
    NEW        = "new"
    QUEUED     = "queued"
    ENRICHING  = "enriching"
    ANALYZING  = "analyzing"
    VERIFIED   = "verified"
    DONE       = "done"
    ERROR      = "error"
    SKIPPED    = "skipped"


# ── Circuit Breaker ───────────────────────────────────────────
class CircuitBreaker:
    """Prevents hammering a failing service."""
    def __init__(self, max_failures: int = 3, reset_timeout: int = 60):
        self.failures = 0
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self._open_since: float | None = None

    @property
    def is_open(self) -> bool:
        if self._open_since is None:
            return False
        if time.monotonic() - self._open_since > self.reset_timeout:
            log.info("Circuit breaker: resetting (half-open)")
            self.failures = 0
            self._open_since = None
            return False
        return True

    def record_success(self):
        self.failures = 0
        self._open_since = None

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.max_failures:
            self._open_since = time.monotonic()
            log.warning(f"Circuit breaker OPEN after {self.failures} failures")


# ── Finding Task ──────────────────────────────────────────────
@dataclass
class FindingTask:
    job_id:       str
    host:         str
    finding_name: str
    plugin_id:    str
    severity:     str
    synopsis:     str = ""
    plugin_output: str = ""
    port:         str = ""
    service:      str = ""
    cves:         list = field(default_factory=list)
    state:        State = State.NEW
    playbook_name: str = ""
    confidence:   int = 0
    verdict:      str = "needs-more"
    signals:      list = field(default_factory=list)
    next_commands: list = field(default_factory=list)
    exploit_links: list = field(default_factory=list)
    raw_outputs:  list = field(default_factory=list)
    error:        str = ""
    started_at:   str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at:  str = ""
    # Priority: 0=critical, 1=high, 2=medium, 3=low, 4=info
    priority:     int = 4

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "host": self.host,
            "finding_name": self.finding_name,
            "plugin_id": self.plugin_id,
            "severity": self.severity,
            "port": self.port,
            "service": self.service,
            "state": self.state.value,
            "playbook_name": self.playbook_name,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "signals": self.signals,
            "next_commands": self.next_commands,
            "exploit_links": self.exploit_links,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


# ── Orchestrator ──────────────────────────────────────────────
class SOAROrchestrator:
    def __init__(self, max_parallel: int = 3):
        self.max_parallel = max_parallel
        # FIX B16: Do NOT create PriorityQueue here — asyncio primitives must be
        # created inside a running event loop (Python 3.10+ enforces this).
        # Queue is created lazily in start() which is called from lifespan.
        self._queue: asyncio.PriorityQueue | None = None
        self._tasks: dict[str, FindingTask] = {}
        self._running = False
        self._workers: list[asyncio.Task] = []
        self._cb_ai = CircuitBreaker(max_failures=3, reset_timeout=120)
        self._cb_mem = CircuitBreaker(max_failures=5, reset_timeout=60)
        # WebSocket broadcast callback — set by main.py
        self._broadcast: Callable[[dict], Awaitable[None]] | None = None

    def set_broadcast(self, fn: Callable[[dict], Awaitable[None]]):
        self._broadcast = fn

    async def _emit(self, event: str, data: dict):
        """Broadcast event to all connected WebSocket clients."""
        if self._broadcast:
            try:
                await self._broadcast({"event": event, "data": data,
                                       "ts": datetime.utcnow().isoformat()})
            except Exception as e:
                log.debug(f"Broadcast error: {e}")

    # ── Submit findings ───────────────────────────────────────
    async def submit(self, findings: list[dict], host: str) -> list[str]:
        """Queue multiple findings for auto-triage. Returns job IDs."""
        SEV_PRI = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ids = []
        for f in findings:
            task = FindingTask(
                job_id=str(uuid.uuid4())[:8],
                host=host,
                finding_name=f.get("name", ""),
                plugin_id=f.get("pluginId", f.get("plugin_id", "")),
                severity=f.get("severity", "info"),
                synopsis=f.get("synopsis", ""),
                plugin_output=f.get("pluginOutput", f.get("plugin_output", "")),
                port=f.get("port", ""),
                service=f.get("service", ""),
                cves=f.get("cves", []),
                state=State.QUEUED,
                priority=SEV_PRI.get(f.get("severity", "info"), 4)
            )
            self._tasks[task.job_id] = task
            if self._queue is not None:
                await self._queue.put((task.priority, task.job_id))
            else:
                # FIX BUG-09: Warn instead of silent drop when queue not ready
                log.warning("SOAR queue not ready — finding '%s' stored but not queued. "
                            "Call orchestrator.start() first.", task.finding_name)
            ids.append(task.job_id)

        await self._emit("triage_started", {
            "total": len(findings), "host": host,
            "job_ids": ids
        })
        log.info(f"Queued {len(findings)} findings for host {host}")
        return ids

    # ── Workers ───────────────────────────────────────────────
    async def start(self):
        if self._running:
            return
        # FIX B16: Create PriorityQueue here, inside the running event loop
        self._queue = asyncio.PriorityQueue()
        self._running = True
        for i in range(self.max_parallel):
            w = asyncio.create_task(self._worker(i))
            self._workers.append(w)
        log.info(f"SOAR Orchestrator started ({self.max_parallel} workers)")

    async def stop(self):
        self._running = False
        for w in self._workers:
            w.cancel()
        self._workers.clear()

    async def _worker(self, worker_id: int):
        log.info(f"SOAR Worker {worker_id} started")
        while self._running:
            try:
                try:
                    priority, job_id = await asyncio.wait_for(
                        self._queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                try:
                    task = self._tasks.get(job_id)
                    if task:
                        await self._process(task, worker_id)
                finally:
                    self._queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Worker {worker_id} error: {e}")

    # ── Process one finding ───────────────────────────────────
    async def _process(self, task: FindingTask, worker_id: int):
        log.info(f"[W{worker_id}] Processing {task.finding_name} ({task.plugin_id})")

        # ── Phase 1: Enrich ──
        task.state = State.ENRICHING
        await self._emit("finding_update", {**task.to_dict(), "worker": worker_id,
                                             "message": "Selecting playbook..."})

        pb = get_playbook(task.plugin_id, task.service, task.port)
        task.playbook_name = pb["name"]

        # Get similar from memory
        mem_context = "No past findings."
        if not self._cb_mem.is_open:
            try:
                similar = mem.search_similar(
                    f"{task.finding_name} {task.plugin_id}", n_results=2
                )
                mem_context = mem.build_memory_context(similar)
                self._cb_mem.record_success()
            except Exception as e:
                self._cb_mem.record_failure()
                log.warning(f"Memory search failed: {e}")

        # ── Phase 2: AI Analysis ──
        task.state = State.ANALYZING
        await self._emit("finding_update", {**task.to_dict(), "worker": worker_id,
                                             "message": "Running AI analysis..."})

        result = {}
        if not self._cb_ai.is_open and ai.is_ollama_running():
            retries = 2
            for attempt in range(retries):
                try:
                    result = await asyncio.wait_for(
                        ai.analyze_output(
                            host=task.host,
                            finding_name=task.finding_name,
                            plugin_id=task.plugin_id,
                            severity=task.severity,
                            synopsis=task.synopsis,
                            plugin_output=task.plugin_output,
                            command="(auto-triage — no manual output)",
                            raw_output=task.plugin_output or f"Nessus detected: {task.finding_name}",
                            memory_context=mem_context
                        ),
                        timeout=60.0
                    )
                    self._cb_ai.record_success()
                    break
                except asyncio.TimeoutError:
                    log.warning(f"AI timeout attempt {attempt+1}/{retries}")
                    if attempt == retries - 1:
                        self._cb_ai.record_failure()
                except Exception as e:
                    self._cb_ai.record_failure()
                    log.error(f"AI error attempt {attempt+1}: {e}")
                    if attempt < retries - 1:
                        await asyncio.sleep(2 ** attempt)

        # ── Phase 3: Fallback scoring if AI failed ──
        if not result:
            result = self._rule_based_score(task, pb)

        # ── Update task ──
        task.confidence = result.get("confidence", 0)
        # Sanitize verdict — AI sometimes returns the template literally
        raw_verdict = result.get("verdict", "needs-more")
        task.verdict = raw_verdict if raw_verdict in ("confirmed", "fp", "needs-more") else "needs-more"
        # Sanitize indicators — AI may return dicts; ChromaDB requires strings
        raw_signals = result.get("indicators", [])
        task.signals = [
            s if isinstance(s, str) else str(s.get("description", s.get("title", str(s))))
            for s in raw_signals
        ]
        task.next_commands = result.get("next_commands", [])[:5]
        task.exploit_links = result.get("exploit_links", [])
        # Add playbook steps as suggested commands
        if not task.next_commands:
            task.next_commands = [
                {"tool": s["tool"], "command": s["cmd"].replace("{host}", task.host).replace("{port}", task.port or "?"),
                 "purpose": s["purpose"], "type": s.get("type", "recon")}
                for s in pb.get("steps", [])[:4]
            ]

        # ── Store in memory ──
        if task.confidence > 20 and not self._cb_mem.is_open:
            try:
                mem.store_finding(
                    host=task.host, finding_name=task.finding_name,
                    plugin_id=task.plugin_id, severity=task.severity,
                    command="auto-triage", raw_output=task.plugin_output[:300],
                    verdict=task.verdict, confidence=task.confidence,
                    summary=result.get("summary", "")[:300],
                    indicators=task.signals[:5]
                )
                self._cb_mem.record_success()
            except Exception as e:
                self._cb_mem.record_failure()

        task.state = State.DONE
        task.finished_at = datetime.utcnow().isoformat()

        await self._emit("finding_done", {
            **task.to_dict(),
            "worker": worker_id,
            "playbook": pb["name"],
            "remediation": pb.get("remediation", []),
            "message": f"{task.verdict.upper()} ({task.confidence}%)"
        })
        log.info(f"[W{worker_id}] Done: {task.finding_name} → {task.verdict} ({task.confidence}%)")

    def _rule_based_score(self, task: FindingTask, pb: dict) -> dict:
        """Fallback confidence scoring using playbook rules when AI unavailable."""
        confidence = 15  # base
        signals = ["Rule-based analysis (AI offline)"]
        po = (task.plugin_output or "").lower()

        # Port open → always some confidence
        if task.port and task.port != "0":
            confidence += 15
            signals.append(f"Service detected on port {task.port}")

        # Service keyword in output
        svc = (task.service or "").lower()
        if svc and svc in po:
            confidence += 20
            signals.append(f"Service '{svc}' confirmed in plugin output")

        # Version string detected
        if re.search(r"\d+\.\d+\.\d+", po):
            confidence += 15
            signals.append("Version string detected in output")

        # Severity boost
        sev_boost = {"critical": 20, "high": 15, "medium": 10, "low": 5, "info": 0}
        confidence += sev_boost.get(task.severity, 0)

        # CVEs known
        if task.cves:
            confidence += 10
            signals.append(f"CVEs referenced: {', '.join(task.cves[:2])}")

        confidence = min(confidence, 65)  # cap rule-based at 65%
        # >= 60 → confirmed, 25-59 → needs-more, < 25 → fp
        # (low confidence = insufficient evidence, not necessarily a false positive)
        verdict = "confirmed" if confidence >= 60 else "needs-more" if confidence >= 25 else "fp"

        return {
            "verdict": verdict,
            "confidence": confidence,
            "indicators": signals,
            "summary": f"Rule-based assessment: {task.finding_name} — {verdict}",
            "next_commands": [],
            "exploit_links": []
        }

    # ── Status API ────────────────────────────────────────────
    def get_status(self, job_id: str) -> dict | None:
        t = self._tasks.get(job_id)
        return t.to_dict() if t else None

    def get_all_statuses(self) -> list[dict]:
        return [t.to_dict() for t in self._tasks.values()]

    def get_summary(self) -> dict:
        tasks = list(self._tasks.values())
        verdicts = {"confirmed": 0, "fp": 0, "needs-more": 0}
        states = {}
        for t in tasks:
            verdicts[t.verdict] = verdicts.get(t.verdict, 0) + 1
            states[t.state.value] = states.get(t.state.value, 0) + 1
        # FIX BUG-02: Guard against _queue being None before start() is called
        return {
            "total": len(tasks),
            "verdicts": verdicts,
            "states": states,
            "queue_size": self._queue.qsize() if self._queue is not None else 0,
            "circuit_breaker_ai": "open" if self._cb_ai.is_open else "closed",
            "circuit_breaker_mem": "open" if self._cb_mem.is_open else "closed",
        }

    def clear(self):
        self._tasks.clear()
        # FIX B16: Guard against queue being None before start() is called
        if self._queue is None:
            return
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except Exception:
                break


# Singleton
orchestrator = SOAROrchestrator(max_parallel=3)
