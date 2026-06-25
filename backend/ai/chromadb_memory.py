from __future__ import annotations
"""ChromaDB vector memory — stores & retrieves past vulnerability analyses."""
import json, logging, uuid, os, threading, hashlib
from datetime import datetime
import chromadb
from chromadb.utils import embedding_functions
from backend.config import CHROMA_PERSIST_DIR, CHROMA_COLLECTION

log = logging.getLogger("aavapt.ai.chromadb")

os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)

_client: chromadb.ClientAPI | None = None
_collection = None
# FIX B14: Thread lock to prevent race condition on concurrent init
_init_lock = threading.Lock()


def _get_ef():
    """Sentence-transformer embedding function (local, no API key)."""
    try:
        return embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
    except Exception:
        return embedding_functions.DefaultEmbeddingFunction()


def get_collection():
    global _client, _collection
    # FIX B14: Double-checked locking pattern — safe for concurrent callers
    if _collection is not None:
        return _collection
    with _init_lock:
        if _collection is not None:
            return _collection
        try:
            _client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
            _collection = _client.get_or_create_collection(
                name=CHROMA_COLLECTION,
                embedding_function=_get_ef(),
                metadata={"hnsw:space": "cosine"}
            )
            log.info(f"ChromaDB ready: {_collection.count()} existing records")
            return _collection
        except Exception as e:
            log.error(f"ChromaDB init error: {e}")
            return None


def is_ready() -> bool:
    return get_collection() is not None


# ── Store a finding analysis ───────────────────────────────────
def store_finding(
    host: str,
    finding_name: str,
    plugin_id: str,
    severity: str,
    command: str,
    raw_output: str,
    verdict: str,
    confidence: int,
    summary: str,
    indicators: list[str]
) -> str | None:
    col = get_collection()
    if col is None:
        return None
    try:
        doc_id = str(uuid.uuid4())
        document = f"{finding_name} {plugin_id} {severity} {summary} {' '.join(indicators)}"
        metadata = {
            "host": host,
            "finding_name": finding_name,
            "plugin_id": plugin_id,
            "severity": severity,
            "verdict": verdict,
            "confidence": confidence,
            "command": command[:500],
            "summary": summary[:500],
            "indicators": json.dumps(indicators[:10]),
            "timestamp": datetime.utcnow().isoformat(),
            "raw_output_preview": raw_output[:300]
        }
        col.add(documents=[document], metadatas=[metadata], ids=[doc_id])
        log.info(f"Stored finding: {finding_name} [{verdict}] id={doc_id}")
        return doc_id
    except Exception as e:
        log.error(f"store_finding error: {e}")
        return None


# ── Search similar findings ────────────────────────────────────
def search_similar(query: str, n_results: int = 3) -> list[dict]:
    col = get_collection()
    if col is None or col.count() == 0:
        return []
    try:
        n = min(n_results, col.count())
        results = col.query(query_texts=[query], n_results=n)
        out = []
        for i, meta in enumerate(results["metadatas"][0]):
            out.append({
                "finding_name": meta.get("finding_name"),
                "plugin_id": meta.get("plugin_id"),
                "verdict": meta.get("verdict"),
                "confidence": meta.get("confidence"),
                "summary": meta.get("summary"),
                "indicators": json.loads(meta.get("indicators", "[]")),
                "timestamp": meta.get("timestamp"),
                "host": meta.get("host"),
                "distance": results["distances"][0][i] if results.get("distances") else None
            })
        return out
    except Exception as e:
        log.error(f"search_similar error: {e}")
        return []


# ── Bulk-index a loaded scan's findings (RAG corpus) ───────────
# Idempotent: deterministic IDs (host:plugin:port:name) so re-syncing the same
# scan upserts instead of duplicating. Lets the whole app (chat, similar-search,
# MCP) retrieve from the current scan even before any verdict is set.
def index_findings(findings: list[dict]) -> int:
    col = get_collection()
    if col is None or not findings:
        return 0
    ids, docs, metas = [], [], []
    for f in findings:
        try:
            hosts = f.get("hosts") or []
            host = hosts[0] if isinstance(hosts, list) and hosts else str(f.get("host", f.get("ip", "")) or "")
            pid = str(f.get("plugin_id", f.get("pluginId", "")) or "")
            name = str(f.get("name", f.get("pluginName", "")) or "")
            port = str(f.get("port", "") or "")
            sev = str(f.get("severity", "info") or "info").lower()
            cves = f.get("cves") or []
            if isinstance(cves, str):
                cves = [cves]
            syn = str(f.get("synopsis", "") or "")
            out = str(f.get("plugin_output", f.get("pluginOutput", "")) or "")
            if not (name or pid):
                continue
            key = f"scan|{host}|{pid}|{port}|{name}"
            did = "scan_" + hashlib.md5(key.encode("utf-8", "ignore")).hexdigest()[:20]
            ids.append(did)
            docs.append(" ".join([name, pid, sev, syn, " ".join(cves)]).strip())
            metas.append({
                "kind": "scan_finding",
                "host": host, "finding_name": name, "plugin_id": pid,
                "port": port, "severity": sev,
                "verdict": "needs-more", "confidence": 0,
                "summary": syn[:500], "indicators": json.dumps(cves[:10]),
                "timestamp": datetime.utcnow().isoformat(),
                "raw_output_preview": out[:300],
            })
        except Exception as e:
            log.warning(f"index_findings skip one: {e}")
            continue
    if not ids:
        return 0
    try:
        col.upsert(documents=docs, metadatas=metas, ids=ids)
        log.info(f"Indexed {len(ids)} scan findings into RAG memory")
        return len(ids)
    except Exception as e:
        log.error(f"index_findings error: {e}")
        return 0


# ── Cross-scan knowledge: "have we VERIFIED this before?" ──────
def lookup_findings(findings: list, max_dist: float = 0.6) -> list:
    """For each finding, return the best PAST VERIFIED (confirmed/fp) match from
    memory across all previous scans/engagements. Powers the 'seen before' view."""
    col = get_collection()
    if col is None or col.count() == 0 or not findings:
        return []
    out = []
    seen_keys = set()
    for f in findings:
        name = str(f.get("name", f.get("pluginName", "")) or "")
        pid = str(f.get("plugin_id", f.get("pluginId", "")) or "")
        q = (name + " " + pid).strip()
        if not q:
            continue
        key = name + "|" + pid
        if key in seen_keys:
            continue
        seen_keys.add(key)
        try:
            sim = search_similar(q, n_results=4)
        except Exception:
            continue
        verified = [s for s in sim
                    if s.get("verdict") in ("confirmed", "fp")
                    and (s.get("distance") is None or s.get("distance") <= max_dist)]
        if verified:
            best = verified[0]
            out.append({
                "finding": name, "plugin_id": pid,
                "verdict": best.get("verdict"),
                "confidence": best.get("confidence"),
                "host": best.get("host"),
                "timestamp": best.get("timestamp"),
                "summary": best.get("summary"),
                "distance": round(best.get("distance"), 3) if best.get("distance") is not None else None,
            })
    return out


def build_memory_context(similar: list[dict]) -> str:
    """Format similar findings as context string for AI prompt."""
    if not similar:
        return "No similar past findings in memory."
    lines = []
    for s in similar:
        verdict = (s.get("verdict") or "unknown").upper()
        lines.append(
            f"- [{verdict} {s['confidence']}%] {s['finding_name']} "
            f"(Plugin {s['plugin_id']}): {s['summary']}"
        )
    return "Similar past analyses:\n" + "\n".join(lines)


# ── Stats ──────────────────────────────────────────────────────
def get_stats() -> dict:
    col = get_collection()
    if col is None:
        return {"total": 0, "ready": False}
    try:
        total = col.count()
        verdicts = {"confirmed": 0, "fp": 0, "needs-more": 0}
        if total > 0:
            all_meta = col.get(include=["metadatas"])["metadatas"]
            for m in all_meta:
                v = m.get("verdict", "needs-more")
                verdicts[v] = verdicts.get(v, 0) + 1
        return {"total": total, "ready": True, "verdicts": verdicts,
                "persist_dir": CHROMA_PERSIST_DIR}
    except Exception as e:
        return {"total": 0, "ready": False, "error": str(e)}


# ── Delete all ─────────────────────────────────────────────────
def clear_memory() -> bool:
    global _collection, _client
    get_collection()  # ensure _client is initialised before we try to delete/recreate
    # FIX B15: Lock during clear, handle delete errors properly
    with _init_lock:
        if _client is None:
            return False
        try:
            if _client:
                try:
                    _client.delete_collection(CHROMA_COLLECTION)
                except Exception as del_err:
                    log.warning(f"delete_collection warning: {del_err}")
            _collection = None
            # Re-create fresh collection
            _collection = _client.get_or_create_collection(
                name=CHROMA_COLLECTION,
                embedding_function=_get_ef(),
                metadata={"hnsw:space": "cosine"}
            )
            log.info("Memory cleared and re-initialised")
            return True
        except Exception as e:
            log.error(f"clear_memory error: {e}")
            _collection = None  # force re-init on next call
            return False
