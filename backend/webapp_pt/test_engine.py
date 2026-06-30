"""
PT Session Test Engine — Ollama RAG + ChromaDB for local AI-assisted testing.
ALL AI processing is local. Zero external API calls.
"""

import json
import logging
import hashlib
import time
from typing import Optional

log = logging.getLogger("aavapt.test_engine")

# ─────────────────────────────────────────────
# ChromaDB RAG Memory (local only)
# ─────────────────────────────────────────────

CHROMA_PATH = "./memory/chromadb"
CHROMA_COLLECTION = "webapp_pt_memory"

_chroma_client = None
_chroma_collection = None


def _get_chroma():
    """Lazy-init ChromaDB client. Returns (client, collection) or (None, None)."""
    global _chroma_client, _chroma_collection
    if _chroma_client is not None:
        return _chroma_client, _chroma_collection
    try:
        import chromadb
        from chromadb.config import Settings
        _chroma_client = chromadb.PersistentClient(
            path=CHROMA_PATH,
            settings=Settings(anonymized_telemetry=False)
        )
        _chroma_collection = _chroma_client.get_or_create_collection(
            name=CHROMA_COLLECTION,
            metadata={"description": "WebApp PT session memory — local only"}
        )
        log.info(f"ChromaDB initialized at {CHROMA_PATH}")
        return _chroma_client, _chroma_collection
    except ImportError:
        log.warning("ChromaDB not installed. Run: pip install chromadb --break-system-packages")
        return None, None
    except Exception as e:
        log.warning(f"ChromaDB init failed: {e}")
        return None, None


def store_finding(session_id: str, test_id: str, finding_text: str,
                  metadata: dict = None):
    """Store a finding/note in ChromaDB for RAG recall in future sessions."""
    _, col = _get_chroma()
    if col is None:
        return
    try:
        doc_id = hashlib.md5(f"{session_id}:{test_id}:{time.time()}".encode()).hexdigest()
        meta = {
            "session_id": session_id,
            "test_id": test_id,
            "timestamp": str(time.time()),
            **(metadata or {}),
        }
        # Chroma requires string values in metadata
        meta = {k: str(v) for k, v in meta.items()}
        col.add(documents=[finding_text], ids=[doc_id], metadatas=[meta])
        log.debug(f"Finding stored in ChromaDB: {doc_id}")
    except Exception as e:
        log.warning(f"ChromaDB store failed: {e}")


def recall_similar_findings(query: str, n_results: int = 5) -> list:
    """Retrieve similar past findings from ChromaDB."""
    _, col = _get_chroma()
    if col is None:
        return []
    try:
        results = col.query(query_texts=[query], n_results=n_results)
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        return [{"text": d, "meta": m} for d, m in zip(docs, metas)]
    except Exception as e:
        log.warning(f"ChromaDB recall failed: {e}")
        return []


def clear_session_memory(session_id: str):
    """Remove all ChromaDB entries for a specific session."""
    _, col = _get_chroma()
    if col is None:
        return
    try:
        results = col.get(where={"session_id": session_id})
        ids = results.get("ids", [])
        if ids:
            col.delete(ids=ids)
            log.info(f"Cleared {len(ids)} ChromaDB entries for session {session_id}")
    except Exception as e:
        log.warning(f"ChromaDB clear failed: {e}")


# ─────────────────────────────────────────────
# Ollama Integration (local only, DeepSeek-R1)
# ─────────────────────────────────────────────

# FIX BUG-04: Use config instead of hardcoded URL
from backend.config import OLLAMA_HOST
OLLAMA_BASE_URL = OLLAMA_HOST
DEFAULT_MODEL = "deepseek-r1:latest"


def _get_ollama_model() -> str:
    """Return configured Ollama model name."""
    return DEFAULT_MODEL


def generate_test_guidance(test: dict, crawl_result: dict,
                           similar_findings: list = None) -> str:
    """
    Ask local Ollama to generate specific testing guidance for the current WSTG test.
    FIX BUG-04: Uses config OLLAMA_HOST instead of hardcoded URL.
    FIX BUG-05: Routes through centralized ollama_client to avoid blocking the event loop.
    """
    try:
        # FIX BUG-05: Use centralized ollama_client.chat() instead of raw requests
        # This avoids blocking the async event loop and reuses caching/model-selection logic
        from backend.ai.ollama_client import chat as _ollama_chat, is_ollama_running
        import re as _re

        if not is_ollama_running():
            return "AI guidance unavailable — Ollama not running? Start: ollama serve"

        target_url = crawl_result.get("target_url", "TARGET")
        technologies = crawl_result.get("technologies", [])
        forms = crawl_result.get("forms", [])
        api_endpoints = crawl_result.get("api_endpoints", [])

        # Build RAG context
        rag_context = ""
        if similar_findings:
            rag_context = "\n\nRelevant past findings from memory:\n"
            for f in similar_findings[:3]:
                rag_context += f"- {f['text'][:200]}\n"

        prompt = (
            f"You are an expert web application penetration tester using OWASP WSTG methodology.\n\n"
            f"CURRENT TEST: {test.get('test_id')} — {test.get('name')}\n"
            f"SEVERITY: {test.get('severity', 'medium').upper()}\n"
            f"TARGET: {target_url}\n"
            f"TECH STACK: {', '.join(technologies) or 'Unknown'}\n"
            f"FORMS FOUND: {len(forms)} (fields: "
            f"{', '.join(f.get('fields',[{}])[0].get('name','') for f in forms[:3] if f.get('fields'))[:100]})\n"
            f"API ENDPOINTS: {', '.join(api_endpoints[:5]) or 'None detected'}\n"
            f"{rag_context}\n\n"
            f"Provide SPECIFIC, ACTIONABLE guidance for testing {test.get('name')} on this target.\n"
            f"Include:\n"
            f"1. Which specific endpoints/parameters to target (based on crawl data above)\n"
            f"2. Exact payloads to try (top 3 most likely to work)\n"
            f"3. What to look for in the response (success indicators)\n"
            f"4. Quick Burp Suite step (if applicable)\n"
            f"5. Risk: briefly explain impact if vulnerable\n\n"
            f"Keep response under 300 words. Be direct and specific to THIS application's tech stack."
        )

        system = "You are an expert web application penetration tester using OWASP WSTG methodology."
        guidance = _ollama_chat(prompt, system=system)
        guidance = _re.sub(r'<think>.*?</think>', '', guidance, flags=_re.DOTALL).strip()
        return guidance or "AI guidance not available. Use manual steps above."

    except Exception as e:
        log.warning(f"Ollama guidance failed: {e}")
        return "AI guidance unavailable — Ollama not running? Start: ollama serve"


def generate_finding_summary(finding: dict, target_url: str) -> str:
    """Generate a finding write-up using Ollama.
    FIX BUG-05: Uses centralized ollama_client.chat() — no blocking requests."""
    try:
        from backend.ai.ollama_client import chat as _ollama_chat, is_ollama_running
        import re as _re

        if not is_ollama_running():
            return f"{finding.get('name')} — {finding.get('notes', 'See evidence.')}"

        prompt = (
            f"Write a professional penetration test finding for this vulnerability:\n\n"
            f"VULNERABILITY: {finding.get('name')}\n"
            f"SEVERITY: {finding.get('severity', 'medium').upper()}\n"
            f"TARGET: {target_url}\n"
            f"CATEGORY: {finding.get('category')}\n"
            f"EVIDENCE: {finding.get('evidence', 'N/A')}\n"
            f"PAYLOAD USED: {finding.get('payload', 'N/A')}\n"
            f"TESTER NOTES: {finding.get('notes', 'N/A')}\n"
            f"OWASP: {', '.join(finding.get('owasp_top10', [])) or 'N/A'}\n\n"
            f"Write a concise finding report with:\n"
            f"- Description (2-3 sentences)\n"
            f"- Technical Details\n"
            f"- Risk Impact (1-2 sentences)\n"
            f"- Recommendation (2-3 bullet points)\n\n"
            f"Keep professional, clear, under 250 words."
        )
        system = "You are a senior penetration tester writing a professional security report."
        result = _ollama_chat(prompt, system=system)
        result = _re.sub(r'<think>.*?</think>', '', result, flags=_re.DOTALL).strip()
        return result or f"{finding.get('name')} — {finding.get('notes', 'See evidence.')}"
    except Exception as e:
        log.warning(f"Ollama finding summary failed: {e}")
    return f"{finding.get('name')} — {finding.get('notes', 'See evidence.')}"


def check_ollama_available() -> dict:
    """Check if Ollama is running and return available models.
    FIX BUG-05: Uses centralized ollama_client instead of raw requests."""
    from backend.ai.ollama_client import is_ollama_running, list_models, get_available_model
    try:
        if is_ollama_running():
            models = [m["id"] for m in list_models()]
            deepseek = any("deepseek" in m.lower() for m in models)
            return {
                "available": True,
                "models": models,
                "deepseek_ready": deepseek,
                "recommended_model": get_available_model(),
            }
    except Exception:
        pass
    return {
        "available": False,
        "models": [],
        "deepseek_ready": False,
        "error": f"Ollama not responding at {OLLAMA_BASE_URL}. Start with: ollama serve",
    }


# ─────────────────────────────────────────────
# Test Engine — main orchestration class
# ─────────────────────────────────────────────

class TestEngine:
    """
    Orchestrates the testing workflow:
    1. Start test → get AI guidance (Ollama + ChromaDB RAG)
    2. Tester runs manual/burp tests
    3. Tester submits result → engine stores finding in ChromaDB
    4. Move to next test
    """

    def __init__(self, session_id: str):
        self.session_id = session_id

    def get_guidance_for_test(self, test: dict, crawl_result: dict) -> str:
        """Get Ollama + RAG guidance for a test."""
        query = f"{test.get('name')} {test.get('category')} vulnerability testing"
        similar = recall_similar_findings(query, n_results=3)
        guidance = generate_test_guidance(test, crawl_result, similar)
        return guidance

    def on_finding(self, test: dict, result_notes: str, evidence: str,
                   payload: str, severity: str):
        """Called when tester marks a test as VULNERABLE — store in ChromaDB."""
        text = (
            f"VULNERABLE: {test.get('test_id')} — {test.get('name')}\n"
            f"Target: (session {self.session_id})\n"
            f"Notes: {result_notes}\n"
            f"Evidence: {evidence[:500]}\n"
            f"Payload: {payload[:200]}"
        )
        store_finding(
            session_id=self.session_id,
            test_id=test.get("test_id"),
            finding_text=text,
            metadata={
                "severity": severity,
                "category": test.get("category"),
                "vuln": "true",
            },
        )

    def get_enriched_test(self, test: dict, crawl_result: dict) -> dict:
        """Return test dict enriched with AI guidance + similar findings."""
        guidance = self.get_guidance_for_test(test, crawl_result)
        similar = recall_similar_findings(
            f"{test.get('name')} {test.get('category')}", n_results=3
        )
        return {
            **test,
            "ai_guidance": guidance,
            "similar_findings": similar,
        }
