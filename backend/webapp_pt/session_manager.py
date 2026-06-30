"""
WebApp PT Session Manager — state machine for penetration testing sessions.
States: CREATED → CRAWLING → CHECKLIST_READY → TESTING → COMPLETED / ABORTED
"""

import uuid
import json
import time
import logging
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

log = logging.getLogger("aavapt.session")


class SessionState(str, Enum):
    CREATED         = "CREATED"
    CRAWLING        = "CRAWLING"
    CHECKLIST_READY = "CHECKLIST_READY"
    TESTING         = "TESTING"
    COMPLETED       = "COMPLETED"
    ABORTED         = "ABORTED"


class TestResult(str, Enum):
    PENDING     = "PENDING"
    VULNERABLE  = "VULNERABLE"
    NOT_VULN    = "NOT_VULNERABLE"
    SKIPPED     = "SKIPPED"
    NEED_MANUAL = "NEED_MANUAL"


@dataclass
class TestEntry:
    test_id: str
    name: str
    category: str
    severity: str
    owasp_top10: list
    status: str = TestResult.PENDING
    result_notes: str = ""
    evidence: str = ""
    payload_used: str = ""
    burp_request: str = ""
    ai_guidance: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    h1_pattern_ids: list = field(default_factory=list)


@dataclass
class PTSession:
    session_id: str
    target_url: str
    state: str = SessionState.CREATED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # Permissions (all must be True before scanning)
    permissions: dict = field(default_factory=lambda: {
        "has_written_permission": False,
        "is_authorized_tester": False,
        "understands_scope": False,
        "agrees_not_to_exploit": False,
        "confirmed_target_url": "",
    })

    # Crawl data
    crawl_result: dict = field(default_factory=dict)
    crawl_started_at: float = 0.0
    crawl_completed_at: float = 0.0

    # Checklist
    checklist: list = field(default_factory=list)  # List[TestEntry as dict]
    current_test_index: int = 0
    total_tests: int = 0

    # Findings
    findings: list = field(default_factory=list)  # Vulnerable tests only

    # Metadata
    tester_name: str = ""
    notes: str = ""
    burp_mode: str = "MANUAL"  # PRO_AUTO | COMMUNITY | MANUAL
    burp_api_key: str = ""     # Not persisted to disk

    # Stats
    tests_completed: int = 0
    tests_vulnerable: int = 0
    tests_skipped: int = 0
    tests_not_vuln: int = 0

    def to_dict(self, include_sensitive: bool = False) -> dict:
        d = {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "permissions": {k: v for k, v in self.permissions.items() if k != "confirmed_target_url"},
            "crawl_completed": bool(self.crawl_result),
            "total_tests": self.total_tests,
            "current_test_index": self.current_test_index,
            "tests_completed": self.tests_completed,
            "tests_vulnerable": self.tests_vulnerable,
            "tests_skipped": self.tests_skipped,
            "tests_not_vuln": self.tests_not_vuln,
            "tester_name": self.tester_name,
            "burp_mode": self.burp_mode,
            "findings_count": len(self.findings),
            "progress_pct": round(self.current_test_index / max(self.total_tests, 1) * 100),
        }
        if include_sensitive:
            d["crawl_result"] = self.crawl_result
            d["checklist"] = self.checklist
            d["findings"] = self.findings
        return d

    def current_test(self) -> Optional[dict]:
        if 0 <= self.current_test_index < len(self.checklist):
            return self.checklist[self.current_test_index]
        return None

    def update_timestamp(self):
        self.updated_at = time.time()

    def permissions_granted(self) -> bool:
        p = self.permissions
        return (
            p.get("has_written_permission") and
            p.get("is_authorized_tester") and
            p.get("understands_scope") and
            p.get("agrees_not_to_exploit") and
            p.get("confirmed_target_url", "").strip() == self.target_url.strip()
        )


# ─────────────────────────────────────────────
# SESSION STORE (in-memory, no external DB)
# ─────────────────────────────────────────────

class SessionStore:
    """
    In-memory session store. Sessions are lost on server restart.
    Credentials are never written to disk.
    """

    def __init__(self):
        self._sessions: dict[str, PTSession] = {}

    def create(self, target_url: str, tester_name: str = "") -> PTSession:
        sid = str(uuid.uuid4())
        session = PTSession(
            session_id=sid,
            target_url=target_url,
            tester_name=tester_name,
        )
        self._sessions[sid] = session
        log.info(f"Session created: {sid} for {target_url}")
        return session

    def get(self, session_id: str) -> Optional[PTSession]:
        return self._sessions.get(session_id)

    def get_all(self) -> list[dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def delete(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            log.info(f"Session deleted: {session_id}")
            return True
        return False

    def update_state(self, session_id: str, new_state: SessionState) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.state = new_state
        s.update_timestamp()
        log.info(f"Session {session_id}: state → {new_state}")
        return True

    def set_permissions(self, session_id: str, permissions: dict) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.permissions.update(permissions)
        s.update_timestamp()
        return True

    def set_crawl_result(self, session_id: str, crawl_result: dict) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.crawl_result = crawl_result
        s.crawl_completed_at = time.time()
        s.update_timestamp()
        return True

    def set_checklist(self, session_id: str, tests: list) -> bool:
        """Load applicable WSTG tests into session checklist."""
        s = self.get(session_id)
        if not s:
            return False

        from .wstg_checklist import get_applicable_tests
        applicable = tests if tests else get_applicable_tests(s.crawl_result)

        checklist = []
        for t in applicable:
            checklist.append({
                "test_id": t["id"],
                "name": t["name"],
                "category": t["category"],
                "severity": t["severity"],
                "owasp_top10": t.get("owasp_top10", []),
                "status": TestResult.PENDING,
                "result_notes": "",
                "evidence": "",
                "payload_used": "",
                "burp_request": "",
                "ai_guidance": "",
                "started_at": 0.0,
                "completed_at": 0.0,
                "h1_pattern_ids": t.get("h1_pattern_ids", []),
                # Include full test data for UI rendering
                "manual_steps": t.get("manual_steps", []),
                "payloads": t.get("payloads", []),
                "expected_vulnerable": t.get("expected_vulnerable", ""),
                "expected_safe": t.get("expected_safe", ""),
                "remediation": t.get("remediation", ""),
                "burp_applicable": t.get("burp_applicable", False),
            })

        s.checklist = checklist
        s.total_tests = len(checklist)
        s.current_test_index = 0
        s.state = SessionState.CHECKLIST_READY
        s.update_timestamp()
        log.info(f"Session {session_id}: checklist loaded ({len(checklist)} tests)")
        return True

    def start_test(self, session_id: str) -> Optional[dict]:
        """Mark current test as started and return it."""
        s = self.get(session_id)
        if not s or s.current_test_index >= s.total_tests:
            return None
        s.state = SessionState.TESTING
        test = s.checklist[s.current_test_index]
        test["started_at"] = time.time()
        s.update_timestamp()
        return test

    def submit_result(self, session_id: str, result: str, notes: str = "",
                      evidence: str = "", payload: str = "", burp_req: str = "") -> dict:
        """Submit result for current test, advance to next."""
        s = self.get(session_id)
        if not s or s.current_test_index >= s.total_tests:
            return {"error": "No active test"}

        test = s.checklist[s.current_test_index]
        test["status"] = result
        test["result_notes"] = notes
        test["evidence"] = evidence
        test["payload_used"] = payload
        test["burp_request"] = burp_req
        test["completed_at"] = time.time()

        # Update stats
        s.tests_completed += 1
        if result == TestResult.VULNERABLE:
            s.tests_vulnerable += 1
            s.findings.append({
                "test_id": test["test_id"],
                "name": test["name"],
                "severity": test["severity"],
                "category": test["category"],
                "notes": notes,
                "evidence": evidence,
                "payload": payload,
                "remediation": test.get("remediation", ""),
                "owasp_top10": test.get("owasp_top10", []),
                "timestamp": time.time(),
            })
        elif result == TestResult.SKIPPED:
            s.tests_skipped += 1
        elif result == TestResult.NOT_VULN:
            s.tests_not_vuln += 1

        # Advance
        s.current_test_index += 1
        s.update_timestamp()

        # Check completion
        if s.current_test_index >= s.total_tests:
            s.state = SessionState.COMPLETED
            log.info(f"Session {session_id}: COMPLETED — {s.tests_vulnerable} findings")
            return {"completed": True, "session": s.to_dict(include_sensitive=False)}

        next_test = s.checklist[s.current_test_index]
        return {"completed": False, "next_test": next_test}

    def skip_test(self, session_id: str, reason: str = "Skipped by tester") -> dict:
        return self.submit_result(session_id, TestResult.SKIPPED, notes=reason)

    def set_ai_guidance(self, session_id: str, test_id: str, guidance: str) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        for test in s.checklist:
            if test["test_id"] == test_id:
                test["ai_guidance"] = guidance
                return True
        return False

    def abort(self, session_id: str) -> bool:
        return self.update_state(session_id, SessionState.ABORTED)


# ─────────────────────────────────────────────
# ENH-03: JSON-based session persistence
# Sessions survive server restart — no sensitive credentials are persisted.
# ─────────────────────────────────────────────

import json as _json
import os as _os

_PERSIST_DIR = _os.path.join(_os.path.dirname(__file__), "..", "..", "history", "sessions")
_PERSIST_FILE = _os.path.join(_PERSIST_DIR, "webapp_pt_sessions.json")


def _save_sessions(sessions: dict):
    """Persist sessions to disk (non-sensitive fields only)."""
    try:
        _os.makedirs(_PERSIST_DIR, exist_ok=True)
        data = {}
        for sid, s in sessions.items():
            d = s.to_dict(include_sensitive=True)
            # Strip sensitive fields before saving
            d.pop("burp_api_key", None)
            # Convert crawl_result keys — keep only metadata, not full HTML
            if "crawl_result" in d and isinstance(d["crawl_result"], dict):
                cr = d["crawl_result"]
                d["crawl_result"] = {
                    k: (v[:50] if isinstance(v, list) else v)
                    for k, v in cr.items()
                    if k not in ("raw_html_sample",)
                }
            data[sid] = d
        with open(_PERSIST_FILE, "w", encoding="utf-8") as f:
            _json.dump(data, f, default=str)
    except Exception as e:
        log.warning(f"Session persist save failed: {e}")


def _load_sessions() -> dict:
    """Load sessions from disk on startup."""
    try:
        if not _os.path.exists(_PERSIST_FILE):
            return {}
        with open(_PERSIST_FILE, encoding="utf-8") as f:
            data = _json.load(f)
        sessions = {}
        for sid, d in data.items():
            try:
                s = PTSession(
                    session_id=d["session_id"],
                    target_url=d.get("target_url", ""),
                    state=d.get("state", SessionState.CREATED),
                    tester_name=d.get("tester_name", ""),
                    burp_mode=d.get("burp_mode", "MANUAL"),
                )
                # Restore stats
                s.tests_completed  = d.get("tests_completed", 0)
                s.tests_vulnerable = d.get("tests_vulnerable", 0)
                s.tests_skipped    = d.get("tests_skipped", 0)
                s.tests_not_vuln   = d.get("tests_not_vuln", 0)
                s.total_tests      = d.get("total_tests", 0)
                s.current_test_index = d.get("current_test_index", 0)
                s.findings         = d.get("findings", [])
                s.checklist        = d.get("checklist", [])
                s.crawl_result     = d.get("crawl_result", {})
                sessions[sid] = s
            except Exception as e:
                log.warning(f"Could not restore session {sid}: {e}")
        log.info(f"Loaded {len(sessions)} persisted WebApp PT sessions")
        return sessions
    except Exception as e:
        log.warning(f"Session persist load failed: {e}")
        return {}


class SessionStore:
    """
    In-memory session store with JSON persistence (ENH-03).
    Credentials are never written to disk.
    """

    def __init__(self):
        self._sessions: dict[str, PTSession] = _load_sessions()

    def _persist(self):
        """Save sessions asynchronously — called after every mutation."""
        _save_sessions(self._sessions)

    def create(self, target_url: str, tester_name: str = "") -> PTSession:
        sid = str(uuid.uuid4())
        session = PTSession(
            session_id=sid,
            target_url=target_url,
            tester_name=tester_name,
        )
        self._sessions[sid] = session
        self._persist()
        log.info(f"Session created: {sid} for {target_url}")
        return session

    def get(self, session_id: str) -> Optional[PTSession]:
        return self._sessions.get(session_id)

    def get_all(self) -> list[dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def delete(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            self._persist()
            log.info(f"Session deleted: {session_id}")
            return True
        return False

    def update_state(self, session_id: str, new_state: SessionState) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.state = new_state
        s.update_timestamp()
        self._persist()
        log.info(f"Session {session_id}: state → {new_state}")
        return True

    def set_permissions(self, session_id: str, permissions: dict) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.permissions.update(permissions)
        s.update_timestamp()
        self._persist()
        return True

    def set_crawl_result(self, session_id: str, crawl_result: dict) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        s.crawl_result = crawl_result
        s.crawl_completed_at = time.time()
        s.update_timestamp()
        self._persist()
        return True

    def set_checklist(self, session_id: str, tests: list) -> bool:
        """Load applicable WSTG tests into session checklist."""
        s = self.get(session_id)
        if not s:
            return False

        from .wstg_checklist import get_applicable_tests
        applicable = tests if tests else get_applicable_tests(s.crawl_result)

        checklist = []
        for t in applicable:
            checklist.append({
                "test_id": t["id"],
                "name": t["name"],
                "category": t["category"],
                "severity": t["severity"],
                "owasp_top10": t.get("owasp_top10", []),
                "status": TestResult.PENDING,
                "result_notes": "",
                "evidence": "",
                "payload_used": "",
                "burp_request": "",
                "ai_guidance": "",
                "started_at": 0.0,
                "completed_at": 0.0,
                "h1_pattern_ids": t.get("h1_pattern_ids", []),
                # Include full test data for UI rendering
                "manual_steps": t.get("manual_steps", []),
                "payloads": t.get("payloads", []),
                "expected_vulnerable": t.get("expected_vulnerable", ""),
                "expected_safe": t.get("expected_safe", ""),
                "remediation": t.get("remediation", ""),
                "burp_applicable": t.get("burp_applicable", False),
            })

        s.checklist = checklist
        s.total_tests = len(checklist)
        s.current_test_index = 0
        s.state = SessionState.CHECKLIST_READY
        s.update_timestamp()
        self._persist()
        log.info(f"Session {session_id}: checklist loaded ({len(checklist)} tests)")
        return True

    def start_test(self, session_id: str) -> Optional[dict]:
        """Mark current test as started and return it."""
        s = self.get(session_id)
        if not s or s.current_test_index >= s.total_tests:
            return None
        s.state = SessionState.TESTING
        test = s.checklist[s.current_test_index]
        test["started_at"] = time.time()
        s.update_timestamp()
        return test

    def submit_result(self, session_id: str, result: str, notes: str = "",
                      evidence: str = "", payload: str = "", burp_req: str = "") -> dict:
        """Submit result for current test, advance to next."""
        s = self.get(session_id)
        if not s or s.current_test_index >= s.total_tests:
            return {"error": "No active test"}

        test = s.checklist[s.current_test_index]
        test["status"] = result
        test["result_notes"] = notes
        test["evidence"] = evidence
        test["payload_used"] = payload
        test["burp_request"] = burp_req
        test["completed_at"] = time.time()

        # Update stats
        s.tests_completed += 1
        if result == TestResult.VULNERABLE:
            s.tests_vulnerable += 1
            s.findings.append({
                "test_id": test["test_id"],
                "name": test["name"],
                "severity": test["severity"],
                "category": test["category"],
                "notes": notes,
                "evidence": evidence,
                "payload": payload,
                "remediation": test.get("remediation", ""),
                "owasp_top10": test.get("owasp_top10", []),
                "timestamp": time.time(),
            })
        elif result == TestResult.SKIPPED:
            s.tests_skipped += 1
        elif result == TestResult.NOT_VULN:
            s.tests_not_vuln += 1

        # Advance
        s.current_test_index += 1
        s.update_timestamp()
        self._persist()

        # Check completion
        if s.current_test_index >= s.total_tests:
            s.state = SessionState.COMPLETED
            log.info(f"Session {session_id}: COMPLETED — {s.tests_vulnerable} findings")
            return {"completed": True, "session": s.to_dict(include_sensitive=False)}

        next_test = s.checklist[s.current_test_index]
        return {"completed": False, "next_test": next_test}

    def skip_test(self, session_id: str, reason: str = "Skipped by tester") -> dict:
        return self.submit_result(session_id, TestResult.SKIPPED, notes=reason)

    def set_ai_guidance(self, session_id: str, test_id: str, guidance: str) -> bool:
        s = self.get(session_id)
        if not s:
            return False
        for test in s.checklist:
            if test["test_id"] == test_id:
                test["ai_guidance"] = guidance
                return True
        return False

    def abort(self, session_id: str) -> bool:
        return self.update_state(session_id, SessionState.ABORTED)


# Global singleton
_store: Optional[SessionStore] = None


def get_store() -> SessionStore:
    global _store
    if _store is None:
        _store = SessionStore()
    return _store
