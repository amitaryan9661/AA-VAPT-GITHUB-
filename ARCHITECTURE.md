# AA-VAPT — Complete Project Architecture & Function Reference
> Version 2.1.0 | Last updated: 2026-06-29  
> Is ek file se poora project samjha ja sakta hai — har module, har function, data flow, aur deployment steps.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Directory Structure](#2-directory-structure)
3. [System Architecture Diagram](#3-system-architecture-diagram)
4. [Data Flow](#4-data-flow)
5. [Module Reference — Backend Core](#5-module-reference--backend-core)
6. [Module Reference — AI Subsystem](#6-module-reference--ai-subsystem)
7. [Module Reference — SOAR Orchestrator](#7-module-reference--soar-orchestrator)
8. [Module Reference — WebApp PT](#8-module-reference--webapp-pt)
9. [Module Reference — Terminal (Kali Linux)](#9-module-reference--terminal-kali-linux)
10. [API Endpoint Reference](#10-api-endpoint-reference)
11. [WebSocket Events](#11-websocket-events)
12. [Authentication & Rate Limiting](#12-authentication--rate-limiting)
13. [MCP Server](#13-mcp-server)
14. [Database & Persistence](#14-database--persistence)
15. [Environment Variables](#15-environment-variables)
16. [Deployment Guide](#16-deployment-guide)
17. [Testing](#17-testing)
18. [Bug Fixes Applied (v2.1.0)](#18-bug-fixes-applied-v210)
19. [Enhancements Implemented (v2.1.0)](#19-enhancements-implemented-v210)

---

## 1. Project Overview

AA-VAPT is a **Vulnerability Assessment & Penetration Testing (VAPT) platform** built for security professionals. It processes Nessus `.nessus` XML scan files and provides:

- **AI analysis** of each finding via a local Ollama LLM (DeepSeek-R1, Gemma3, Llama3)
- **RAG memory** via ChromaDB — learns from past verified verdicts so future scans are smarter
- **Attack chain detection** — combines individual findings into multi-step attack paths (LLMNR → SMB Relay → Admin, Kerberoasting, etc.)
- **SOAR triage** — async priority queue that auto-analyses every finding in parallel
- **WebApp Penetration Testing** module — Playwright crawler + WSTG checklist + Burp Suite integration
- **Live exploit intelligence** — EPSS probability + CISA KEV live data per CVE
- **ML false-positive filter** — RandomForest classifier trained on your own verdicts
- **Knowledge graph** — graphifyy 71.5x token reduction for AI context
- **Interactive terminal** — real Kali Linux shell in the browser (local PTY or SSH)
- **MCP server** — exposes tools to Claude / AI agents via Model Context Protocol

**Stack:** FastAPI + asyncio backend, xterm.js + vanilla JS frontend, Ollama local LLM, ChromaDB vector DB, Playwright browser automation, scikit-learn ML.

**No cloud required.** Everything runs on localhost. Zero data leaves your machine.

---

## 2. Directory Structure

```
AA-AGENT-V3-CHAINS/
├── backend/                    # All Python backend code
│   ├── main.py                 # FastAPI app, all HTTP + WebSocket routes (1300+ lines)
│   ├── config.py               # Central config — ports, paths, model names
│   ├── auth.py                 # API key authentication (ENH-01)
│   ├── ws_manager.py           # WebSocket connection manager
│   ├── findings_store.py       # In-memory findings store + search + pagination
│   ├── findings_parser.py      # Nessus XML parser → normalized finding dicts
│   ├── script_generator.py     # Auto-generate SSL/SSH/server-version bash scripts
│   ├── mcp_server.py           # MCP (Model Context Protocol) FastAPI router
│   ├── graphify_integration.py # graphifyy knowledge graph wrapper
│   ├── terminal_pty.py         # Kali Linux PTY terminal over WebSocket
│   ├── attack_chain_engine.py  # Multi-step attack chain detection engine
│   ├── requirements.txt        # Python dependencies
│   │
│   ├── ai/                     # AI subsystem
│   │   ├── ollama_client.py    # Ollama LLM client — analyze, chat, commands, summary
│   │   ├── chromadb_memory.py  # ChromaDB RAG memory — store, search, index, stats
│   │   ├── ml_engine.py        # scikit-learn FP classifier + KMeans clustering
│   │   └── exploit_intel.py    # EPSS + CISA KEV live exploit intelligence
│   │
│   ├── soar/                   # SOAR Orchestrator
│   │   ├── orchestrator.py     # Async priority queue task processor + circuit breaker
│   │   └── playbooks.py        # SOAR playbook definitions
│   │
│   └── webapp_pt/              # WebApp Penetration Testing module
│       ├── session_manager.py  # PT session lifecycle + JSON persistence
│       ├── crawler.py          # Playwright async web crawler
│       ├── test_engine.py      # WSTG test guidance generator
│       ├── burp_integration.py # Burp Suite Pro/Community/Manual integration
│       ├── wstg_checklist.py   # OWASP WSTG test definitions
│       ├── report_generator.py # HTML / JSON / Markdown report builder
│       └── tool_runner.py      # Run real pentest tools (nmap, nikto, etc.)
│
├── frontend/                   # HTML/CSS/JS frontend (served separately)
│   ├── index.html              # Main Nessus analyzer UI
│   ├── webapp-pt.html          # WebApp PT module UI
│   └── terminal.html           # Kali Linux terminal UI (xterm.js)
│
├── history/                    # Persisted scan history JSON files (runtime created)
│   └── sessions/
│       └── webapp_pt_sessions.json   # PT sessions persistence
│
├── tests/                      # Unit tests
│   └── test_chain_engine.py    # Attack chain engine tests (pytest)
│
├── PROJECT_REVIEW.md           # Full bug & enhancement review report
└── ARCHITECTURE.md             # This file
```

---

## 3. System Architecture Diagram

```
Browser (xterm.js / JS UI)
        │
        │  HTTP REST + WebSocket
        ▼
┌─────────────────────────────────────────────────────────┐
│               FastAPI Application (main.py)             │
│                                                         │
│  /api/analyze      /api/soar/*    /api/chains/*         │
│  /api/memory/*     /api/ml/*      /api/intel/*          │
│  /api/webapp-pt/*  /api/burp/*    /api/graphify/*       │
│  /api/findings/*   /api/history/* /api/ask              │
│  /ws  (events)     /ws/terminal   /mcp  (MCP server)    │
│                                                         │
│  ┌─────────────┐  ┌────────────┐  ┌────────────────┐   │
│  │ Auth Layer  │  │Rate Limiter│  │ CORS Middleware │   │
│  │ (auth.py)   │  │ (slowapi)  │  │                │   │
│  └─────────────┘  └────────────┘  └────────────────┘   │
└───────────┬─────────────────────────────────────────────┘
            │
    ┌───────┴──────────────────────────────────┐
    │                                          │
    ▼                                          ▼
┌──────────────────┐                  ┌─────────────────┐
│   AI Subsystem   │                  │  SOAR Subsystem │
│                  │                  │                 │
│ ollama_client.py │                  │ orchestrator.py │
│  → analyze_output│                  │  → PriorityQueue│
│  → chat_finding  │                  │  → CircuitBreaker│
│  → suggest_cmds  │                  │  → playbooks.py │
│                  │                  └─────────────────┘
│ chromadb_memory  │
│  → store_finding │
│  → search_similar│         ┌──────────────────────────┐
│  → index_findings│         │  WebApp PT Subsystem     │
│                  │         │                          │
│ ml_engine.py     │         │ session_manager.py       │
│  → train_fp      │         │ crawler.py (Playwright)  │
│  → predict_fp    │         │ test_engine.py (WSTG)    │
│  → cluster       │         │ burp_integration.py      │
│  → risk_rank     │         │ tool_runner.py           │
│                  │         └──────────────────────────┘
│ exploit_intel.py │
│  → EPSS API      │         ┌──────────────────────────┐
│  → CISA KEV      │         │  Terminal Subsystem      │
└──────────────────┘         │                          │
                             │ terminal_pty.py          │
┌──────────────────┐         │  Mode 1: Local PTY       │
│  Attack Chain    │         │   (pty.fork → /bin/zsh)  │
│  Engine          │         │  Mode 2: SSH → Kali      │
│                  │         │   (paramiko SSH)         │
│ detect_chains()  │         └──────────────────────────┘
│ run_chain_det()  │
│ generate_poc()   │
│ CHAIN_RULES      │
└──────────────────┘

External Services (all optional, all local):
  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐
  │ Ollama (local)  │  │ ChromaDB (local) │  │ Burp Suite     │
  │ localhost:11434 │  │ sentence-transf. │  │ localhost:1337 │
  └─────────────────┘  └──────────────────┘  └────────────────┘
  ┌─────────────────┐  ┌──────────────────┐
  │ EPSS API        │  │ CISA KEV         │
  │ (api.first.org) │  │ (cisa.gov JSON)  │
  └─────────────────┘  └──────────────────┘
```

---

## 4. Data Flow

### 4a. Nessus Scan Analysis Flow
```
User uploads .nessus file
    → frontend parsesNessus() → findings array
    → POST /api/findings/sync → findings_store.set_findings()
                              → mem.index_findings() [background]
    → POST /api/analyze (per finding)
        → mem.search_similar() [RAG context]
        → ai.analyze_output() [Ollama LLM]
        → mem.store_finding() [if confidence > 70]
        → ws_manager.broadcast("memory_updated")
        → returns verdict/summary/indicators/confidence
```

### 4b. SOAR Triage Flow
```
POST /api/soar/triage (all findings at once)
    → orchestrator.submit() → PriorityQueue (severity order)
    → orchestrator._process() [async loop]
        → _rule_based_score() [offline scoring always]
        → circuit_breaker → ai.analyze_output() [if Ollama up]
        → mem.store_finding() [confirmed verdicts]
        → ws_manager.broadcast("soar_result") [per finding]
    → GET /api/soar/results → all job statuses
```

### 4c. Attack Chain Detection Flow
```
POST /api/chains/detect
    → findings_store.get_all() [or from request]
    → detect_chains(findings)
        → for each CHAIN_RULE:
            → _condition_matches() per required condition
            → _collect_hosts() from matching findings
            → if all conditions met → chain detected
    → run_chain_detection() [async wrapper]
        → ai.chat_finding() [LLM narrative, if Ollama up]
    → generate_poc_script() [bash PoC per chain]
    → returns sorted chains (CRITICAL first)
```

### 4d. WebApp PT Flow
```
POST /api/webapp-pt/start-session
    → SessionStore.create() → PTSession (uuid)
    → persisted to webapp_pt_sessions.json

POST /api/webapp-pt/{id}/request-permission
    → validate_scan_permission() [legal gate]
    → store.set_permissions()

POST /api/webapp-pt/{id}/crawl
    → WebAppCrawler.crawl_authenticated/unauthenticated()
        → Playwright (Chromium/Firefox/WebKit)
        → _crawl() [BFS page discovery]
        → _auto_login() [form detection + submit]
        → _extract_links() [page.evaluate with safe arg passing]
        → _scan_js_secrets() [regex on JS files]
        → requests fallback if Playwright unavailable
    → store.set_crawl_result()
    → ws_manager.broadcast("webapp_crawl_complete")

GET /api/webapp-pt/{id}/next-test
    → wstg_checklist.get_applicable_tests()
    → TestEngine.get_enriched_test()
        → ollama_client.chat() [test guidance]
    → returns WSTG test + AI guidance

POST /api/webapp-pt/{id}/submit-result
    → store.submit_result()
    → on VULNERABLE: TestEngine.on_finding()
    → persisted to webapp_pt_sessions.json
```

---

## 5. Module Reference — Backend Core

### `backend/main.py` — FastAPI Application
**Purpose:** Central FastAPI app. All HTTP routes, WebSocket endpoints, lifespan management.

| Function/Class | Description |
|---|---|
| `lifespan(app)` | Async context manager. On startup: initializes ChromaDB, checks Ollama, starts SOAR orchestrator. On shutdown: stops orchestrator cleanly. |
| `websocket_endpoint(ws)` | `/ws` — General event WebSocket. Handles `ping` → `pong`. Broadcasts SOAR results, memory updates, model changes. |
| `websocket_terminal(ws)` | `/ws/terminal` — Delegates to `terminal_pty.terminal_session()`. Full Kali Linux shell over WebSocket. |
| `status()` | `GET /api/status` — System health: Ollama status, ChromaDB stats, SOAR summary, WS clients, auth status, rate limiting. |
| `analyze()` | `POST /api/analyze` — Core AI analysis. Auth required. Searches RAG memory for context, calls Ollama, stores high-confidence results. |
| `chat()` | `POST /api/chat` — Contextual Q&A about a specific finding. No auth required. |
| `suggest_commands()` | `POST /api/commands` — AI-generated pentest commands for a finding. |
| `executive_summary()` | `POST /api/summary` — LLM executive summary of all findings. |
| `soar_triage()` | `POST /api/soar/triage` — Auth required. Max 500 findings. Submits all to SOAR priority queue. |
| `soar_status()` | `GET /api/soar/status` — Queue size, processed count, circuit breaker state. |
| `soar_results()` | `GET /api/soar/results` — All job statuses with verdicts. |
| `soar_result(job_id)` | `GET /api/soar/result/{job_id}` — Single job status. |
| `list_playbooks()` | `GET /api/soar/playbooks` — Available SOAR playbook definitions. |
| `get_models()` | `GET /api/models` — Available Ollama models + active model. |
| `select_model()` | `POST /api/models/select` — Switch active LLM. Broadcasts model change event. |
| `memory_search()` | `POST /api/memory/search` — Semantic search in ChromaDB. |
| `memory_stats()` | `GET /api/memory/stats` — ChromaDB collection size, verdict counts. |
| `memory_clear()` | `DELETE /api/memory` — Wipe ChromaDB collection. |
| `memory_feedback()` | `POST /api/memory/feedback` — Store user correction (correct=false → FP flag, confidence=10). |
| `memory_lookup()` | `POST /api/memory/lookup` — Cross-scan RAG: find past matches for current findings. |
| `memory_store_verdict()` | `POST /api/memory/store-verdict` — Manually persist a verdict into ChromaDB. |
| `history_save()` | `POST /api/history/save` — Save scan to JSON file in `history/`. 12-char UUID prefix. |
| `history_list()` | `GET /api/history/list` — List all saved scans (metadata only). |
| `history_load(hid)` | `GET /api/history/load/{hid}` — Load full scan data. Input validated (alphanumeric only). |
| `history_delete(hid)` | `DELETE /api/history/{hid}` — Delete a saved scan file. Input validated. |
| `generate_scripts()` | `POST /api/generate-scripts` — Auto-generate SSL/SSH/server-version verification bash scripts. |
| `findings_sync()` | `POST /api/findings/sync` — Push frontend scan data into findings_store. Triggers RAG indexing. |
| `findings_search()` | `GET /api/findings/search` — Keyword/IP/CVE/port search across loaded scan. |
| `findings_page()` | `GET /api/findings/page` — Paginated findings access (page, per_page params). |
| `ask()` | `POST /api/ask` — Global chatbot. Keyword-matches findings + RAG memory + Ollama answer. |
| `ml_status()` | `GET /api/ml/status` — Is FP model trained, on how many samples. |
| `ml_train_fp()` | `POST /api/ml/train-fp` — Train RandomForest on confirmed/FP-labelled findings. |
| `ml_predict_fp()` | `POST /api/ml/predict-fp` — Predict false-positive probability for all findings. |
| `ml_cluster()` | `POST /api/ml/cluster` — KMeans cluster similar findings to spot patterns. |
| `ml_risk_rank()` | `POST /api/ml/risk-rank` — Score 0-100 "fix this first" priority per finding. |
| `ml_remediation()` | `POST /api/ml/remediation` — AI remediation steps for one finding. Offline fallback. |
| `intel_enrich()` | `POST /api/intel/enrich` — Live EPSS + CISA KEV data for given CVE list. |
| `intel_status()` | `GET /api/intel/status` — KEV catalog size + EPSS cache size. |
| `graphify_status()` | `GET /api/graphify/status` — graphifyy installed? Available graphs? |
| `graphify_build()` | `POST /api/graphify/build` — Build knowledge graph from findings. |
| `graphify_query()` | `POST /api/graphify/query` — Natural language query against graph. |
| `graphify_explain()` | `POST /api/graphify/explain` — Explain a specific node (CVE/host/plugin). |
| `graphify_list()` | `GET /api/graphify/list` — List built graphs. |
| `chains_detect()` | `POST /api/chains/detect` — Run attack chain detection on loaded findings. |
| `chains_rules()` | `GET /api/chains/rules` — List all chain rules with conditions and MITRE IDs. |
| `chains_poc()` | `POST /api/chains/poc` — Generate/re-generate PoC bash script for a chain. |

---

### `backend/config.py` — Central Configuration
**Purpose:** Single source of truth for all configurable values.

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `deepseek-r1:8b` | Default LLM model |
| `API_HOST` | `0.0.0.0` | FastAPI bind address |
| `API_PORT` | `8000` | Backend port |
| `FRONTEND_PORT` | `8181` | Frontend dev server port (CORS allowlist) |
| `CHROMA_HOST` | `localhost` | ChromaDB host |
| `CHROMA_PORT` | `8001` | ChromaDB port |
| `CHROMA_COLLECTION` | `vapt_memory` | ChromaDB collection name |

---

### `backend/auth.py` — API Key Authentication
**Purpose:** Optional API key guard on sensitive endpoints. Backward-compatible: if `AAVAPT_API_KEY` env var not set, auth is disabled (dev mode).

| Symbol | Description |
|---|---|
| `_API_KEY` | Read from `AAVAPT_API_KEY` env var. Empty = auth disabled. |
| `_AUTH_ENABLED` | `bool(_API_KEY)` |
| `_key_header` | `APIKeyHeader(name="X-API-Key")` — reads from HTTP header |
| `_key_query` | `APIKeyQuery(name="api_key")` — reads from query string |
| `require_auth(header_key, query_key)` | FastAPI `Depends()` dependency. Raises 401 if auth enabled and key invalid. No-op if auth disabled. |
| `auth_status() → dict` | Returns `{"enabled": bool, "note": str}` for `/api/status`. Never exposes the actual key. |

**Usage:** `@app.post("/api/analyze") async def analyze(req, _auth=Depends(require_auth))`

---

### `backend/ws_manager.py` — WebSocket Manager
**Purpose:** Manages all connected WebSocket clients. Thread-safe broadcast.

| Symbol | Description |
|---|---|
| `WSManager` | Singleton class managing connected WebSocket set. |
| `WSManager.connect(ws)` | Add client. Rejects with code 1008 if `> MAX_WS_CONNECTIONS` (50). |
| `WSManager.disconnect(ws)` | Remove client from set. |
| `WSManager.broadcast(data: dict)` | Send JSON to all clients. **Uses `list(self._connections)` snapshot** to avoid mutation-during-iteration bug (BUG-06 fix). |
| `WSManager.count` | Property: current number of connected clients. |
| `MAX_WS_CONNECTIONS` | `50` — hard cap to prevent resource exhaustion. |
| `ws_manager` | Module-level singleton instance. |

---

### `backend/findings_store.py` — In-Memory Findings Store
**Purpose:** Holds the currently-loaded scan in memory for fast searching without re-reading ChromaDB.

| Function | Description |
|---|---|
| `set_findings(findings, meta) → int` | Replace in-memory store with new scan. Returns count. |
| `get_all() → list[dict]` | Return all findings. |
| `search(query, limit=50) → list[dict]` | Case-insensitive keyword/IP/port/CVE search across name, synopsis, hosts, cves, port. |
| `host_summary() → dict` | Group findings by host with severity counts. |
| `get_page(page, per_page) → dict` | Paginated access. Returns `{findings, total, page, per_page, has_more}`. |

**Finding dict schema:** `{name, plugin_id, severity, synopsis, plugin_output, solution, port, service, hosts, cves, risk_factor, cvss3_base_score}`

---

### `backend/attack_chain_engine.py` — Attack Chain Detection Engine
**Purpose:** Detects multi-step attack paths that individual findings miss.

#### Chain Rules (`CHAIN_RULES` list)
Each rule is a dict with these fields:

| Field | Type | Description |
|---|---|---|
| `id` | str | Unique chain identifier (e.g. `"smb_relay_ntlm"`) |
| `name` | str | Human-readable chain name |
| `description` | str | Full attack path description |
| `requires` | list[dict] | ALL conditions must match ≥1 finding (AND logic) |
| `any_of` | list[dict] | At least one must match (OR logic, optional) |
| `upgraded_risk` | str | CRITICAL / HIGH / MEDIUM (always ≥ individual severities) |
| `steps` | list[str] | Step-by-step attack path description |
| `mitre` | list[str] | MITRE ATT&CK technique IDs (e.g. `"T1557.001"`) |
| `generates` | str | PoC template key in `POC_TEMPLATES` dict |
| `references` | list[str] | Tool URLs / references |

#### Built-in Chain Rules
| Chain ID | Name | Risk |
|---|---|---|
| `smb_relay_ntlm` | LLMNR Poisoning → NTLMv1 Capture → SMB Relay → Admin | CRITICAL |
| `kerberoasting_path` | Weak Kerberos → SPN Enumeration → Offline Hash Cracking | HIGH |
| `pass_the_hash` | NTLM Hash Dump → Pass-the-Hash → Lateral Movement | CRITICAL |
| `ssl_downgrade_mitm` | TLS 1.0/SSLv3 + No HSTS → MITM → Session Hijack | HIGH |
| `default_creds_rce` | Default Credentials → Admin Console → Remote Code Execution | CRITICAL |
| `ms17_010_chain` | EternalBlue (MS17-010) → DoublePulsar → System Shell | CRITICAL |
| `zerologon_dcsync` | ZeroLogon → Domain Controller → DCSync → All Hashes | CRITICAL |
| `web_rce_chain` | SQLi/RCE + File Upload + No WAF → Webshell | HIGH |

#### Functions

| Function | Signature | Description |
|---|---|---|
| `_finding_text(f)` | `(dict) → str` | Concatenates name+synopsis+plugin_output+cves into lowercase searchable string. |
| `_condition_matches(cond, findings)` | `(dict, list) → list` | Returns findings that match condition by keyword OR plugin_id. |
| `_collect_hosts(findings)` | `(list) → list[str]` | Deduplicates hosts from `hosts` list + `host` field across multiple findings. |
| `detect_chains(findings)` | `(list) → list[dict]` | Core detection. Iterates all CHAIN_RULES, checks requires+any_of, returns matched chains sorted by risk. |
| `generate_poc_script(chain)` | `(dict) → str` | Generates ready-to-run bash PoC script from `POC_TEMPLATES[chain["generates"]]`. |
| `run_chain_detection(findings, narrate)` | `async (list, bool) → dict` | Async wrapper. Calls detect_chains(), then for each chain calls Ollama for narrative + business impact. |

---

## 6. Module Reference — AI Subsystem

### `backend/ai/ollama_client.py` — Ollama LLM Client
**Purpose:** All communication with the local Ollama API. Manages model selection, JSON extraction, offline fallback commands.

| Symbol | Description |
|---|---|
| `OLLAMA_BASE_URL` | From `backend.config.OLLAMA_HOST` (not hardcoded — BUG-04 fix) |
| `_MODELS` | List of supported models in priority order: `deepseek-r1:8b`, `gemma3:latest`, `gemma:7b`, `llama3:latest` |
| `_active_model` | Module-level variable tracking currently selected model |
| `is_ollama_running() → bool` | HEAD request to `OLLAMA_BASE_URL`. Fast liveness check. |
| `get_available_model() → str` | Returns first model from `_MODELS` that Ollama has installed. |
| `get_model_info() → dict` | Returns `{active, available: list}` |
| `set_active_model(model_id)` | Update `_active_model` |
| `_chat_async(prompt, system, temp) → str` | **Core LLM call.** Uses `asyncio.get_running_loop()` (BUG-01 fix, was `get_event_loop()`). POSTs to `/api/chat`. Returns model response text. |
| `_extract_json(text) → dict` | Extracts JSON from LLM response even if wrapped in markdown code blocks. Falls back to `{}`. |
| `chat(prompt, system, temp) → str` | Public sync-compatible wrapper around `_chat_async`. Used by test_engine (BUG-05 fix — replaces direct `requests.post()`). |
| `analyze_output(host, finding_name, ...) → dict` | Builds security analysis prompt, calls `_chat_async`, extracts structured JSON: `{verdict, confidence, summary, indicators, remediation, priority}`. |
| `chat_finding(question, context) → str` | General Q&A about a finding. Used by `/api/chat` and `/api/ask`. |
| `suggest_commands(finding_name, ...) → list[str]` | Returns list of pentest commands for the finding. Offline: returns `offline_commands[plugin_id]` if known. |
| `generate_executive_summary(findings_json) → str` | Generates a management-level summary of all findings. |
| `offline_commands` | Dict mapping `plugin_id → [list of commands]` for 30+ common Nessus plugins. Used when Ollama is offline. |

---

### `backend/ai/chromadb_memory.py` — ChromaDB RAG Memory
**Purpose:** Persistent vector memory of all verified findings. Enables cross-scan learning.

| Symbol | Description |
|---|---|
| `_VERDICT_COUNTS` | In-memory counter dict `{verdict: count}` — O(1) stats without fetching all records (BUG-07/ENH-08 fix). |
| `get_collection()` | Returns ChromaDB collection (lazy init). Uses `sentence-transformers/all-MiniLM-L6-v2` for embeddings. Returns `None` if ChromaDB unavailable. |
| `is_ready() → bool` | Quick check if collection is accessible. |
| `_bump_verdict(verdict)` | Increment `_VERDICT_COUNTS[verdict]`. Called on every `store_finding()`. |
| `store_finding(host, finding_name, plugin_id, severity, command, raw_output, verdict, confidence, summary, indicators) → str` | Embeds finding text, stores in ChromaDB with metadata. Returns document ID. Calls `_bump_verdict()`. |
| `search_similar(query, n_results=5) → list[dict]` | Semantic similarity search. Returns findings with metadata + distance score. |
| `build_memory_context(results) → str` | Formats search results into a prompt-ready context string. |
| `index_findings(findings)` | Batch-embed all findings from a scan (for `/api/findings/sync`). Skips already-indexed. |
| `lookup_findings(findings) → list[dict]` | For each finding, find best past verified match (confirmed/fp). Returns only matches with similarity above threshold. |
| `get_stats() → dict` | Returns `{total, confirmed, fp, needs_more, other}`. Uses `_VERDICT_COUNTS` (O(1)); resyncs from DB on restart. |
| `clear_memory() → bool` | Delete and recreate the ChromaDB collection. Resets `_VERDICT_COUNTS`. |

---

### `backend/ai/ml_engine.py` — Machine Learning Engine
**Purpose:** Supervised false-positive classification + unsupervised clustering of findings.

| Function | Description |
|---|---|
| `status() → dict` | Is scikit-learn available? Is FP model trained? Training sample count. |
| `_featurize(findings) → np.ndarray` | Convert findings to numerical feature matrix: severity encoding, CVE count, port number, plugin_id hash, text length. |
| `train_fp(findings) → dict` | Train RandomForestClassifier on findings labelled `confirmed` or `fp`. Requires ≥10 samples. Saves model with joblib. |
| `predict_fp(findings) → dict` | Predict false-positive probability (0-1) for each finding. Returns sorted list with FP scores. |
| `cluster(findings, k=None) → dict` | KMeans clustering. Auto-selects k if not provided (min of √n, 8). Groups similar findings. |
| `risk_rank(findings, asset_weights={}) → dict` | Explainable priority score 0-100 per finding. Factors: severity, CVSS score, exploit intel (EPSS), asset weight multiplier. |

---

### `backend/ai/exploit_intel.py` — Live Exploit Intelligence
**Purpose:** Fetch real-time exploit probability (EPSS) and CISA Known Exploited Vulnerabilities (KEV) data.

| Function | Description |
|---|---|
| `load_kev() → dict` | Download CISA KEV JSON catalog from `cisa.gov`. Cached in memory. Returns `{cve_id: {name, date_added, due_date, notes}}`. |
| `fetch_epss(cves) → dict` | Batch-query FIRST.org EPSS API for exploit probability scores. Returns `{cve_id: {epss, percentile, date}}`. |
| `enrich(cves) → dict` | Combined enrichment: EPSS + KEV for given CVE list. Returns `{cve_id: {epss_score, percentile, in_kev, kev_date, kev_notes}}`. |
| `status() → dict` | KEV catalog size + EPSS cache size. |

---

## 7. Module Reference — SOAR Orchestrator

### `backend/soar/orchestrator.py` — Async SOAR Task Processor
**Purpose:** Priority queue that processes all findings in parallel, highest severity first. Includes circuit breaker to protect Ollama.

| Symbol | Description |
|---|---|
| `CircuitBreaker` | Simple circuit breaker class. Opens after `max_failures` consecutive AI errors, resets after `reset_timeout` seconds. Prevents hammering an unresponsive Ollama. |
| `CircuitBreaker.call(coro)` | Execute async coroutine through the breaker. Raises `CircuitOpenError` if open. |
| `SOAROrchestrator` | Main orchestrator class. |
| `SOAROrchestrator.start()` | Start the async worker task. |
| `SOAROrchestrator.stop()` | Stop worker, drain queue. |
| `SOAROrchestrator.set_broadcast(fn)` | Register WebSocket broadcast callback. |
| `SOAROrchestrator.submit(findings, host) → list[str]` | Add findings to priority queue (severity → priority int). Returns list of job IDs. Warns if queue is `None` (BUG-09 fix). |
| `SOAROrchestrator.clear()` | Empty the queue + results dict. |
| `SOAROrchestrator._process()` | Async worker loop. Dequeues findings, calls `_rule_based_score()` always, calls AI through circuit breaker, stores results, broadcasts. |
| `SOAROrchestrator._rule_based_score(finding) → dict` | Offline scoring: severity weight + CVE count + CVSS score → risk score 0-100. Always succeeds (no AI). |
| `SOAROrchestrator.get_summary() → dict` | `{processed, queue_size, results_count, circuit_state}`. Queue size safely handles `None` queue (BUG-02 fix). |
| `SOAROrchestrator.get_status(job_id) → dict` | Single job result. |
| `SOAROrchestrator.get_all_statuses() → list` | All job results. |
| `orchestrator` | Module-level singleton instance. |

### `backend/soar/playbooks.py` — SOAR Playbooks
**Purpose:** Named response playbook definitions for different vulnerability types.

`PLAYBOOKS` dict maps playbook key → `{name, icon, risk_level, steps: list[str]}`. Examples: `ssl_weak`, `default_creds`, `ms17_010`, `sqli`.

---

## 8. Module Reference — WebApp PT

### `backend/webapp_pt/session_manager.py` — PT Session Manager
**Purpose:** Lifecycle management of WebApp PT sessions. Full JSON persistence across restarts.

| Symbol | Description |
|---|---|
| `SessionState` | Enum: `CREATED`, `PERMISSION_PENDING`, `PERMISSION_GRANTED`, `CRAWLING`, `CHECKLIST_READY`, `TESTING`, `COMPLETED`, `ABORTED` |
| `TestResult` | Enum values: `"vulnerable"`, `"not_vulnerable"`, `"skipped"`, `"needs_manual"` |
| `PTSession` | Dataclass holding session state, target URL, crawl result, checklist, findings, test progress. |
| `PTSession.permissions_granted()` | True if all 4 permission fields are True. |
| `PTSession.current_test()` | Returns current active test dict or None. |
| `PTSession.to_dict(include_sensitive=False)` | Serializes session. Excludes `burp_api_key` and large `raw_html_sample` when `include_sensitive=False`. |
| `SessionStore` | Main store class. Thread-safe dict of sessions. |
| `SessionStore.__init__()` | Calls `_load_sessions()` — restores sessions from JSON on startup. |
| `SessionStore.create(target_url, tester_name) → PTSession` | Create new session. Generates UUID session_id. Calls `_persist()`. |
| `SessionStore.get(session_id) → PTSession` | Returns session or None. |
| `SessionStore.delete(session_id) → bool` | Remove session. Calls `_persist()`. |
| `SessionStore.update_state(session_id, state)` | Update session state enum. Calls `_persist()`. |
| `SessionStore.set_permissions(session_id, perms)` | Store permission dict. Sets state to `PERMISSION_GRANTED` if all True. Calls `_persist()`. |
| `SessionStore.set_crawl_result(session_id, crawl_dict)` | Store crawl result. Sets state to `CHECKLIST_READY`. Calls `_persist()`. |
| `SessionStore.set_checklist(session_id, tests)` | Set WSTG test list. Generates from `get_applicable_tests()` if empty. Sets state to `TESTING`. Calls `_persist()`. |
| `SessionStore.start_test(session_id) → dict` | Return next uncompleted test, mark as in-progress. Calls `_persist()`. |
| `SessionStore.submit_result(session_id, result, notes, evidence, payload, burp_req) → dict` | Record test result. Advances to next test. If all done → state `COMPLETED`. Calls `_persist()`. |
| `SessionStore.get_all() → list` | All sessions as dicts. |
| `_save_sessions(sessions)` | Write `sessions` dict to `history/sessions/webapp_pt_sessions.json`. |
| `_load_sessions() → dict` | Read sessions from JSON. Returns empty dict on error. |
| `get_store() → SessionStore` | Returns module-level singleton `_store`. |

---

### `backend/webapp_pt/crawler.py` — Playwright Web Crawler
**Purpose:** Async BFS page crawler using Playwright (headless Chromium) with authentication support.

| Symbol | Description |
|---|---|
| `CrawlResult` | Dataclass: pages_found, forms_found, js_files, secrets_found, auth_required, login_page, errors, raw_data. |
| `CrawlResult.summary()` | Returns summary dict for WebSocket broadcast. |
| `CrawlResult.to_dict()` | Full serialization for persistence. |
| `WebAppCrawler(max_pages, broadcast_fn)` | Main crawler class. |
| `WebAppCrawler.crawl_unauthenticated(url) → CrawlResult` | Start crawl without login. Tries Playwright first, falls back to `requests`. |
| `WebAppCrawler.crawl_authenticated(url, user, pass) → CrawlResult` | Calls `_auto_login()` first, then `_crawl()`. |
| `WebAppCrawler._crawl(page, start_url) → CrawlResult` | BFS crawl: visit page → extract links → enqueue new pages → detect forms → scan JS files. |
| `WebAppCrawler._extract_links(page, base_origin) → list[str]` | Uses `page.evaluate(script, base_origin)` with argument passing (BUG-03 fix — no f-string JS injection). |
| `WebAppCrawler._auto_login(page, url, user, pass) → bool` | Detect login form (heuristic: input[type=password]), fill and submit. **Verifies success** by checking URL change + HTML for failure strings (BUG-10 fix). |
| `WebAppCrawler._scan_js_secrets(page, js_url) → list[str]` | Fetch JS file with `page.evaluate("(async (url) => {...})(arguments[0])", js_url)` — safe arg passing (BUG-03 fix). Regex-scan for API keys, tokens, passwords. |

---

### `backend/webapp_pt/test_engine.py` — WSTG Test Engine
**Purpose:** Generates AI-enriched guidance for each OWASP WSTG test based on the crawl result.

| Symbol | Description |
|---|---|
| `OLLAMA_BASE_URL` | From `backend.config.OLLAMA_HOST` (BUG-04 fix — not hardcoded). |
| `TestEngine(session_id)` | Engine instance per session. |
| `TestEngine.get_enriched_test(test, crawl_result) → dict` | Takes WSTG test dict + crawl data. Returns test + `ai_guidance` field. |
| `TestEngine.generate_test_guidance(test, crawl_result) → str` | Calls `ollama_client.chat()` (BUG-05 fix — uses shared client, not direct `requests.post()`). Returns step-by-step guidance. |
| `TestEngine.generate_finding_summary(finding, notes, evidence) → str` | AI summary of a confirmed finding. |
| `TestEngine.on_finding(test, notes, evidence, payload, severity)` | Called when test result is VULNERABLE. Stores in session findings. |
| `check_ollama_available() → dict` | Uses `ollama_client.is_ollama_running()` (BUG-05 fix). Returns `{available, model, note}`. |

---

### `backend/webapp_pt/burp_integration.py` — Burp Suite Integration
**Purpose:** Adapts to three Burp modes based on what's available.

| Symbol | Description |
|---|---|
| `BurpMode` | Enum: `PRO_AUTO` (Burp Pro REST API), `COMMUNITY` (manual XML import), `MANUAL` (raw request analysis only) |
| `detect_burp_mode() → dict` | Auto-detect which mode is available. Checks if Burp Pro API is accessible on `localhost:1337`. |
| `set_api_key(key)` | Set Burp Pro API key for authenticated REST calls. |
| `burp_available() → bool` | True if Pro mode with valid API key. |
| `start_scan_pro(target_url, scan_type) → dict` | Start a Burp Pro automated scan via REST API. |
| `get_scan_status_pro(scan_id) → dict` | Poll Burp Pro scan status. |
| `get_scan_issues_pro(scan_id) → list` | Get Burp Pro scan findings. |
| `import_burp_xml(xml_content) → dict` | Parse Burp XML export into findings. |
| `import_burp_xml_unified(xml_content) → dict` | Parse Burp XML → unified findings format matching Nessus schema. |
| `analyze_manual_request(raw_request, host) → dict` | Analyze raw HTTP request/response for common vulnerabilities (injection, XSS headers, etc.) |
| `validate_scan_permission(perms, target) → dict` | Validate that all legal permission fields are True before allowing scan. |
| `start_burp_job(target, scan_type, username, password) → dict` | Start async Burp job (Pro or simulated). Returns `{ok, job_id}`. |
| `get_burp_job(job_id) → dict` | Get Burp job status and findings. |

---

### `backend/webapp_pt/wstg_checklist.py` — OWASP WSTG Checklist
**Purpose:** Defines and selects applicable WSTG tests based on crawl findings.

| Function | Description |
|---|---|
| `get_applicable_tests(crawl_result) → list[dict]` | Returns WSTG tests applicable to the target. Filters based on what crawler found (forms → injection tests, auth pages → auth tests, JS → client-side tests). |

Each test dict: `{test_id, category, name, description, severity, references: list[str]}`.

Categories covered: `Information Gathering`, `Configuration`, `Authentication`, `Session Management`, `Input Validation`, `Error Handling`, `Cryptography`, `Business Logic`, `Client-Side`.

---

## 9. Module Reference — Terminal (Kali Linux)

### `backend/terminal_pty.py` — Kali Linux Terminal over WebSocket
**Purpose:** Full interactive terminal in the browser. Two modes: local PTY on Kali, or SSH to a remote Kali machine.

| Symbol | Description |
|---|---|
| `_SSH_MODE` | `True` if `KALI_SSH_HOST` env var is set. Determines mode at startup. |
| `_detect_shell() → str` | Auto-detect best shell: checks `/bin/zsh` → `/usr/bin/zsh` → `/bin/bash`. Respects `AAVAPT_SHELL` override. |
| `_SHELL` | Detected shell path. Kali default is `/bin/zsh`. |
| `_set_winsize(fd, rows, cols)` | `fcntl.ioctl(TIOCSWINSZ)` — resize PTY on terminal resize event. |
| `_kali_banner(mode) → str` | ANSI green banner shown on connect: "AA-VAPT — Kali Linux Terminal", mode, shell. |
| `terminal_session(ws)` | **Main entry point.** Accepts WebSocket, routes to `_local_terminal` or `_ssh_terminal`. In local mode, rejects non-localhost clients. |
| `_local_terminal(ws)` | Opens PTY via `pty.fork()`. Child becomes `_SHELL -l`. Parent bridges PTY ↔ WebSocket. Handles resize events. Clean SIGKILL on disconnect. |
| `_ssh_terminal(ws)` | Connects to remote Kali via paramiko SSH. Runs `invoke_shell(term="xterm-256color")`. Background thread reads SSH channel. Bridges to WebSocket. |
| `terminal_status() → dict` | Returns mode, shell/host/auth info, ready status. For `/api/status`. |

**WebSocket Protocol (client → server, JSON):**
- `{"type": "input", "data": "<keystrokes>"}` — user typed something
- `{"type": "resize", "cols": N, "rows": N}` — terminal resized

**Server → client:** raw terminal output as text frames.

---

## 10. API Endpoint Reference

### Authentication
- `require_auth` applied to: `POST /api/analyze`, `POST /api/soar/triage`
- Header: `X-API-Key: <key>` or query param `?api_key=<key>`
- If `AAVAPT_API_KEY` env not set → all endpoints open (dev mode)

### Core Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/status` | — | System health + all subsystem status |
| GET | `/health` | — | Simple `{"status": "ok"}` liveness check |
| GET | `/mcp` | — | MCP server tool discovery |
| POST | `/mcp` | — | MCP tool execution |
| WS | `/ws` | — | Event stream (SOAR results, memory updates, model changes) |
| WS | `/ws/terminal` | — | Interactive Kali Linux terminal |

### AI Analysis

| Method | Path | Auth | Body | Description |
|---|---|---|---|---|
| POST | `/api/analyze` | ✓ | `AnalyzeRequest` | Full AI analysis of one finding |
| POST | `/api/chat` | — | `ChatRequest` | Q&A about a finding |
| POST | `/api/commands` | — | `CommandRequest` | AI pentest command suggestions |
| POST | `/api/summary` | — | `SummaryRequest` | Executive summary of all findings |
| POST | `/api/ask` | — | `AskRequest` | Global chatbot against loaded scan |

### SOAR

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/soar/triage` | ✓ | Auto-triage all findings (max 500) |
| GET | `/api/soar/status` | — | Queue status + circuit breaker state |
| GET | `/api/soar/results` | — | All triage results |
| GET | `/api/soar/result/{job_id}` | — | Single job result |
| GET | `/api/soar/playbooks` | — | Available playbooks |

### Memory (ChromaDB RAG)

| Method | Path | Description |
|---|---|---|
| POST | `/api/memory/search` | Semantic search |
| GET | `/api/memory/stats` | Collection stats (verdict counts) |
| DELETE | `/api/memory` | Clear all memory |
| POST | `/api/memory/feedback` | Correct a verdict |
| POST | `/api/memory/lookup` | Find past matches for current scan |
| POST | `/api/memory/store-verdict` | Manually store a verdict |

### Findings

| Method | Path | Description |
|---|---|---|
| POST | `/api/findings/sync` | Push scan data to server + trigger RAG index |
| GET | `/api/findings/search?q=&limit=` | Keyword/IP/CVE search |
| GET | `/api/findings/page?page=&per_page=` | Paginated access |

### History

| Method | Path | Description |
|---|---|---|
| POST | `/api/history/save` | Save scan to JSON |
| GET | `/api/history/list` | List saved scans |
| GET | `/api/history/load/{hid}` | Load saved scan |
| DELETE | `/api/history/{hid}` | Delete saved scan |

### Machine Learning

| Method | Path | Description |
|---|---|---|
| GET | `/api/ml/status` | FP model training status |
| POST | `/api/ml/train-fp` | Train FP classifier |
| POST | `/api/ml/predict-fp` | Predict FP probabilities |
| POST | `/api/ml/cluster` | Cluster similar findings |
| POST | `/api/ml/risk-rank` | Priority score per finding |
| POST | `/api/ml/remediation` | AI remediation steps |

### Exploit Intelligence

| Method | Path | Description |
|---|---|---|
| POST | `/api/intel/enrich` | EPSS + CISA KEV for CVEs |
| GET | `/api/intel/status` | KEV/EPSS cache sizes |

### Attack Chains

| Method | Path | Description |
|---|---|---|
| POST | `/api/chains/detect` | Detect attack chains in loaded scan |
| GET | `/api/chains/rules` | List all chain rules |
| POST | `/api/chains/poc` | Generate PoC bash script for chain |

### Knowledge Graph

| Method | Path | Description |
|---|---|---|
| GET | `/api/graphify/status` | graphifyy installed? |
| POST | `/api/graphify/build` | Build knowledge graph |
| POST | `/api/graphify/query` | Natural language graph query |
| POST | `/api/graphify/explain` | Explain a graph node |
| GET | `/api/graphify/list` | List built graphs |

### Script Generation

| Method | Path | Description |
|---|---|---|
| POST | `/api/generate-scripts` | Generate SSL/SSH/server bash scripts |

### WebApp PT

| Method | Path | Description |
|---|---|---|
| POST | `/api/webapp-pt/start-session` | Create new PT session |
| POST | `/api/webapp-pt/{id}/request-permission` | Submit legal permission gate |
| POST | `/api/webapp-pt/{id}/crawl` | Start Playwright crawl |
| POST | `/api/webapp-pt/{id}/generate-checklist` | Generate WSTG test list |
| GET | `/api/webapp-pt/{id}/next-test` | Get next WSTG test + AI guidance |
| POST | `/api/webapp-pt/{id}/submit-result` | Submit test result |
| POST | `/api/webapp-pt/{id}/skip-test` | Skip current test |
| GET | `/api/webapp-pt/{id}` | Get full session data |
| DELETE | `/api/webapp-pt/{id}` | Delete session |
| POST | `/api/webapp-pt/{id}/generate-report` | Generate HTML/JSON/Markdown report |
| POST | `/api/webapp-pt/{id}/parse-burp` | Analyze raw Burp request |
| GET | `/api/webapp-pt/sessions/list` | List all sessions |
| GET | `/api/webapp-pt/ai/status` | Ollama available for PT module? |
| GET | `/api/webapp-pt/tools/available` | Available pentest tools |
| POST | `/api/webapp-pt/tools/run` | Run tool suite against target |
| GET | `/api/webapp-pt/tools/run/{job_id}` | Tool job status + results |

### Burp Suite

| Method | Path | Description |
|---|---|---|
| GET | `/api/burp/detect` | Auto-detect Burp mode |
| POST | `/api/burp/set-api-key` | Set Burp Pro API key |
| GET | `/api/burp/available` | Is Burp Pro ready? |
| POST | `/api/burp/run` | Start Burp Pro scan job |
| GET | `/api/burp/run/{job_id}` | Poll Burp job status |
| POST | `/api/burp/to-memory` | Save Burp findings to ChromaDB |
| POST | `/api/burp/import-xml-merge` | Import Burp XML → unified findings |
| POST | `/api/burp/start-scan` | Direct Burp Pro scan (legacy) |
| GET | `/api/burp/scan-status/{id}` | Burp Pro scan status |
| GET | `/api/burp/issues/{id}` | Burp Pro scan issues |
| POST | `/api/burp/import-xml` | Parse Burp XML export |
| POST | `/api/burp/analyze-request` | Analyze raw HTTP request |

---

## 11. WebSocket Events

All events broadcast on `/ws` as JSON.

| Event | Direction | Payload | Description |
|---|---|---|---|
| `ping` | Client → Server | `"ping"` (text) | Keepalive |
| `pong` | Server → Client | `{"event": "pong"}` | Keepalive response |
| `memory_updated` | Server → Client | `{"event": "memory_updated", "data": stats_dict}` | After any ChromaDB write |
| `model_changed` | Server → Client | `{"event": "model_changed", "data": {"model": "..."}}` | After model switch |
| `soar_result` | Server → Client | `{"event": "soar_result", "job_id": ..., "data": result}` | SOAR job complete |
| `webapp_crawl_complete` | Server → Client | `{"type": "webapp_crawl_complete", "session_id": ..., "summary": ...}` | Crawler finished |
| `webapp_crawl_error` | Server → Client | `{"type": "webapp_crawl_error", "session_id": ..., "error": ...}` | Crawler error |

**Terminal** (`/ws/terminal`) uses its own protocol — see Section 9.

---

## 12. Authentication & Rate Limiting

### Authentication (ENH-01)
- Module: `backend/auth.py`
- Mechanism: API key via `X-API-Key` header or `?api_key=` query param
- Enabled: only if `AAVAPT_API_KEY` environment variable is set
- Protected endpoints: `/api/analyze`, `/api/soar/triage`
- Returns `401 Unauthorized` with JSON detail if key invalid

### Rate Limiting (ENH-02)
- Library: `slowapi` (wraps `limits` library)
- Applied per-IP via `get_remote_address`
- Registered on `app.state.limiter`
- Graceful degradation: if `slowapi` not installed → rate limiting silently disabled
- Returns `429 Too Many Requests` on violation

---

## 13. MCP Server

### `backend/mcp_server.py`
**Purpose:** Exposes AA-VAPT tools to Claude/AI agents via Model Context Protocol.

Mounted at `/mcp`. Implements MCP JSON-RPC spec.

Available MCP tools (exposed to AI agents):

| Tool Name | Description |
|---|---|
| `get_findings` | Get all loaded Nessus findings |
| `search_findings` | Search findings by keyword/IP/CVE |
| `get_host_summary` | Summary of findings per host |
| `analyze_finding` | AI analysis of a specific finding |
| `get_memory_stats` | ChromaDB memory statistics |
| `search_memory` | Semantic search in memory |
| `get_soar_status` | SOAR orchestrator status |
| `run_soar_triage` | Trigger SOAR triage |

---

## 14. Database & Persistence

### ChromaDB (Vector Database)
- **Purpose:** Persistent RAG memory of verified findings
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (local, no API calls)
- **Collection:** `vapt_memory` (configurable via `CHROMA_COLLECTION`)
- **Mode:** Embedded (file-based) by default; or connect to a ChromaDB server (`CHROMA_HOST:CHROMA_PORT`)
- **Document schema:** `{text, metadata: {host, finding_name, plugin_id, severity, verdict, confidence, timestamp, ...}}`

### JSON History (`history/`)
- Scan saves: `history/{12-char-uuid}_{scan_name}.json`
- Schema: `{meta: {id, name, target, scan_date, saved_at, counts...}, issues: [...], outputs: {...}}`

### PT Session Persistence (`history/sessions/webapp_pt_sessions.json`)
- All `SessionStore` mutations auto-save to this file
- Loaded on backend startup (survives restarts)
- Sensitive fields excluded: `burp_api_key`, `raw_html_sample`

### ML Models (`backend/ai/`)
- FP classifier: `fp_classifier.pkl` (joblib)
- Created by `ml_engine.train_fp()`, loaded automatically on `predict_fp()`

---

## 15. Environment Variables

| Variable | Default | Required | Description |
|---|---|---|---|
| `AAVAPT_API_KEY` | _(empty)_ | No | API key for auth. If empty, auth disabled. |
| `AAVAPT_SHELL` | _(auto)_ | No | Override terminal shell path. |
| `KALI_SSH_HOST` | _(empty)_ | No | Remote Kali IP/hostname. If set, enables SSH terminal mode. |
| `KALI_SSH_PORT` | `22` | No | SSH port for remote Kali. |
| `KALI_SSH_USER` | `kali` | No | SSH username. |
| `KALI_SSH_PASS` | _(empty)_ | No | SSH password (use key file instead for security). |
| `KALI_SSH_KEY` | _(empty)_ | No | Path to SSH private key file. |
| `KALI_SSH_TIMEOUT` | `10` | No | SSH connect timeout (seconds). |

Config values (in `backend/config.py` — edit directly or override via env):
- `OLLAMA_HOST` = `http://localhost:11434`
- `API_PORT` = `8000`
- `FRONTEND_PORT` = `8181`
- `CHROMA_COLLECTION` = `vapt_memory`

---

## 16. Deployment Guide

### Prerequisites
```bash
# 1. Install Ollama + a model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-r1:8b      # recommended — best security analysis
# OR: ollama pull gemma3:latest
# OR: ollama pull llama3:latest

# 2. Start Ollama
ollama serve

# 3. Install Python dependencies
cd AA-AGENT-V3-CHAINS
pip install -r backend/requirements.txt --break-system-packages

# 4. (Optional) Playwright browsers for WebApp PT
playwright install chromium
```

### Run Locally
```bash
# Terminal 1: Start backend
cd AA-AGENT-V3-CHAINS
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Serve frontend
cd frontend
python -m http.server 8181

# Open browser: http://localhost:8181
```

### Run with API Key Auth
```bash
export AAVAPT_API_KEY="your-secret-key-here"
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Terminal Mode: Local Kali Linux
```bash
# Run backend directly on Kali Linux — terminal auto-detects /bin/zsh
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
# Open http://localhost:8181/terminal.html
```

### Terminal Mode: Remote Kali Linux (SSH)
```bash
# Option A: Password auth
export KALI_SSH_HOST="192.168.1.50"
export KALI_SSH_USER="kali"
export KALI_SSH_PASS="kali"
python -m uvicorn backend.main:app ...

# Option B: Key auth (recommended)
export KALI_SSH_HOST="192.168.1.50"
export KALI_SSH_USER="kali"
export KALI_SSH_KEY="/home/user/.ssh/id_rsa"
python -m uvicorn backend.main:app ...
```

### Install paramiko for SSH Terminal Mode
```bash
pip install paramiko --break-system-packages
```

---

## 17. Testing

### Run Unit Tests
```bash
# From project root
pytest tests/ -v

# Single test file
pytest tests/test_chain_engine.py -v

# With coverage
pytest tests/ --cov=backend --cov-report=html
```

### Test Coverage (test_chain_engine.py)
Tests in `tests/test_chain_engine.py` cover:

| Test | What it verifies |
|---|---|
| `test_finding_text_lowercase` | `_finding_text()` normalizes to lowercase |
| `test_finding_text_includes_cves` | CVE IDs included in searchable text |
| `test_condition_matches_by_keyword` | Keyword matching across finding fields |
| `test_condition_matches_by_plugin_id` | Plugin ID matching |
| `test_condition_no_match` | Non-matching conditions return empty |
| `test_collect_hosts_unique` | Host deduplication across findings |
| `test_collect_hosts_from_host_field` | Single `host` field also collected |
| `test_smb_relay_chain_detected` | Full SMB Relay chain detection |
| `test_smb_relay_chain_not_detected_missing_one` | Partial match → no chain |
| `test_smb_relay_chain_upgraded_risk` | Detected chain risk = CRITICAL |
| `test_ssl_downgrade_chain_detected` | SSL Downgrade chain detection |
| `test_default_creds_chain_detected` | Default creds chain detection |
| `test_no_chains_empty_findings` | Empty input → empty output |
| `test_no_chains_irrelevant_findings` | Non-matching findings produce no unknown chains |
| `test_chains_sorted_critical_first` | Output sorted by risk (CRITICAL > HIGH) |
| `test_poc_script_generated` | PoC bash script generated correctly |
| `test_poc_script_unknown_template` | Unknown template → graceful "No PoC template" message |
| `test_poc_script_empty_hosts` | Empty hosts → script still generated |
| `test_all_rules_have_required_fields` | All CHAIN_RULES have all required fields |
| `test_all_generates_keys_have_poc_templates` | Every rule's `generates` key has a PoC template |

---

## 18. Bug Fixes Applied (v2.1.0)

| ID | File | Bug | Fix |
|---|---|---|---|
| BUG-01 | `ai/ollama_client.py` | `get_event_loop()` deprecated — fails in async context | Changed to `get_running_loop()` |
| BUG-02 | `soar/orchestrator.py` | `_queue.qsize()` crashes if queue is None | Added null check: `if self._queue is not None else 0` |
| BUG-03 | `webapp_pt/crawler.py` | f-string JS injection in `_extract_links()` and `_scan_js_secrets()` — XSS risk | Changed to `page.evaluate(script, arg)` with proper arg passing |
| BUG-04 | `webapp_pt/test_engine.py` | Ollama URL hardcoded as `localhost:11434` | Changed to `from backend.config import OLLAMA_HOST` |
| BUG-05 | `webapp_pt/test_engine.py` | Direct `requests.post()` to Ollama — bypassed retry/fallback logic | Changed to `ollama_client.chat()` |
| BUG-06 | `ws_manager.py` | `broadcast()` iterated set directly — `RuntimeError` if client disconnects mid-loop | Changed to `list(self._connections)` snapshot |
| BUG-07 | `ai/chromadb_memory.py` | `get_stats()` fetched ALL ChromaDB records on every call — O(n) at scale | Added `_VERDICT_COUNTS` in-memory counter; stats now O(1) |
| BUG-08 | `main.py` | History ID was 8 chars (UUID prefix) — collision probability too high at scale | Changed to 12 chars |
| BUG-09 | `soar/orchestrator.py` | `submit()` silently dropped findings if queue was None | Added warning log |
| BUG-10 | `webapp_pt/crawler.py` | `_auto_login()` always returned True even on failed login | Added URL change check + failure keyword detection |
| BUG-11 | `webapp_pt/crawler.py` | `result.js_files.extend(js_urls)` added duplicates | Changed to dedup loop with `seen` set |

---

## 19. Enhancements Implemented (v2.1.0)

| ID | Enhancement | Where |
|---|---|---|
| ENH-01 | API Key authentication on sensitive endpoints | `backend/auth.py` + `main.py` |
| ENH-02 | Rate limiting via slowapi (graceful if not installed) | `main.py` |
| ENH-03 | Session persistence for WebApp PT (survives restarts) | `webapp_pt/session_manager.py` |
| ENH-04 | Unified Ollama client in test_engine (no direct requests) | `webapp_pt/test_engine.py` |
| ENH-06 | Paginated findings endpoint `/api/findings/page` | `findings_store.py` + `main.py` |
| ENH-07 | Comprehensive unit tests for attack chain engine | `tests/test_chain_engine.py` |
| ENH-08 | O(1) ChromaDB stats with in-memory counters | `ai/chromadb_memory.py` |
| ENH-09 | WebSocket connection limit (50 max, reject with 1008) | `ws_manager.py` |
| ENH-12 | SOAR triage hard cap (500 findings max per request) | `main.py` |
| **NEW** | **Real Kali Linux terminal** — local PTY + SSH to remote Kali | `backend/terminal_pty.py` |

---

*This document covers AA-VAPT v2.1.0. For the bug/enhancement review with full rationale, see `PROJECT_REVIEW.md`.*
