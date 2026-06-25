# AA-VAPT Nessus Analyzer — Build Progress

## Status: ✅ COMPLETE (v3 — SOAR + Gemma + WebSocket)

## Quick Start
```bash
unzip AA-VAPT-Nessus-Analyzer.zip -d nessus-analyzer && cd nessus-analyzer
bash install.sh        # First time: Python deps + Ollama + DeepSeek model
bash run.sh            # Start all services + open browser
bash run.sh --no-ai    # Offline mode (no backend needed)
```

## Services Started by run.sh
| Service | Port | Purpose |
|---------|------|---------|
| Frontend (Python HTTP) | 8181 | nessus-analyzer.html |
| FastAPI Backend | 8000 | AI analysis, SOAR, MCP |
| Ollama | 11434 | DeepSeek / Gemma / Llama3 |
| WebSocket | 8000/ws | Real-time SOAR events |
| MCP Server | 8000/mcp | Claude Desktop / Cursor |

## File Structure (19 files in ZIP)
```
nessus-analyzer.html          1685 lines — full frontend
run.sh                        130 lines  — one-command launcher
install.sh                    165 lines  — full dependency installer
backend/
  config.py                   centralized settings
  main.py                     FastAPI v2 — all routes + WebSocket
  mcp_server.py               MCP JSON-RPC 2.0 (6 tools)
  ws_manager.py               WebSocket broadcast manager
  requirements.txt            fastapi, uvicorn, ollama, chromadb, sentence-transformers
  ai/
    ollama_client.py          DeepSeek+Gemma+Llama3 multi-model support
    chromadb_memory.py        vector store + semantic search + feedback
  soar/
    orchestrator.py           SOAR engine: async queue, circuit breaker, state machine
    playbooks.py              Oracle/SMB/SSH/Web/FTP playbooks
```

## Features (All Implemented)

### Frontend (nessus-analyzer.html)
- Upload Nessus HTML or .nessus XML → auto-parse
- Sample data loader (172.21.102.13 Oracle DB, 10 issues)
- Issue sidebar: severity filter, search, jump by number
- Per-issue: full Nessus details, plugin output, references
- Verification commands (1-10 per issue, copy button)
- Output paste area + Analyze button
- **AI status bar**: Ollama dot, ChromaDB dot, model name, WS live, MCP badge
- **SOAR panel**: Auto-Triage All button, progress bar, real-time log
- **AI Analysis panel** per issue: AI Analyze, AI Suggest Commands, Search Memory
- **ChromaDB panel**: similar past findings auto-surface
- **AI Chat**: ask AI about any finding in natural language
- **Model selector**: DeepSeek / Gemma / Llama3 / Mistral dropdown
- CVSS v3.1 calculator (full metric groups, live score)
- CVE Intelligence (NVD, ExploitDB, Metasploit, GitHub, Shodan, Vulners, CISA KEV)
- Report generator → Nessus-style HTML with SOAR signals + raw outputs
- Offline fallback → regex analysis when AI not available
- LocalStorage persistence across sessions
- WebSocket auto-reconnect (5s retry)

### Backend AI Stack
- **DeepSeek-R1** (7b/1.5b) via Ollama — primary analysis model
- **Gemma** (3:9b/3:4b/2:9b/2:2b) — alternative model
- **Llama3** / **Mistral** / **Phi3** / **Qwen2** — fallback chain
- Model preference auto-selection + user override via dropdown
- Handles DeepSeek `<think>...</think>` reasoning blocks

### ChromaDB Memory (RAG)
- Persistent vector storage in `./memory/chromadb/`
- `all-MiniLM-L6-v2` sentence embeddings (local, no API)
- Auto-stores every AI analysis result
- Semantic search: similar past findings surface in UI
- Feedback endpoint (thumbs up/down → improves future)
- Stats API: total stored, verdict breakdown

### SOAR Orchestrator
- Async task queue (asyncio, no Celery)
- Priority queue: Critical → High → Medium → Low → Info
- 3 parallel workers
- State machine: QUEUED → ENRICHING → ANALYZING → DONE
- Circuit breaker: AI (3 failures → 120s cooldown), Memory (5 failures → 60s)
- Retry with exponential backoff (2 attempts per finding)
- Rule-based fallback scoring when AI unavailable
- Auto-stores results in ChromaDB

### SOAR Playbooks
- **Oracle**: TNS version, SID brute, ODAT, default creds, Metasploit (10 steps)
- **SMB**: EternalBlue/MS17-010, enum4linux, smbmap, CrackMapExec (5 steps)
- **SSH**: ssh-audit, auth methods, algo enum (3 steps)
- **Web**: whatweb, nikto, HTTP vuln scripts, headers check (4 steps)
- **FTP**: anonymous access, bounce, vuln scripts (1 step)
- **Default**: generic nmap + vuln scripts

### WebSocket (Real-time)
- Events: `triage_started`, `finding_update`, `finding_done`, `memory_updated`, `model_changed`
- Auto-reconnect on disconnect
- Ping/pong keepalive
- Multi-client broadcast

### MCP Server (6 tools)
- `analyze_nessus_finding` — full AI analysis via POST /mcp
- `suggest_commands` — Kali command suggestions
- `search_similar_findings` — ChromaDB semantic search
- `calculate_cvss` — CVSS v3.1 score from vector or metrics
- `get_memory_stats` — ChromaDB stats
- `clear_memory` — wipe all stored findings

## MCP Config for Claude Desktop
```json
{
  "mcpServers": {
    "aa-vapt-nessus": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

## API Endpoints
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/status | Full system status |
| POST | /api/analyze | AI analyze output |
| POST | /api/chat | Chat with AI about finding |
| POST | /api/commands | AI suggest commands |
| POST | /api/summary | Executive summary |
| POST | /api/soar/triage | Start auto-triage |
| GET | /api/soar/results | All SOAR results |
| GET | /api/soar/playbooks | List playbooks |
| GET | /api/models | Available models |
| POST | /api/models/select | Switch model |
| POST | /api/memory/search | Semantic search |
| POST | /api/memory/feedback | Record verdict feedback |
| DELETE | /api/memory | Clear all memory |
| WS | /ws | Real-time events |
| POST | /mcp | MCP JSON-RPC 2.0 |
| GET | /docs | FastAPI Swagger UI |
