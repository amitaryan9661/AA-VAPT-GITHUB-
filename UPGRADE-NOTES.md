# AA-VAPT — Upgrade Notes (v2)

## graphify Knowledge Graph Integration (v2.1)

AA-VAPT now supports **graphifyy** — a knowledge graph builder that converts
your Nessus findings into a queryable, interactive graph.

**Token reduction: ~71.5x** vs naive file reading (Tree-sitter static analysis +
LLM semantic extraction).

### New API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/graphify/status` | GET | Check if graphify is installed, list built graphs |
| `/api/graphify/build` | POST | Build graph from loaded findings |
| `/api/graphify/query` | POST | Query graph with natural language |
| `/api/graphify/explain` | POST | Explain a CVE/host/plugin node in depth |
| `/api/graphify/list` | GET | List all previously built graphs |

### Install

```bash
pip install graphifyy && graphify install
```

Or just run `bash install.sh` — it now installs graphifyy automatically.

### Quick usage

```bash
# Build a knowledge graph from current scan findings
curl -X POST http://localhost:8000/api/graphify/build \
  -H "Content-Type: application/json" \
  -d '{"scan_label": "client_scan_june", "mode": "standard"}'

# Query the graph (71.5x fewer tokens)
curl -X POST http://localhost:8000/api/graphify/query \
  -H "Content-Type: application/json" \
  -d '{"graph_json_path": "./graphify-out/client_scan_june_20240611/graph.json",
       "question": "which hosts have critical vulnerabilities related to OpenSSH?"}'
```

### Output files (in `./graphify-out/<label>/`)

- `graph.html` — interactive visual graph (click nodes, search, filter)
- `graph.json` — persistent queryable graph (use for future queries without rebuild)
- `GRAPH_REPORT.md` — god nodes, surprising connections, suggested analyst questions
- `obsidian/` — open as Obsidian vault



```bash
bash run.sh          # starts Ollama (if installed) + backend + frontend, opens browser
bash run.sh --no-ai  # frontend only, no AI backend
```

## SSL / SSH / Server verification scripts (rewritten)

* **SSL certificate: testssl is the PRIMARY tool** (it directly reports
  `Certificate Validity ... expired`, exactly like the PoC). `nmap --script
  ssl-cert` is used **only as a fallback** when testssl fails, then `openssl`
  last. SSH and server-version still use nmap first (`ssh2-enum-algos` /
  `http-server-header`), then `ssh-audit` / `curl`.
* **Only real issues are reported for SSL:** `EXPIRED`, `EXPIRING <30 days`,
  `WEAK SHA-1`. Trust / self-signed / wrong-hostname findings are **ignored**
  (they are Nessus noise on internal networks).
* **One blank line between every target** so each result is clearly separated.
* **All output is printed to the same terminal AND saved** to `./aa-vapt-logs/`
  in the directory you run the script from (report + raw nmap/testssl evidence).
* A short, accurate **summary** prints at the end of every script.

Generated dynamically from your loaded scan via the tool
(`POST /api/generate-scripts`) or run the bundled standalone
`verify_ssl_testssl.sh`, `verify_server_versions.sh`, `vapt_verify.sh`.

## Unified AI pipeline

`finding -> check_memory (ChromaDB) -> extract host/port/service -> Ollama
DeepSeek with real values + past verified cases -> store verdict + confidence`.
Everything runs through Ollama only; every step has an offline fallback.

## Global Search + AI Assistant panel (frontend)

Floating, collapsible panel (bottom-right, "Search & Ask"):

* Search bar — type an **IP / host / port / CVE / plugin / keyword** to instantly
  filter the loaded scan; each hit shows a severity badge and a one-click **jump**
  to the finding.
* Chat — ask e.g. *"what critical findings are on 172.21.101.21?"*,
  *"show all SSL issues"*, *"which hosts have open port 22?"*,
  *"summarize high severity findings"*. Answers use **only** the loaded scan +
  ChromaDB memory through Ollama. If Ollama is offline it falls back to local
  keyword search so you always get an answer.

## Smart command generation

Every suggested command is **copy-paste ready with the real IP/port/service**
(no `TARGET`/`PORT` placeholders), grouped into **Quick Check / Deep Scan /
Exploit Verify**. Works fully offline via the built-in generator.

## New MCP tools (`backend/mcp_server.py`)

`search_findings`, `get_host_summary`, `get_commands_for_finding`,
`check_memory`, `store_result` (plus the existing analyze/CVSS/memory tools).
Every MCP tool call is logged to the console (`[MCP] tool call: ...`).

## Memory feedback loop

Top-3 similar past cases are injected into every analysis; results with
confidence > 70 are auto-stored; the thumbs up/down feedback updates the stored
verdict in ChromaDB.

## Bug fixes

* `run.sh` — `warn()` was called before it was defined (port-busy check moved
  below the function definitions).
* Log files moved out of `/tmp` into `./aa-vapt-logs/` (where you run the tool).
* SSH "CBC cipher" findings are no longer mis-classified as SSL.
* No new Python dependencies were added.
