# AA-VAPT — Complete Reference Guide

> **Last Updated:** June 2026  
> **Version:** 2.0.0  

---

## Quick Start

```bash
cd /mnt/c/Users/"Amit Aryan"/Downloads/VAPTT-AGENT

# Pehli baar setup
bash install.sh

# Start karo (browser automatically khulega)
bash daemon.sh start
```

**Tool URL:** http://localhost:8181/nessus-analyzer.html

---

## Daemon Commands

| Command | Kaam |
|---------|------|
| `bash daemon.sh start` | Sab services background mein start karo (browser bhi khulega) |
| `bash daemon.sh stop` | Sab services band karo |
| `bash daemon.sh restart` | Restart karo |
| `bash daemon.sh status` | Running status dekho |
| `bash daemon.sh logs` | Live logs tail karo |
| `bash daemon.sh autostart` | Windows boot pe auto-start register karo (ek baar) |

---

## run.sh vs daemon.sh

| | `bash run.sh` | `bash daemon.sh start` |
|---|---|---|
| Mode | Foreground (Ctrl+C se band) | Background (terminal band karo, chalta rahega) |
| Browser | Auto-open | Auto-open |
| `--no-ai` flag | Yes (`bash run.sh --no-ai`) | No |

---

## Service URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost:8181/nessus-analyzer.html |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| MCP Server | http://localhost:8000/mcp |
| Health Check | http://localhost:8000/health |
| Status | http://localhost:8000/api/status |

---

## Docker (agar Docker Desktop + WSL integration enabled ho)

```bash
# Pehli baar / update ke baad
docker compose up --build -d

# Stop
docker compose down

# Logs
docker compose logs -f
```

---

## Verification Scripts

### 1. High/Critical/Medium — Interactive Verifier
```bash
# JSON file se (AA-VAPT tool se export karke)
bash vapt_verify.sh -t 192.168.1.100 -f scan_export.json

# Manual mode
bash vapt_verify.sh -t 192.168.1.100
```

**Flow:** Finding dikhata hai → Tool chalata hai (nmap/testssl/nikto/smbclient/etc.) → Puchta hai: **[c]onfirmed / [f]alse-positive / [s]kip / [q]uit** → Report save karta hai

### 2. Low/Info — Interactive Verifier
```bash
bash vapt_verify_low_info.sh -t 192.168.1.100 -f scan_export.json
```

**Tools:** nmap, curl, openssl, dig, nc, snmpwalk — lighter checks for informational findings

### 3. SSL Certificate Checker (testssl primary)
```bash
bash verify_ssl_testssl.sh
```

**Dikhata hai sirf:** Certificate Valid From/To dates, EXPIRED, Expiring <30d, Weak SHA-1, Self-signed  
**135 targets pre-loaded.** testssl.sh primary → openssl fallback

### 4. Server Version Disclosure
```bash
bash verify_server_versions.sh
```

**Checks:** HTTP Server header exposure (Microsoft-HTTPAPI, IIS, nginx, Apache) across 119 targets

---

## Auto-Generated Scripts (New Feature)

Jab bhi Nessus file upload karo AA-VAPT tool mein, **automatically** 5 scripts generate hote hain:

| Script | Kya karta hai |
|--------|--------------|
| `verify_ssl_testssl.sh` | SSL cert validity + SHA-1 (scan ke actual SSL targets) |
| `verify_server_versions.sh` | Server version disclosure (scan ke HTTP targets) |
| SSL+SSH Combined | testssl + nmap + openssl SSL/SSH checks |
| Master Script | Saare findings, ek-ek karke, numbered |
| *(Backend-generated)* | openssl-based cert dates script (green cards) |

Download button scripts panel mein appear hota hai scan load hone ke baad.

---

## API Endpoints (Backend)

| Method | Endpoint | Kaam |
|--------|----------|------|
| GET | `/health` | Health check |
| GET | `/api/status` | Full status (Ollama, ChromaDB, SOAR, WS) |
| POST | `/api/analyze` | AI analysis of finding + command output |
| POST | `/api/chat` | Chat about a finding |
| POST | `/api/commands` | Suggest verification commands |
| POST | `/api/summary` | Executive summary generation |
| POST | `/api/soar/triage` | Auto-triage all findings |
| GET | `/api/soar/status` | SOAR queue status |
| GET | `/api/soar/results` | All triage results |
| POST | `/api/generate-scripts` | Generate bash scripts from findings |
| POST | `/api/memory/search` | Search similar past findings |
| GET | `/api/memory/stats` | ChromaDB stats |
| DELETE | `/api/memory` | Clear memory |
| POST | `/api/history/save` | Save scan to history |
| GET | `/api/history/list` | List saved scans |
| GET | `/api/history/load/{id}` | Load saved scan |

---

## Manual SSL Commands (Kali Linux)

> `IP` aur `PORT` replace karo target se

### Certificate Dates + Expiry

**testssl (most accurate):**
```bash
testssl --severity HIGH --expired --color 0 IP:PORT
```

**OpenSSL:**
```bash
openssl s_client -connect IP:PORT -servername IP </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer
```

**Nmap:**
```bash
nmap -p PORT --script ssl-cert,ssl-date IP
```

**Bulk — multiple ports:**
```bash
for port in 443 8443 7551 7552 8089; do
  echo "=== $port ===" 
  openssl s_client -connect IP:$port -servername IP </dev/null 2>/dev/null \
    | openssl x509 -noout -dates 2>/dev/null || echo "  no cert"
done
```

### Self-Signed / Trust Issues
```bash
testssl --color 0 --severity MEDIUM IP:PORT

openssl s_client -connect IP:PORT -servername IP </dev/null 2>&1 \
  | grep -E "verify|Cert|CN=|SAN|error|depth"
```

### Weak SHA-1
```bash
openssl s_client -connect IP:PORT </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep "Signature Algorithm"
```

### HSTS Check
```bash
curl -sI https://IP:PORT/ | grep -iE "strict-transport|hsts"
```

---

## Manual SSH Commands

### Weak Algorithms
```bash
ssh-audit -p PORT IP

nmap -p PORT --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey IP
```

---

## Manual HTTP / Server Version

### Server Header Check
```bash
curl -sI http://IP:PORT/ | grep -iE "^server:|^x-powered-by:|^x-aspnet"
```

**Bulk check:**
```bash
for port in 80 443 5985 8080 8082 47001; do
  echo "=== $port ==="
  curl -sI http://IP:$port/ --max-time 5 | grep -i "^server:" || echo "  no response"
done
```

### Nmap HTTP Info
```bash
nmap -p PORT --script http-server-header,http-headers,http-methods,http-title IP
```

---

## Directory Structure

```
VAPTT-AGENT/
├── backend/
│   ├── main.py              — FastAPI app (API endpoints, lifespan)
│   ├── config.py            — Ports, paths, model config
│   ├── script_generator.py  — Auto-generates bash scripts from findings
│   ├── mcp_server.py        — MCP protocol server
│   ├── ws_manager.py        — WebSocket connection manager
│   ├── ai/
│   │   ├── ollama_client.py — Ollama AI client (async, non-blocking)
│   │   └── chromadb_memory.py — Vector memory (ChromaDB)
│   └── soar/
│       ├── orchestrator.py  — SOAR engine (priority queue, workers, circuit breaker)
│       └── playbooks.py     — Verification playbooks per vuln type
├── nessus-analyzer.html     — Frontend (single-file tool)
├── run.sh                   — Foreground launcher
├── daemon.sh                — Background 24/7 service manager
├── install.sh               — One-command installer
├── vapt_verify.sh           — Interactive verifier (Critical/High/Medium)
├── vapt_verify_low_info.sh  — Interactive verifier (Low/Info)
├── verify_ssl_testssl.sh    — SSL cert checker (testssl + openssl)
├── verify_server_versions.sh — HTTP server version checker
├── Dockerfile               — Backend Docker image
├── docker-compose.yml       — Full stack (ollama + backend + frontend)
├── docker-entrypoint.sh     — Docker startup (wait for ollama, pull model)
├── nginx.conf               — Nginx config for frontend container
├── history/                 — Saved scan JSON files
├── memory/chromadb/         — ChromaDB vector store (persistent)
└── logs/                    — backend.log, frontend.log, ollama.log
```

---

## Fixes Applied (v2.0.0)

### Python Backend
- **ollama_client.py** — `sync chat()` was blocking asyncio event loop → wrapped in `run_in_executor`
- **orchestrator.py** — `task_done()` missing from `finally` block → queue corruption fixed
- **orchestrator.py** — `_rule_based_score` verdict logic bug (only triggered at exactly 65%) → fixed thresholds
- **orchestrator.py** — `indicators` list from AI contained dicts, not strings → sanitized before ChromaDB store
- **chromadb_memory.py** — `s['verdict'].upper()` crashed if verdict was `None` → None-safe access
- **main.py** — `history_load` had no JSON error handling → wrapped in try/except
- **main.py** — `clear()` not calling `task_done()` per drained item → fixed
- **main.py** — ChromaDB init blocking startup → moved to background `run_in_executor`

### Bash Scripts
- **run.sh** — `err()` didn't exit → added `exit 1`; backend check used `kill -0` not HTTP; redundant `2>&1`
- **daemon.sh** — `OLLAMA_PID` clobbered by `save_pids()` overwrite; unconditional `pkill ollama`; `lsof` missing → `ss` fallback; BAT path unquoted (spaces broke it); browser auto-open added
- **install.sh** — `read -p` failed silently in non-interactive (curl|bash pipe); redundant `2>&1`
- **verify_ssl_testssl.sh** — Complete rewrite: testssl primary, openssl fallback, shows only cert dates + SHA-1 + expiry in color
- **verify_server_versions.sh** — Fixed hardcoded output path (ran appended to same file); added curl check; safe increments
- **vapt_verify.sh** — 10 bugs: SSL grep wrong string, nmap glob expansion, invalid port spec, SSH tool mislabeled, curl compat, `set -e` + `((VAR++))` crashes

### New Features
- **script_generator.py** — Auto-generates `verify_ssl_testssl.sh` + `verify_server_versions.sh` from any Nessus upload
- **vapt_verify_low_info.sh** — Interactive verifier for Low/Info findings
- **Docker support** — `docker compose up --build -d` single command
- **POST /api/generate-scripts** — Backend API for script generation

---

## Tool Resources

| Tool | Install | Repo |
|------|---------|------|
| testssl.sh | `apt install testssl.sh` | https://github.com/drwetter/testssl.sh |
| ssh-audit | `apt install ssh-audit` | https://github.com/jtesta/ssh-audit |
| sslscan | `apt install sslscan` | https://github.com/rbsec/sslscan |
| nikto | `apt install nikto` | https://github.com/sullo/nikto |
| enum4linux | `apt install enum4linux` | https://github.com/CiscoCXSecurity/enum4linux |
| smbmap | `pip install smbmap` | https://github.com/ShawnDEvans/smbmap |
| whatweb | `apt install whatweb` | https://github.com/urbanadventurer/WhatWeb |
| ODAT (Oracle) | Manual install | https://github.com/quentinhardy/odat |
