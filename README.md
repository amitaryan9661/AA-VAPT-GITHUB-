# AA-VAPT Nessus Analyzer — Complete Documentation

> **Version:** AA-AGENT-V3
> **Type:** Single-file browser-based VAPT toolkit
> **Author:** Amit Aryan
> **Stack:** HTML + JS (frontend) · Python FastAPI (AI backend) · Ollama (local LLM)

---

## What Is This?

AA-VAPT is an **all-in-one VAPT (Vulnerability Assessment & Penetration Testing) tool** that runs entirely in your browser. No cloud, no subscription — everything runs on your local machine.

A single HTML file + a Python backend + local AI (Ollama). Starts with a single command.

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Windows (WSL2) / Linux / macOS | Ubuntu 22+ / Kali Linux |
| Python | 3.10+ | 3.12+ |
| RAM | 4 GB | 8 GB (for AI models) |
| Storage | 2 GB | 10 GB (AI models) |
| Browser | Chrome / Firefox | Chrome latest |
| Internet | First-time install only | — |

---

## Installation

### Clone the Repository
```bash
git clone https://github.com/amitaryan9661/AA-VAPT-GITHUB.git
cd AA-VAPT-GITHUB
```

## Quick Start (3 Steps)

### Step 1 — Install (only once)
```bash
bash install.sh
```
This automatically installs:
- Python virtual environment
- FastAPI + Uvicorn + all Python packages
- Ollama (local AI engine)
- DeepSeek-R1 1.5B model (for AI analysis)
- ChromaDB (memory/vector store)

### Step 2 — Run
```bash
bash run.sh
```

### Step 3 — Open Browser
The tool opens automatically in your browser:
```
http://localhost:8181/nessus-analyzer.html
```

**For WSL users:**
```bash
cd /mnt/c/Users/<YourName>/Downloads/AA-VAPT-GITHUB
bash run.sh
```

---

## Run Without AI (Faster)
```bash
bash run.sh --no-ai
```

---

## File Structure

```
AA-VAPT-GITHUB/
├── nessus-analyzer.html     ← Main tool (entire frontend)
├── nmap-pt.html             ← Nmap script generator & analyzer
├── webapp-pt.html           ← Web application pentest tool
├── run.sh                   ← One-command launcher ⭐ START HERE
├── install.sh               ← One-command installer ⭐ RUN FIRST
├── daemon.sh                ← Background service mode
├── README.md                ← This file
│
├── backend/                 ← Python AI backend
│   ├── main.py              ← FastAPI app entry point
│   ├── config.py            ← Configuration (ports, model names)
│   ├── requirements.txt     ← Python dependencies
│   ├── mcp_server.py        ← MCP (Model Context Protocol) server
│   ├── script_generator.py  ← AI-assisted script generation
│   ├── ws_manager.py        ← WebSocket connection manager
│   ├── ai/
│   │   ├── ollama_client.py     ← Ollama LLM client
│   │   └── chromadb_memory.py   ← Vector DB for AI memory
│   └── soar/
│       ├── orchestrator.py  ← SOAR automation engine
│       └── playbooks.py     ← Pre-built SOAR playbooks
│
├── logs/                    ← Runtime logs
└── docker-compose.yml       ← Docker deployment (optional)
```

---

## All Features — Detailed Guide

### 1. Scan Analysis (Home Page)
**What it does:** Parses Nessus `.nessus` XML files and displays a vulnerability dashboard.

**How to use:**
1. Drag & drop a `.nessus` file on the home page (or click Choose File)
2. Automatic parsing — dashboard displays:
   - Severity breakdown (Critical / High / Medium / Low / Info)
   - Total vulnerability count
   - Host-wise distribution
3. Click a severity badge to filter
4. Click any vulnerability → CVE, CVSS, description, solution
5. `Generate Report` → Download full HTML report

---

### 2. Nmap Output
**What it does:** Parses Nmap results and generates a professional Word document.

**How to use:**
1. Upload a `.txt` / `.nmap` / `.docx` file (or select a folder)
2. Or paste text directly
3. Click `Parse & Preview`
4. `Download Word Doc` → Professional `.docx` VAPT report

**Supported input:** Nmap text output, `.nmap` files, `.docx` files with nmap output

---

### 3. Output Analyzer
**What it does:** Paste the output of any security tool → AI analyzes it.

**How to use:**
1. Paste tool output (nikto, gobuster, sqlmap, nmap, etc.)
2. Click `Analyze` → AI explains findings + risk level + next steps
3. `AI Suggest Commands` → Commands for the next step
4. `Save Output` → Save to history

**Requires:** Ollama running with a model

---

### 4. Diff Scanner
**What it does:** Compare two scans — see which ports are new or closed.

**How to use:**
1. Upload Old Scan (baseline)
2. Upload New Scan (latest)
3. Click `Compare`
4. Results: Newly Opened Ports (new risk) | Closed Ports (patched) | Unchanged
5. `Download Report` → Word document

**Supported:** `.txt` / `.nmap` / `.docx` / folder upload

---

### 5. Report Merger
**What it does:** Merges multiple Nessus `.nessus` files into one consolidated report.

**How to use:**
1. Upload multiple `.nessus` files
2. `Merge & Generate` → Combined report
3. Duplicates are automatically removed

---

### 6. History
**What it does:** Record of previous saved analyses.

- Past Output Analyzer results
- Saved scans
- Filter by type/date
- Click to reload / Delete

**Note:** Data is stored in browser localStorage — will be deleted if browser data is cleared.

---

### 7. Script Generator
**What it does:** Enter a target → generates a ready-to-run bash script.

**How to use:**
1. Enter target (IP / domain / multiple / file upload)
2. Tool type auto-detected (Web vs Infra) or select manually
3. Check the tools you want:

   **Web Tools:** nikto, nuclei, gobuster, feroxbuster, testssl, sqlmap, whatweb, wafw00f, subfinder, httpx
   
   **Infra Tools:** nmap TCP, nmap UDP, nmap vuln, masscan, smbclient, enum4linux, snmpwalk, onesixtyone

4. Set variables: WORDLIST path, THREADS count, OUTDIR path
5. `Generate Script` → Preview bash script
6. `Copy` or `Download .sh`

**Script Features:**
- If a tool is not installed → automatically installs it
- Output is automatically saved to: `$OUTDIR/toolname_target_date.txt`
- Generates a loop for multiple targets

**Custom Commands:**
- `Edit Commands` → Modify the command for any tool
- Modifications are permanently saved in localStorage

---

### 8. IP Manager

#### Tab 1 — IP Set Divider
**What it does:** Divides a large IP list into equal sets.

**How to use:**
1. Upload `.txt` / `.xlsx` / `.csv` (one IP per line)
2. View stats: Total / Duplicates / Unique / Sets
3. Configure scope name and set size (default: 5 IPs/set)
4. Preview sets in the table
5. Click `Download ZIP`

**ZIP structure:**
```
scope_ProjectName_20250610.zip
├── Set_01_[192.168.1.1-192.168.1.5].txt
├── Set_02_[192.168.1.6-192.168.1.10].txt
├── all_ips.txt
└── _scope_info.txt
```

**Duplicate detection:** Click the badge → list of duplicate IPs with count

#### Tab 2 — Scope Compare
**What it does:** Compare old vs new scope.

**How to use:**
1. Upload old scope file
2. Upload new scope file
3. Click `Compare Scopes`
4. Results:
   - New IPs Added (not in old, now in new)
   - IPs Removed (in old, not in new)
   - Common IPs (same in both)
5. `Download Word Report` → Color-coded `.docx` report
6. `Download .txt Summary` → Plain text

---

### 9. CVE Intel
**What it does:** Search a CVE number → get details, CVSS score, affected products, references.

**How to use:**
1. Type a CVE number (e.g. CVE-2021-44228)
2. Full details will appear
3. `Open in CVSS Calculator` → Score breakdown

---

### 10. CVSS Calculator
**What it does:** Manually calculate a CVSS v3 score.

1. Select each metric (Attack Vector, Complexity, etc.)
2. Score is calculated in real-time
3. `Copy Vector` → Copy the CVSS string

---

### 11. Settings
- Theme: Dark / Light mode
- Sidebar: Collapsed / Expanded default
- AI Backend URL (if you need to change the port)

---

## Projects Feature (Topbar)
Manage multiple engagements.

1. Click "No project" in the topbar
2. Type a project name → `+ Create`
3. All data (scans, history) is linked to this project
4. `✕` → Close project

---

## AI Features (Requires Ollama)

| Feature | Location | Description |
|---|---|---|
| AI Analyze | Output Analyzer | Tool output → AI explains findings |
| AI Suggest Commands | Output Analyzer | Next-step commands |
| SOAR Triage | Scan Analysis | Auto-triage with AI |
| Memory/Chat | Output Analyzer | Chat about findings |

**AI Status check:**
```
http://localhost:8000/api/status
http://localhost:8000/docs        (API documentation)
```

---

## Ports Reference

| Service | Port | URL |
|---|---|---|
| Frontend | 8181 | http://localhost:8181/nessus-analyzer.html |
| Backend (FastAPI) | 8000 | http://localhost:8000 |
| Ollama | 11434 | http://localhost:11434 |

---

## Libraries (CDN — No npm needed)

| Library | Version | Purpose |
|---|---|---|
| Chart.js | 4.4.1 | Severity charts |
| docx.js | 8.5.0 | Word document generation |
| JSZip | 3.10.1 | ZIP file creation |
| mammoth | 1.4.18 | Read .docx files |
| SheetJS (xlsx) | 0.18.5 | Read .xlsx/.xls Excel files |

---

## Troubleshooting

**Tool not opening in browser:**
```bash
curl http://localhost:8181/nessus-analyzer.html -I
# If error:
bash run.sh
```

**AI not working:**
```bash
curl http://localhost:11434/api/tags    # Check Ollama
ollama list                             # List models
ollama pull deepseek-r1:1.5b           # Pull missing model
```

**Backend error:**
```bash
cat logs/backend.log
bash install.sh    # Reinstall
```

**File upload not working:**
- Use Chrome browser
- File size must be under 50MB

---

## Docker (Optional)
```bash
docker-compose up -d
# URL: http://localhost:8181/nessus-analyzer.html
```

## Background Mode
```bash
bash daemon.sh start    # Start in background
bash daemon.sh stop     # Stop
bash daemon.sh status   # Check status
```

---

## Privacy
- No data is sent to the cloud
- Ollama = fully local LLM, no external API
- `.nessus` files are parsed only in browser memory
- localStorage = data saved in browser, not on server

---

## Disclaimer

This tool is intended **exclusively for authorized penetration testing and security assessments**. Use only on systems you own or have explicit written permission to test. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

---

## Quick Reference

```
CLONE    →  git clone https://github.com/amitaryan9661/AA-VAPT-GITHUB.git
INSTALL  →  bash install.sh
RUN      →  bash run.sh
NO AI    →  bash run.sh --no-ai
URL      →  http://localhost:8181/nessus-analyzer.html
API DOCS →  http://localhost:8000/docs

TABS:
  Scan Analysis   — .nessus file → vulnerability dashboard
  Nmap Output     — nmap results → Word doc
  Output Analyzer — any tool output + AI analysis
  Diff Scanner    — compare two scans → new/closed ports
  Report Merger   — merge multiple .nessus files
  History         — saved analyses
  Script Gen      — auto bash script generator
  IP Manager      — IP set divider + scope compare
  CVE Intel       — CVE lookup
  CVSS Calc       — score calculator
  Settings        — theme, preferences
```

---

*AA-VAPT — Built for security professionals. Run local. Stay private.*
