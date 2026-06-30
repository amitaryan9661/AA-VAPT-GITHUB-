"""Ollama AI client — DeepSeek-R1, Gemma, Llama3, Mistral support."""
import json, logging, re, asyncio, time, threading
import ollama as _ollama
from backend.config import OLLAMA_HOST, OLLAMA_MODEL

# ── Cached list() to avoid hammering Ollama at startup ──
_list_cache = None
_list_cache_ts = 0.0
_LIST_TTL = 8  # seconds
_LIST_LOCK = threading.Lock()   # protect _list_cache from concurrent init

log = logging.getLogger("aavapt.ai.ollama")
_client = _ollama.Client(host=OLLAMA_HOST)
_async_client = _ollama.AsyncClient(host=OLLAMA_HOST)  # truly async — cancellable
_active_model = None

MODEL_PREFERENCE = [
    "llama3.2:3b","llama3.2:1b","llama3.2",   # best tool-calling support
    "llama3.1:8b","llama3.1",                   # also supports tool calls
    "llama3:8b","llama3",
    "mistral-nemo","mistral:7b","mistral",
    "gemma3:9b","gemma3:4b","gemma3:1b",
    "deepseek-r1:7b","deepseek-r1:1.5b","deepseek-r1",  # last — no native tool calls
    "phi3:mini","phi3","qwen2:7b","qwen2",
]
MODEL_DISPLAY = {
    "deepseek":"DeepSeek-R1","gemma":"Gemma","llama":"Llama3",
    "mistral":"Mistral","phi":"Phi3","qwen":"Qwen",
}

def _cached_list():
    """Return _client.list() result, cached for _LIST_TTL seconds to avoid startup spam."""
    global _list_cache, _list_cache_ts
    now = time.time()
    with _LIST_LOCK:
        if _list_cache is None or (now - _list_cache_ts) > _LIST_TTL:
            _list_cache = _client.list()
            _list_cache_ts = now
        return _list_cache

def list_models():
    try:
        raw = [m.model for m in _cached_list().models]
        out = []
        for m in raw:
            display = m
            for key, label in MODEL_DISPLAY.items():
                if key in m.lower():
                    display = label + " (" + m + ")"
                    break
            out.append({"id": m, "display": display})
        return out
    except Exception:
        return []

def get_available_model():
    global _active_model
    if _active_model:
        return _active_model
    try:
        installed = [m.model for m in _cached_list().models]
        if not installed:
            return OLLAMA_MODEL
        for preferred in MODEL_PREFERENCE:
            for m in installed:
                if preferred.split(":")[0].lower() in m.lower():
                    return m
        return installed[0]
    except Exception as e:
        log.warning("Cannot list models: %s", e)
        return OLLAMA_MODEL

def set_active_model(model_id):
    global _active_model
    _active_model = model_id
    log.info("Active model: %s", model_id)

def get_model_info():
    active = get_available_model()
    return {
        "active": active,
        "active_display": next((m["display"] for m in list_models() if m["id"]==active), active),
        "available": list_models(),
        "override": _active_model,
    }

def is_ollama_running():
    try:
        _cached_list()
        return True
    except Exception:
        return False

def chat(prompt, system="", model=None):
    m = model or get_available_model()
    messages = []
    if system:
        messages.append({"role":"system","content":system})
    messages.append({"role":"user","content":prompt})
    try:
        resp = _client.chat(model=m, messages=messages, options={"temperature":0.1,"num_predict":2048})
        return resp.message.content.strip()
    except Exception as e:
        log.error("Ollama chat error: %s", e)
        raise

async def _chat_async(prompt, system="", model=None, timeout=45):
    """Truly async chat using AsyncClient — timeout actually cancels the request."""
    m = model or get_available_model()
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        resp = await asyncio.wait_for(
            _async_client.chat(model=m, messages=messages,
                               options={"temperature": 0.1, "num_predict": 1024}),
            timeout=timeout,
        )
        return (resp.message.content or "").strip()
    except asyncio.TimeoutError:
        raise Exception(f"LLM timeout after {timeout}s — model may still be loading")
    except Exception as e:
        log.error("_chat_async error: %s", e)
        raise


# ─────────────────────────────────────────────────────────────
#  Tool-calling (OpenAI-compatible Ollama format)
# ─────────────────────────────────────────────────────────────

_NO_TOOL_CALL_MODELS = ("deepseek-r1", "deepseek-v2", "llama2",
                         "phi3", "phi4", "gemma", "qwen",
                         "mistral")  # all mistral variants — use JSON-prompt fallback

def _model_supports_tool_calls(model_name: str) -> bool:
    """Models known to support Ollama native tool_calls."""
    name = (model_name or "").lower()
    # These don't reliably support Ollama tool_calls — use JSON-prompt instead
    for skip in _NO_TOOL_CALL_MODELS:
        if skip in name:
            return False
    # llama3.1+, mistral-nemo, command-r, firefunction support tool calls
    for ok in ("llama3.1", "llama3.2", "mistral-nemo", "command-r",
               "firefunction", "hermes", "functionary"):
        if ok in name:
            return True
    return False


def chat_with_tools(messages: list, tools: list, model=None) -> dict:
    """
    Call Ollama using native tool-calling format with automatic JSON-prompt fallback.

    Strategy:
      1. Try native tool-calling (tools= parameter) — works on Ollama ≥0.2 + capable models
      2. If tool_calls not returned, try JSON-in-text extraction from the response
      3. If tools= fails entirely (older Ollama / unsupported model), fall back to
         plain chat with a JSON-format instruction prompt

    Returns: {"tool_call": {"name":..., "arguments":...}, "content": thought_text}
    """
    m = model or get_available_model()

    # ── Attempt 1: native tool-calling (skip for unsupported models) ───
    if not _model_supports_tool_calls(m):
        log.debug("Model %s: skipping native tool_calls, using JSON-prompt", m)
        return _json_prompt_fallback(messages, tools, m)

    try:
        resp = _client.chat(
            model=m,
            messages=messages,
            tools=tools,
            options={"temperature": 0.0, "num_predict": 512},
        )
        msg = resp.message

        if msg.tool_calls:
            tc = msg.tool_calls[0]
            fn = tc.function
            args = fn.arguments if isinstance(fn.arguments, dict) else json.loads(fn.arguments or "{}")
            log.debug("Tool-call (native): %s %s", fn.name, args)
            return {"tool_call": {"name": fn.name, "arguments": args}, "content": ""}

        # Model responded with text (no tool_call) — try JSON extraction
        text = (msg.content or "").strip()
        extracted = _extract_json_block(text)
        if extracted and "action" in extracted:
            log.debug("Tool-call (json-in-text): %s", extracted.get("action"))
            return {
                "tool_call": {
                    "name":      extracted["action"],
                    "arguments": extracted.get("action_input", {}),
                },
                "content": extracted.get("thought", ""),
            }

        # Text reply with no tool — return as content (agent will treat as finish)
        return {"tool_call": None, "content": text}

    except Exception as e:
        log.warning("Native tool-calling failed (%s) — falling back to JSON-prompt", e)

    return _json_prompt_fallback(messages, tools, m)


def _build_json_prompt(messages: list, tools: list) -> str:
    """Build a compact single-turn JSON-output prompt for models without native tool_calls."""
    # Group tools by category for readability
    tool_lines = "\n".join(
        f'  {t["function"]["name"]}: {t["function"].get("description","")[:100]}'
        for t in tools
    )
    system_content = next((m["content"] for m in messages if m["role"] == "system"), "")
    # Use last 8 messages for context (enough to track recent steps without overflow)
    recent = [m for m in messages[-8:] if m["role"] in ("user", "assistant", "tool")]
    context_parts = []
    for m in recent:
        role = m["role"].upper()
        content = str(m.get("content") or "")[:300]
        # Summarize tool results to avoid huge observations bloating the prompt
        if m["role"] == "tool":
            content = content[:200] + ("…" if len(content) > 200 else "")
        context_parts.append(f"[{role}]: {content}")
    context = "\n".join(context_parts)
    return (
        f"{system_content[:800]}\n\n"
        f"AVAILABLE TOOLS:\n{tool_lines}\n\n"
        f"RECENT HISTORY:\n{context}\n\n"
        "Respond with EXACTLY ONE JSON object (no markdown, no explanation):\n"
        '{"thought":"your reasoning","action":"tool_name","action_input":{"param":"value"}}\n'
        "If all tasks are done:\n"
        '{"thought":"complete","action":"finish","action_input":{"answer":"full summary"}}'
    )


def _parse_json_response(text: str) -> dict:
    """Parse JSON action from LLM text response."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    extracted = _extract_json_block(text)
    if extracted and "action" in extracted:
        log.info("JSON-prompt → %s", extracted.get("action"))
        return {
            "tool_call": {
                "name":      extracted["action"],
                "arguments": extracted.get("action_input", {}),
            },
            "content": extracted.get("thought", ""),
        }
    return {"tool_call": None, "content": text}


def _json_prompt_fallback(messages: list, tools: list, model: str) -> dict:
    """Sync JSON-prompt fallback — only called from sync context."""
    prompt = _build_json_prompt(messages, tools)
    resp = _client.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0.0, "num_predict": 512},
    )
    return _parse_json_response(resp.message.content or "")


async def _json_prompt_fallback_async(messages: list, tools: list,
                                      model: str, timeout: int = 45) -> dict:
    """Async JSON-prompt — uses AsyncClient so timeout actually cancels the request."""
    prompt = _build_json_prompt(messages, tools)
    resp = await asyncio.wait_for(
        _async_client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.0, "num_predict": 512},
        ),
        timeout=timeout,
    )
    return _parse_json_response(resp.message.content or "")


async def chat_with_tools_async(messages: list, tools: list, model=None, timeout=45) -> dict:
    """
    Async tool-calling — uses AsyncClient so timeouts actually cancel the HTTP request.

    Flow:
      1. If model doesn't support native tool_calls → _json_prompt_fallback_async (truly cancellable)
      2. If model supports native tool_calls → try native via AsyncClient, fall back to async JSON-prompt
    """
    m = model or get_available_model()

    # ── Fast path: model known to not support tool_calls ──────────────────
    if not _model_supports_tool_calls(m):
        log.debug("chat_with_tools_async: %s → JSON-prompt (timeout=%ds)", m, timeout)
        try:
            return await _json_prompt_fallback_async(messages, tools, m, timeout=timeout)
        except asyncio.TimeoutError:
            raise Exception(f"LLM timeout after {timeout}s — try a smaller/faster model")

    # ── Native tool_calls via AsyncClient ─────────────────────────────────
    try:
        resp = await asyncio.wait_for(
            _async_client.chat(
                model=m,
                messages=messages,
                tools=tools,
                options={"temperature": 0.0, "num_predict": 512},
            ),
            timeout=timeout,
        )
        msg = resp.message
        if msg.tool_calls:
            tc = msg.tool_calls[0]
            fn = tc.function
            args = fn.arguments if isinstance(fn.arguments, dict) else json.loads(fn.arguments or "{}")
            log.debug("Native tool-call: %s %s", fn.name, args)
            return {"tool_call": {"name": fn.name, "arguments": args}, "content": ""}

        # Text reply — try JSON extraction
        text = (msg.content or "").strip()
        extracted = _extract_json_block(text)
        if extracted and "action" in extracted:
            return {
                "tool_call": {"name": extracted["action"], "arguments": extracted.get("action_input", {})},
                "content": extracted.get("thought", ""),
            }
        return {"tool_call": None, "content": text}

    except asyncio.TimeoutError:
        raise Exception(f"LLM timeout after {timeout}s — try a smaller/faster model")
    except Exception as e:
        log.warning("Native tool-calling failed (%s) — falling back to async JSON-prompt", e)
        return await _json_prompt_fallback_async(messages, tools, m, timeout=timeout)


def _extract_json_block(text: str) -> dict:
    """Extract first balanced JSON object from text (fallback for non-tool-call models)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    for start in range(len(text)):
        if text[start] != "{":
            continue
        depth, in_str, escape = 0, False, False
        for end in range(start, len(text)):
            ch = text[end]
            if escape:
                escape = False; continue
            if ch == "\\" and in_str:
                escape = True; continue
            if ch == '"':
                in_str = not in_str; continue
            if in_str:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:end + 1])
                    except Exception:
                        break
    return {}

def _extract_json(text):
    """FIX B12: Robust JSON extraction — find the largest balanced { } block."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Walk through text looking for balanced JSON objects
    best = None
    for start in range(len(text)):
        if text[start] != '{':
            continue
        depth = 0
        in_str = False
        escape = False
        for end in range(start, len(text)):
            ch = text[end]
            if escape:
                escape = False
                continue
            if ch == '\\' and in_str:
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:end+1]
                    try:
                        parsed = json.loads(candidate)
                        if best is None or len(candidate) > len(best[0]):
                            best = (candidate, parsed)
                    except json.JSONDecodeError:
                        pass
                    break
    return best[1] if best else {}

ANALYZE_SYSTEM = (
    "You are a senior penetration tester. Analyze raw command output from Kali Linux "
    "against a Nessus finding. Be precise. Respond ONLY with valid JSON."
)

async def analyze_output(host, finding_name, plugin_id, severity, synopsis,
                          plugin_output, command, raw_output,
                          memory_context="No similar past findings."):
    # FIX B13: Notify AI when inputs are truncated so it can factor that in
    po_truncated = len(plugin_output) > 600
    ro_truncated = len(raw_output) > 1800
    truncation_note = ""
    if po_truncated or ro_truncated:
        truncation_note = (
            "\nNOTE: "
            + ("Plugin output truncated to 600 chars. " if po_truncated else "")
            + ("Raw output truncated to 1800 chars. " if ro_truncated else "")
            + "Base verdict on available data; use 'needs-more' if truncation affects confidence."
        )

    prompt = (
        "Analyze this pentest data:\n\n"
        "TARGET: " + host + "\n"
        "FINDING: " + finding_name + "\n"
        "PLUGIN: " + plugin_id + "\n"
        "SEVERITY: " + severity + "\n"
        "SYNOPSIS: " + synopsis + "\n"
        "PLUGIN OUTPUT: " + plugin_output[:600] + "\n\n"
        "COMMAND: " + command + "\n"
        "OUTPUT:\n" + raw_output[:1800] + "\n\n"
        "MEMORY: " + memory_context[:400]
        + truncation_note + "\n\n"
        "Respond with JSON only:\n"
        '{"verdict":"confirmed|fp|needs-more","confidence":0-100,'
        '"indicators":["..."],"summary":"...","next_commands":['
        '{"tool":"...","command":"...","purpose":"...","type":"recon|enum|exploit|verify"}],'
        '"exploit_links":[{"title":"...","url":"...","cve":"...","exploitable":true}],'
        '"false_positive_reason":null,"risk_notes":"..."}'
    )
    try:
        raw = await _chat_async(prompt, ANALYZE_SYSTEM)
        result = _extract_json(raw)
        if not result:
            result = {
                "verdict":"needs-more","confidence":40,
                "indicators":["AI could not parse output"],
                "summary":raw[:300],"next_commands":[],"exploit_links":[],
                "false_positive_reason":None,"risk_notes":"Manual review required"
            }
        return result
    except Exception as e:
        log.error("analyze_output error: %s", e)
        return {
            "verdict":"needs-more","confidence":0,
            "indicators":["AI error: "+str(e)],
            "summary":"Ollama unavailable — using offline analysis.",
            "next_commands":[],"exploit_links":[],
            "false_positive_reason":None,"risk_notes":""
        }

CHAT_SYSTEM = (
    "You are an expert penetration tester. Answer questions about vulnerabilities "
    "concisely and technically. Include CVEs, exploits, and remediation."
)

async def chat_finding(question, finding_context):
    prompt = "Context:\n" + finding_context + "\n\nQuestion: " + question
    try:
        return await _chat_async(prompt, CHAT_SYSTEM)
    except Exception as e:
        return "AI unavailable: " + str(e)

async def generate_executive_summary(findings_json):
    system = "You are a senior security consultant writing an executive summary. Be professional and concise."
    prompt = (
        "Generate a professional executive summary for this Nessus assessment:\n\n"
        + findings_json[:3000]
        + "\n\nInclude: risk rating, top findings, business impact, top 5 remediation steps. 2-3 paragraphs."
    )
    try:
        return await _chat_async(prompt, system)
    except Exception as e:
        return "Summary failed: " + str(e)

CMD_SYSTEM = (
    "You are a Kali Linux penetration tester. Return ONLY a JSON array of "
    "ready-to-run commands. Every command MUST contain the real target IP, "
    "real port and real service - never placeholders like TARGET/PORT/IP. "
    "nmap must be the FIRST command. Group commands into three categories: "
    "'Quick Check', 'Deep Scan', 'Exploit Verify'."
)

# ──────────────────────────────────────────────────────────────────────
#  OFFLINE command generator (no Ollama needed) — TASK 4 fallback.
#  nmap-first, copy-paste-ready, REAL values, three categories.
# ──────────────────────────────────────────────────────────────────────
def _norm_port(port, default):
    p = str(port or "").strip()
    return p if p and p != "0" else str(default)


def offline_commands(finding_name, plugin_id, port, service, host, version=""):
    name = (finding_name or "").lower()
    svc = (service or "").lower()
    host = host or "TARGET_IP"
    cmds = []

    def add(tool, command, purpose, ctype, category):
        cmds.append({"tool": tool, "command": command, "purpose": purpose,
                     "type": ctype, "category": category, "note": ""})

    def has(*words):
        return any(w in name or w in svc for w in words)

    is_ssh = "ssh" in name or "ssh" in svc

    # ── SSH ─ checked first ("cipher"/"kex" words also appear in SSL) ─
    if is_ssh:
        p = _norm_port(port, 22)
        add("nmap", f"nmap -Pn -p {p} --script ssh2-enum-algos {host}",
            "Enumerate SSH ciphers / MAC / KEX / host keys",
            "recon", "Quick Check")
        add("ssh-audit", f"ssh-audit -p {p} {host}",
            "Detailed weak-algorithm audit (CBC / MD5 / DH-group1)",
            "enum", "Deep Scan")
        add("ssh",
            f"ssh -p {p} -o StrictHostKeyChecking=no -o BatchMode=yes -vv user@{host} 2>&1 | grep -iE 'cipher|kex|mac'",
            "Observe negotiated cipher/KEX/MAC at connection time",
            "verify", "Exploit Verify")
        return cmds

    # ── SSL / TLS ──────────────────────────────────────────────────
    if has("ssl", "tls", "certificate", "cipher", "sha-1", "sha1", "poodle",
           "beast", "heartbleed", "drown", "freak", "logjam", "sweet32", "rc4"):
        p = _norm_port(port, 443)
        add("nmap", f"nmap -Pn --script ssl-cert,ssl-enum-ciphers -p {p} {host}",
            "PRIMARY: certificate validity + cipher suite enumeration (fast, no rate limit)",
            "recon", "Quick Check")
        add("testssl", f"testssl -S --color 0 --warnings off {host}:{p}",
            "SECONDARY if nmap gives no dates: full certificate audit",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn --script ssl-enum-ciphers -p {p} {host}",
            "Enumerate supported TLS protocols and cipher suites",
            "enum", "Deep Scan")
        add("testssl", f"testssl --color 0 --warnings off {host}:{p}",
            "Full TLS audit: weak ciphers, protocol issues",
            "enum", "Deep Scan")
        add("openssl",
            f"echo | openssl s_client -connect {host}:{p} 2>/dev/null | openssl x509 -noout -dates -serial -fingerprint -sha1",
            "Confirm validity dates + SHA-1 fingerprint directly",
            "verify", "Exploit Verify")

    # ── SMB / Windows ──────────────────────────────────────────────
    elif has("smb", "ms17", "eternalblue", "ms08", "netbios", "cifs", "samba"):
        p = _norm_port(port, 445)
        add("nmap", f"nmap -Pn -p {p},139 --script smb-protocols,smb-security-mode {host}",
            "SMB versions + signing / security mode",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -p {p} --script smb-vuln-ms17-010,smb-vuln-ms08-067 {host}",
            "Check EternalBlue / MS08-067 exposure",
            "enum", "Deep Scan")
        add("smbclient", f"smbclient -L //{host} -N",
            "List shares via null session",
            "verify", "Exploit Verify")

    # ── HTTP / Web / Server version ────────────────────────────────
    elif has("http", "web", "iis", "apache", "nginx", "server header",
             "server version", "php", "banner", "tomcat"):
        p = _norm_port(port, 80)
        proto = "https" if p in ("443", "8443", "8089", "7551", "7552") else "http"
        add("nmap", f"nmap -Pn -p {p} --script http-server-header,http-headers,http-title {host}",
            "Grab Server banner + response headers",
            "recon", "Quick Check")
        add("curl", f"curl -skI {proto}://{host}:{p}/",
            "Confirm Server / X-Powered-By header leak",
            "verify", "Quick Check")
        add("nikto", f"nikto -h {proto}://{host}:{p} -maxtime 300",
            "Web vulnerability scan",
            "enum", "Deep Scan")
        add("whatweb", f"whatweb -a 3 {proto}://{host}:{p}",
            "Fingerprint web technologies and versions",
            "enum", "Deep Scan")

    # ── SMTP / Mail ────────────────────────────────────────────────
    elif has("smtp", "mail", "open relay", "vrfy", "expn"):
        p = _norm_port(port, 25)
        add("nmap", f"nmap -Pn -p {p} --script smtp-commands {host}",
            "Enumerate supported SMTP commands + banner",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -p {p} --script smtp-open-relay {host}",
            "Test for open mail relay",
            "enum", "Deep Scan")
        add("openssl", f"openssl s_client -starttls smtp -connect {host}:{p}",
            "Inspect STARTTLS certificate on the mail service",
            "verify", "Exploit Verify")

    # ── FTP ────────────────────────────────────────────────────────
    elif has("ftp", "anonymous"):
        p = _norm_port(port, 21)
        add("nmap", f"nmap -Pn -p {p} --script ftp-anon,ftp-syst {host}",
            "Check anonymous login + FTP system info",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -p {p} --script ftp-vsftpd-backdoor {host}",
            "Check for vsftpd backdoor",
            "enum", "Deep Scan")
        add("curl", f"curl -v ftp://{host}:{p}/ --user anonymous:anonymous",
            "Verify anonymous read access",
            "verify", "Exploit Verify")

    # ── RDP ────────────────────────────────────────────────────────
    elif has("rdp", "remote desktop", "bluekeep", "ms12-020"):
        p = _norm_port(port, 3389)
        add("nmap", f"nmap -Pn -p {p} --script rdp-enum-encryption {host}",
            "Enumerate RDP encryption / NLA",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -p {p} --script rdp-vuln-ms12-020 {host}",
            "Check MS12-020 / BlueKeep exposure",
            "enum", "Deep Scan")

    # ── SNMP ───────────────────────────────────────────────────────
    elif has("snmp", "community"):
        p = _norm_port(port, 161)
        add("nmap", f"nmap -Pn -sU -p {p} --script snmp-info {host}",
            "SNMP system info via default community",
            "recon", "Quick Check")
        add("snmpwalk", f"snmpwalk -v2c -c public {host}",
            "Walk the MIB using 'public' community",
            "enum", "Deep Scan")

    # ── Database ───────────────────────────────────────────────────
    elif has("mysql", "mssql", "sql server", "oracle", "postgres", "redis", "mongodb"):
        defaults = {"mssql": 1433, "oracle": 1521, "postgres": 5432, "redis": 6379, "mongodb": 27017}
        dport = next((v for k, v in defaults.items() if k in name or k in svc), 3306)
        p = _norm_port(port, dport)
        add("nmap", f"nmap -Pn -p {p} -sV {host}",
            "Confirm database service + version",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -p {p} --script '*-info,*-empty-password' {host}",
            "Check default / empty credentials and info leak",
            "enum", "Deep Scan")

    # ── Generic fallback ───────────────────────────────────────────
    if not cmds:
        p = _norm_port(port, 0)
        portspec = f"-p {p}" if p != "0" else "-F"
        add("nmap", f"nmap -Pn -sV -sC {portspec} {host}",
            "Service/version detection + default scripts",
            "recon", "Quick Check")
        add("nmap", f"nmap -Pn -sV --version-all {portspec} {host}",
            "Aggressive version detection",
            "enum", "Deep Scan")
    return cmds


async def suggest_commands(finding_name, plugin_id, port, service, host, context=""):
    """AI command suggestions with REAL values; offline generator as fallback."""
    offline = offline_commands(finding_name, plugin_id, port, service, host)
    if not is_ollama_running():
        log.info("Ollama offline - using offline command generator")
        return offline

    prompt = (
        "Generate verification commands for this finding. Use the REAL values "
        "below in EVERY command (no placeholders). nmap must be first.\n"
        "Finding: " + str(finding_name) + "\n"
        "Plugin : " + str(plugin_id) + "\n"
        "Host   : " + str(host) + "\n"
        "Port   : " + str(port) + "\n"
        "Service: " + str(service) + "\n"
        "Context: " + str(context) + "\n\n"
        'Return a JSON array (5-9 items): '
        '[{"tool":"nmap","command":"nmap -Pn ... ' + str(host) + '",'
        '"purpose":"why","type":"recon|enum|verify",'
        '"category":"Quick Check|Deep Scan|Exploit Verify"}]'
    )
    try:
        raw = await _chat_async(prompt, CMD_SYSTEM)
        clean = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
        arr_match = re.search(r"\[[\s\S]*\]", clean)
        if arr_match:
            parsed = json.loads(arr_match.group())
            cleaned = []
            for c in parsed:
                cmd = str(c.get("command", ""))
                if re.search(r"\b(TARGET|PLACEHOLDER|x\.x\.x\.x)\b", cmd, re.I) or "<" in cmd:
                    continue
                if host and host not in ("TARGET", "TARGET_IP") and host not in cmd:
                    continue
                c.setdefault("category", "Quick Check")
                cleaned.append(c)
            if cleaned:
                return cleaned
    except Exception as e:
        log.warning("suggest_commands AI failed: %s - using offline fallback", e)
    return offline
