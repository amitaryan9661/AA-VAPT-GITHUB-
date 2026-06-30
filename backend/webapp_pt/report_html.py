# -*- coding: utf-8 -*-
"""
HTML Report Generator — Professional Pentest Report
=====================================================
Generates a self-contained HTML report with:
  - Executive summary with CVSS-scored severity counts
  - Attack chain visualizations
  - Per-finding detail with PoC evidence
  - Remediation recommendations
  - Professional dark theme matching AA-VAPT UI
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional


_SEVERITY_CONFIG = {
    "critical": {"color": "#ef4444", "bg": "#ef444420", "icon": "🔴", "score": 4},
    "high":     {"color": "#f97316", "bg": "#f9731620", "icon": "🟠", "score": 3},
    "medium":   {"color": "#eab308", "bg": "#eab30820", "icon": "🟡", "score": 2},
    "low":      {"color": "#22c55e", "bg": "#22c55e20", "icon": "🟢", "score": 1},
    "info":     {"color": "#3b82f6", "bg": "#3b82f620", "icon": "🔵", "score": 0},
}

def _sev_score(s: str) -> int:
    return _SEVERITY_CONFIG.get(s.lower(), {"score": 0})["score"]


def generate_html_report(
    target: str,
    findings: list[dict],
    agent_summaries: list[dict],
    attack_chains: list[dict],
    markdown_report: str = "",
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sorted_findings = sorted(findings, key=lambda f: _sev_score(f.get("severity", "info")), reverse=True)

    counts = {}
    for f in findings:
        s = f.get("severity", "info").lower()
        counts[s] = counts.get(s, 0) + 1

    confirmed_exploits = [f for f in findings if f.get("exploit_confirmed")]
    risk_score = min(10.0, sum(_sev_score(f.get("severity","info")) * 0.8 for f in findings) / max(len(findings), 1) * 3)
    risk_label = "CRITICAL" if risk_score >= 8 else "HIGH" if risk_score >= 6 else "MEDIUM" if risk_score >= 4 else "LOW"
    risk_color = "#ef4444" if risk_score >= 8 else "#f97316" if risk_score >= 6 else "#eab308" if risk_score >= 4 else "#22c55e"

    # ── Finding cards ─────────────────────────────────────────────────
    finding_cards = ""
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "info").lower()
        cfg = _SEVERITY_CONFIG.get(sev, _SEVERITY_CONFIG["info"])
        payloads = f.get("payloads", [])
        payload_html = ""
        if payloads:
            payload_html = "<div style='margin-top:8px'><span style='color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px'>Confirmed Payloads</span>"
            for p in payloads[:3]:
                payload_str = str(p.get("payload", p) if isinstance(p, dict) else p)
                url_str     = str(p.get("url", "") if isinstance(p, dict) else "")
                payload_html += f"""
                <div style='background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 12px;margin-top:6px;font-family:monospace;font-size:12px'>
                  <span style='color:#ef4444'>{_esc(payload_str[:120])}</span>
                  {f'<div style="color:#64748b;margin-top:3px;font-size:10px">{_esc(url_str[:100])}</div>' if url_str else ''}
                </div>"""
            payload_html += "</div>"

        confirmed_badge = '<span style="background:#22c55e20;color:#22c55e;border:1px solid #22c55e;border-radius:4px;padding:1px 8px;font-size:10px;margin-left:6px">✓ CONFIRMED EXPLOIT</span>' if f.get("exploit_confirmed") else ""
        cve_html = ""
        cves = f.get("cve", [])
        if cves:
            cve_html = " ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" style="background:#7c3aed20;color:#a78bfa;border:1px solid #7c3aed;border-radius:4px;padding:1px 6px;font-size:10px;text-decoration:none">{_esc(c)}</a>' for c in (cves if isinstance(cves, list) else [cves])[:3])

        finding_cards += f"""
        <div class="finding-card" style="background:#1e293b;border:1px solid #334155;border-left:4px solid {cfg['color']};border-radius:8px;padding:16px;margin-bottom:12px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:16px">{cfg['icon']}</span>
            <span style="font-weight:700;color:#f8fafc;font-size:14px">{i}. {_esc(f.get('name','Unknown Finding'))}</span>
            {confirmed_badge}
            <span style="margin-left:auto;background:{cfg['bg']};color:{cfg['color']};border:1px solid {cfg['color']}40;border-radius:4px;padding:2px 10px;font-size:11px;font-weight:700">{sev.upper()}</span>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:8px;font-size:12px;color:#94a3b8">
            <span>📍 <b>Host:</b> {_esc(str(f.get('host',''))[:60])}</span>
            <span>🔧 <b>Source:</b> {_esc(str(f.get('source',''))[:30])}</span>
            {f'<span>💯 <b>CVSS:</b> {f.get("cvss_score","")}</span>' if f.get("cvss_score") else ''}
            {cve_html}
          </div>
          {f'<p style="color:#cbd5e1;font-size:13px;margin:0">{_esc(str(f.get("description",""))[:400])}</p>' if f.get("description") else ''}
          {payload_html}
        </div>"""

    # ── Attack chains ─────────────────────────────────────────────────
    chain_html = ""
    for ch in attack_chains:
        sev = ch.get("severity", "high").lower()
        cfg = _SEVERITY_CONFIG.get(sev, _SEVERITY_CONFIG["high"])
        steps = ch.get("steps", [])
        step_html = " → ".join(f'<span style="background:#0f172a;border:1px solid #334155;border-radius:4px;padding:2px 8px;font-size:12px;color:#e2e8f0">{_esc(str(s))}</span>' for s in steps)
        chain_html += f"""
        <div style="background:#1e293b;border:1px solid {cfg['color']}40;border-left:4px solid {cfg['color']};border-radius:8px;padding:14px;margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="color:{cfg['color']};font-weight:700;font-size:14px">⛓️ {_esc(ch.get('name','Attack Chain'))}</span>
            <span style="background:{cfg['bg']};color:{cfg['color']};border-radius:4px;padding:1px 8px;font-size:10px;font-weight:700;margin-left:auto">{sev.upper()}</span>
          </div>
          <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:8px">{step_html}</div>
          <p style="color:#94a3b8;font-size:12px;margin:0">{_esc(ch.get('description',''))}</p>
        </div>"""

    # ── Agent summary cards ────────────────────────────────────────────
    agent_cards = ""
    emoji_map = {"recon": "🗺️", "vuln_scan": "🔍", "exploit": "💥", "report": "📄", "web": "🕷️"}
    for a in agent_summaries:
        name    = a.get("agent", "?")
        emoji   = a.get("emoji", emoji_map.get(name, "🤖"))
        status  = a.get("status", "done")
        status_color = "#22c55e" if status == "done" else "#ef4444" if status == "error" else "#eab308"
        agent_cards += f"""
        <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px;flex:1;min-width:150px">
          <div style="font-size:22px;margin-bottom:4px">{emoji}</div>
          <div style="font-weight:700;color:#f8fafc;text-transform:capitalize;margin-bottom:6px">{name.replace('_',' ')} Agent</div>
          <div style="font-size:12px;color:#94a3b8">Status: <span style="color:{status_color}">{status}</span></div>
          <div style="font-size:12px;color:#94a3b8">Findings: <b style="color:#f8fafc">{a.get('findings',0)}</b></div>
          <div style="font-size:12px;color:#94a3b8">Steps: <b style="color:#f8fafc">{a.get('steps',0)}</b></div>
          {f'<div style="font-size:11px;color:#64748b;margin-top:6px">{_esc(str(a.get("answer",""))[:120])}</div>' if a.get("answer") else ''}
        </div>"""

    # ── Severity chart data ───────────────────────────────────────────
    sev_bars = ""
    total = max(len(findings), 1)
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = counts.get(sev, 0)
        if not c:
            continue
        cfg = _SEVERITY_CONFIG[sev]
        pct = int(c / total * 100)
        sev_bars += f"""
        <div style="margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;margin-bottom:3px">
            <span>{cfg['icon']} {sev.upper()}</span><span><b style="color:#f8fafc">{c}</b></span>
          </div>
          <div style="background:#0f172a;border-radius:4px;height:8px;overflow:hidden">
            <div style="background:{cfg['color']};width:{pct}%;height:100%;border-radius:4px;transition:width 1s"></div>
          </div>
        </div>"""

    # ── Remediation summary ─────────────────────────────────────────
    remediation_html = ""
    remed_map = {
        "xss":        ("Cross-Site Scripting", "Implement Content Security Policy (CSP). Encode all user-supplied output using context-aware encoding. Validate and sanitize all inputs."),
        "sqli":       ("SQL Injection", "Use parameterized queries / prepared statements. Apply principle of least privilege to DB accounts. Never concatenate user input into SQL strings."),
        "lfi":        ("Local File Inclusion", "Whitelist allowed file paths. Avoid dynamic file includes from user input. Chroot/jail the web server process."),
        "ssrf":       ("Server-Side Request Forgery", "Whitelist allowed outbound URLs. Block requests to 169.254.x.x, 10.x.x.x, 172.16.x.x, 127.x.x.x. Use an outbound proxy."),
        "cors":       ("CORS Misconfiguration", "Explicitly whitelist trusted origins. Never reflect the Origin header directly. Require credentials only with explicit trusted origin list."),
        "ssl":        ("SSL/TLS Weakness", "Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only. Disable weak cipher suites. Enable HSTS with preload."),
        "headers":    ("Missing Security Headers", "Add: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy."),
        "smb":        ("SMB Vulnerability", "Disable SMBv1 immediately. Apply MS17-010 patch. Enable SMB signing. Restrict SMB to internal networks only."),
        "nuclei":     ("Template-Based Vulnerability", "Apply vendor patches. Review CVE for specific remediation steps. Update all components to latest stable versions."),
        "ssh":        ("SSH Misconfiguration", "Disable weak ciphers/MACs. Use Ed25519 or ECDSA keys. Disable password auth, use key-based auth only. Apply fail2ban."),
        "redirect":   ("Open Redirect", "Validate redirect URLs against a strict whitelist. Avoid using user-controlled values in redirects."),
        "command":    ("Command Injection", "Never pass user input to shell commands. Use language-provided APIs instead of shell. Implement strict input validation."),
    }
    for key, (vuln_name, remed) in remed_map.items():
        relevant = any(key in (f.get("source","") + f.get("name","") + f.get("description","")).lower() for f in findings)
        if relevant:
            remediation_html += f"""
            <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px;margin-bottom:10px">
              <div style="font-weight:700;color:#f8fafc;margin-bottom:6px">🛡️ {vuln_name}</div>
              <p style="color:#94a3b8;font-size:13px;margin:0">{remed}</p>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VAPT Report — {_esc(target)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
  h1 {{ font-size: 28px; font-weight: 800; color: #f8fafc; }}
  h2 {{ font-size: 18px; font-weight: 700; color: #f8fafc; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid #334155; }}
  h3 {{ font-size: 15px; font-weight: 700; color: #f8fafc; margin-bottom: 12px; }}
  @media print {{ body {{ background: #fff; color: #111; }} .no-print {{ display:none; }} }}
  @keyframes fadeIn {{ from {{ opacity:0; transform:translateY(10px) }} to {{ opacity:1; transform:translateY(0) }} }}
  .finding-card {{ animation: fadeIn 0.3s ease; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border:1px solid #334155;border-radius:12px;padding:28px;margin-bottom:28px">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
      <div>
        <div style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:2px;margin-bottom:4px">AA-VAPT Multi-Agent System</div>
        <h1>Penetration Test Report</h1>
        <div style="color:#94a3b8;margin-top:6px;font-size:14px">
          Target: <b style="color:#38bdf8">{_esc(target)}</b> &nbsp;·&nbsp; Generated: {now}
        </div>
      </div>
      <div style="text-align:center;background:#0f172a;border:2px solid {risk_color};border-radius:12px;padding:16px 24px">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Risk Level</div>
        <div style="font-size:32px;font-weight:800;color:{risk_color}">{risk_label}</div>
        <div style="font-size:12px;color:#94a3b8">{risk_score:.1f} / 10</div>
      </div>
    </div>
  </div>

  <!-- Stats row -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:800;color:#f8fafc">{len(findings)}</div>
      <div style="font-size:12px;color:#94a3b8">Total Findings</div>
    </div>
    <div style="background:#1e293b;border:1px solid #ef444440;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:800;color:#ef4444">{counts.get('critical',0)+counts.get('high',0)}</div>
      <div style="font-size:12px;color:#94a3b8">Critical/High</div>
    </div>
    <div style="background:#1e293b;border:1px solid #22c55e40;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:800;color:#22c55e">{len(confirmed_exploits)}</div>
      <div style="font-size:12px;color:#94a3b8">Confirmed Exploits</div>
    </div>
    <div style="background:#1e293b;border:1px solid #a78bfa40;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:800;color:#a78bfa">{len(attack_chains)}</div>
      <div style="font-size:12px;color:#94a3b8">Attack Chains</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:800;color:#f8fafc">{len(agent_summaries)}</div>
      <div style="font-size:12px;color:#94a3b8">Agents Used</div>
    </div>
  </div>

  <!-- Severity breakdown -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px">
      <h3>Severity Breakdown</h3>
      {sev_bars or '<p style="color:#64748b">No findings</p>'}
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px">
      <h3>Agent Performance</h3>
      <div style="display:flex;flex-wrap:wrap;gap:10px">{agent_cards}</div>
    </div>
  </div>

  <!-- Attack Chains -->
  {f'<h2>⛓️ Attack Chains ({len(attack_chains)})</h2>{chain_html}' if attack_chains else ''}

  <!-- Findings -->
  <h2>🔍 Vulnerability Findings ({len(findings)})</h2>
  {finding_cards or '<p style="color:#64748b;background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px">No vulnerabilities found.</p>'}

  <!-- Remediation -->
  {f'<h2>🛡️ Remediation Recommendations</h2>{remediation_html}' if remediation_html else ''}

  <!-- Footer -->
  <div style="border-top:1px solid #334155;margin-top:40px;padding-top:20px;text-align:center;color:#475569;font-size:12px">
    <div>Generated by <b style="color:#a78bfa">AA-VAPT Multi-Agent System</b> · {now}</div>
    <div style="margin-top:4px">Target: {_esc(target)} · Findings: {len(findings)} · Confirmed Exploits: {len(confirmed_exploits)}</div>
  </div>

</div>
<script>
  // Print button
  document.addEventListener('keydown', e => {{ if(e.ctrlKey && e.key==='p') window.print(); }});
</script>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML escape helper."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
