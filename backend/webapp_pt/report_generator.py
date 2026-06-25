"""
WebApp PT Report Generator — HTML, JSON, and Markdown export.
All generation is local. No external calls.
"""

import json
import time
from datetime import datetime
from typing import Optional


def generate_html_report(session: dict, findings: list, checklist: list,
                          crawl_result: dict) -> str:
    """Generate a professional HTML penetration test report."""
    target_url = session.get("target_url", "Unknown")
    session_id = session.get("session_id", "")
    tester = session.get("tester_name", "Anonymous Tester")
    date_str = datetime.now().strftime("%B %d, %Y")
    total = session.get("total_tests", 0)
    vulns = session.get("tests_vulnerable", 0)
    not_vuln = session.get("tests_not_vuln", 0)
    skipped = session.get("tests_skipped", 0)

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Risk rating
    if sev_counts["critical"] > 0:
        risk_rating = "CRITICAL"
        risk_color = "#dc2626"
    elif sev_counts["high"] > 0:
        risk_rating = "HIGH"
        risk_color = "#ea580c"
    elif sev_counts["medium"] > 0:
        risk_rating = "MEDIUM"
        risk_color = "#d97706"
    elif sev_counts["low"] > 0:
        risk_rating = "LOW"
        risk_color = "#65a30d"
    else:
        risk_rating = "INFORMATIONAL"
        risk_color = "#0891b2"

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "medium").lower()
        sev_colors = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#65a30d", "info": "#0891b2"
        }
        sc = sev_colors.get(sev, "#888")
        remediation = f.get("remediation", "Refer to OWASP remediation guidance.")
        owasp = ", ".join(f.get("owasp_top10", [])) or "N/A"
        ai_summary = f.get("ai_summary", "")
        evidence = f.get("evidence", "").replace("<", "&lt;").replace(">", "&gt;")
        payload = f.get("payload", "").replace("<", "&lt;").replace(">", "&gt;")

        findings_html += f"""
        <div class="finding" id="finding-{i}">
            <div class="finding-header" style="border-left:4px solid {sc}">
                <span class="finding-num">F{i:02d}</span>
                <div class="finding-title-area">
                    <h3 class="finding-name">{f.get('name', 'Unknown')}</h3>
                    <div class="finding-meta">
                        <span class="badge" style="background:{sc}">{sev.upper()}</span>
                        <span class="badge-outline">{f.get('category','')}</span>
                        <span class="badge-outline">OWASP: {owasp}</span>
                    </div>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>{f.get('notes','') or ai_summary or 'See evidence below.'}</p>
                </div>
                {f'<div class="finding-section"><h4>AI Summary</h4><p>{ai_summary}</p></div>' if ai_summary else ''}
                {f'<div class="finding-section"><h4>Evidence / Proof of Concept</h4><pre>{evidence}</pre></div>' if evidence else ''}
                {f'<div class="finding-section"><h4>Payload Used</h4><code>{payload}</code></div>' if payload else ''}
                <div class="finding-section">
                    <h4>Remediation</h4>
                    <p>{remediation}</p>
                </div>
            </div>
        </div>"""

    # Coverage table (first 30 tests)
    coverage_rows = ""
    sev_badge_map = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#d97706", "low": "#65a30d", "info": "#0891b2"
    }
    status_icons = {
        "VULNERABLE": "🔴", "NOT_VULNERABLE": "✅",
        "SKIPPED": "⏭️", "PENDING": "⬜", "NEED_MANUAL": "🔵"
    }
    for t in checklist[:50]:
        icon = status_icons.get(t.get("status", "PENDING"), "⬜")
        sc = sev_badge_map.get(t.get("severity", "info"), "#888")
        coverage_rows += f"""
            <tr>
                <td>{t.get('test_id','')}</td>
                <td>{t.get('name','')}</td>
                <td>{t.get('category','')}</td>
                <td><span style="background:{sc};color:#fff;padding:2px 6px;border-radius:3px;font-size:11px">{t.get('severity','').upper()}</span></td>
                <td style="font-size:16px">{icon} {t.get('status','')}</td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebApp PT Report — {target_url}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  .report-header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid #334155; border-radius: 12px; padding: 40px; margin-bottom: 32px; }}
  .report-header h1 {{ font-size: 2rem; color: #f1f5f9; margin-bottom: 8px; }}
  .report-header .subtitle {{ color: #94a3b8; font-size: 1rem; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
    gap: 16px; margin-top: 24px; }}
  .meta-item {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; }}
  .meta-item .label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: .5px; }}
  .meta-item .value {{ font-size: 1rem; color: #f1f5f9; font-weight: 600; margin-top: 4px; }}
  .risk-badge {{ display:inline-block; background: {risk_color}22; color: {risk_color};
    border: 1px solid {risk_color}44; border-radius: 6px; padding: 4px 12px; font-weight: 700;
    font-size: 1.2rem; }}
  .stats-row {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 32px; }}
  .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
    padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .lbl {{ font-size: 11px; color: #64748b; text-transform: uppercase; margin-top: 4px; }}
  section {{ margin-bottom: 40px; }}
  section h2 {{ font-size: 1.3rem; color: #f1f5f9; margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 1px solid #334155; }}
  .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
    margin-bottom: 20px; overflow: hidden; }}
  .finding-header {{ padding: 20px 24px; display: flex; align-items: flex-start; gap: 16px;
    background: #0f172a; }}
  .finding-num {{ color: #64748b; font-size: 1.1rem; font-weight: 700; min-width: 40px; }}
  .finding-title-area {{ flex: 1; }}
  .finding-name {{ font-size: 1.1rem; color: #f1f5f9; margin-bottom: 8px; }}
  .finding-meta {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-outline {{ border: 1px solid #334155; padding: 2px 8px; border-radius: 4px; font-size: 11px; color: #94a3b8; }}
  .finding-body {{ padding: 20px 24px; }}
  .finding-section {{ margin-bottom: 16px; }}
  .finding-section h4 {{ color: #94a3b8; font-size: 11px; text-transform: uppercase;
    letter-spacing: .5px; margin-bottom: 6px; }}
  .finding-section p {{ color: #cbd5e1; }}
  .finding-section pre {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
    padding: 12px; font-size: 12px; overflow-x: auto; color: #86efac; }}
  .finding-section code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px;
    font-size: 12px; color: #fbbf24; }}
  .coverage-table {{ width: 100%; border-collapse: collapse; }}
  .coverage-table th {{ background: #0f172a; padding: 10px 12px; text-align: left;
    font-size: 11px; color: #64748b; text-transform: uppercase; border-bottom: 1px solid #334155; }}
  .coverage-table td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b;
    font-size: 13px; color: #cbd5e1; }}
  .coverage-table tr:hover td {{ background: #1e293b22; }}
  .exec-summary {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
    padding: 24px; margin-bottom: 24px; }}
  .exec-summary p {{ color: #94a3b8; margin-bottom: 8px; }}
  @media print {{ body {{ background: white; color: black; }}
    .container {{ max-width: 100%; }}
    .finding {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="container">

  <div class="report-header">
    <h1>🔒 Web Application Penetration Test Report</h1>
    <p class="subtitle">{target_url}</p>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Target</div><div class="value">{target_url}</div></div>
      <div class="meta-item"><div class="label">Report Date</div><div class="value">{date_str}</div></div>
      <div class="meta-item"><div class="label">Tester</div><div class="value">{tester}</div></div>
      <div class="meta-item"><div class="label">Session ID</div><div class="value" style="font-size:0.75rem">{session_id}</div></div>
      <div class="meta-item"><div class="label">Overall Risk</div><div class="value"><span class="risk-badge">{risk_rating}</span></div></div>
    </div>
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="num" style="color:#dc2626">{sev_counts['critical']}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num" style="color:#ea580c">{sev_counts['high']}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num" style="color:#d97706">{sev_counts['medium']}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num" style="color:#65a30d">{sev_counts['low']}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num" style="color:#64748b">{total}</div><div class="lbl">Tests Run</div></div>
  </div>

  <section>
    <h2>Executive Summary</h2>
    <div class="exec-summary">
      <p>A web application penetration test was conducted against <strong>{target_url}</strong> on {date_str} by {tester}.</p>
      <p>The assessment followed the <strong>OWASP Web Security Testing Guide (WSTG) v4.2</strong> methodology, covering {total} test cases across authentication, authorization, input validation, session management, and business logic.</p>
      <p><strong>{vulns} vulnerabilities</strong> were identified: {sev_counts['critical']} Critical, {sev_counts['high']} High, {sev_counts['medium']} Medium, {sev_counts['low']} Low.</p>
      <p>Technologies detected: {', '.join(crawl_result.get('technologies', ['Unknown']))}</p>
      <p>Pages crawled: {crawl_result.get('pages_crawled', 0)} | Forms found: {len(crawl_result.get('forms', []))} | API endpoints: {len(crawl_result.get('api_endpoints', []))}</p>
    </div>
  </section>

  {'<section><h2>Vulnerabilities Found (' + str(len(findings)) + ')</h2>' + findings_html + '</section>' if findings else '<section><h2>No Vulnerabilities Found</h2><p style="color:#64748b">No vulnerabilities were identified during this assessment.</p></section>'}

  <section>
    <h2>Test Coverage ({len(checklist)} Tests)</h2>
    <div style="overflow-x:auto">
      <table class="coverage-table">
        <thead>
          <tr><th>ID</th><th>Test Name</th><th>Category</th><th>Severity</th><th>Status</th></tr>
        </thead>
        <tbody>{coverage_rows}</tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Appendix — Target Information</h2>
    <div class="exec-summary">
      <p><strong>URL:</strong> {target_url}</p>
      <p><strong>Technologies:</strong> {', '.join(crawl_result.get('technologies', ['Unknown']))}</p>
      <p><strong>Auth Endpoints:</strong> {', '.join(crawl_result.get('auth_endpoints', [])[:5]) or 'None detected'}</p>
      <p><strong>File Upload Points:</strong> {len(crawl_result.get('file_upload_points', []))}</p>
      <p><strong>JS Secrets Found:</strong> {len(crawl_result.get('js_secrets', []))}</p>
      <p><strong>Methodology:</strong> OWASP WSTG v4.2</p>
      <p><strong>Tool:</strong> AA-VAPT WebApp PT Module (local processing — zero external API calls)</p>
    </div>
  </section>

  <footer style="text-align:center;color:#334155;padding:24px 0;font-size:12px">
    Generated by AA-VAPT | {date_str} | All processing local — no data transmitted externally
  </footer>
</div>
</body>
</html>"""


def generate_json_report(session: dict, findings: list, checklist: list,
                          crawl_result: dict) -> dict:
    """Generate machine-readable JSON report."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "report_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "session": {
            "session_id": session.get("session_id"),
            "target_url": session.get("target_url"),
            "tester": session.get("tester_name"),
            "state": session.get("state"),
            "total_tests": session.get("total_tests", 0),
            "tests_completed": session.get("tests_completed", 0),
            "tests_vulnerable": session.get("tests_vulnerable", 0),
        },
        "summary": {
            "overall_risk": _compute_risk(sev_counts),
            "vulnerability_counts": sev_counts,
            "technologies": crawl_result.get("technologies", []),
            "pages_crawled": crawl_result.get("pages_crawled", 0),
            "forms_found": len(crawl_result.get("forms", [])),
            "api_endpoints": len(crawl_result.get("api_endpoints", [])),
        },
        "findings": findings,
        "test_coverage": [
            {
                "test_id": t.get("test_id"),
                "name": t.get("name"),
                "category": t.get("category"),
                "severity": t.get("severity"),
                "status": t.get("status"),
            }
            for t in checklist
        ],
        "methodology": "OWASP WSTG v4.2",
    }


def generate_markdown_report(session: dict, findings: list,
                              crawl_result: dict) -> str:
    """Generate Markdown report for easy sharing."""
    target = session.get("target_url", "Unknown")
    tester = session.get("tester_name", "Anonymous")
    date_str = datetime.now().strftime("%Y-%m-%d")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity", "low").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    lines = [
        f"# Web Application Penetration Test Report",
        f"",
        f"**Target:** {target}  ",
        f"**Date:** {date_str}  ",
        f"**Tester:** {tester}  ",
        f"**Methodology:** OWASP WSTG v4.2  ",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {sev_counts['critical']} |",
        f"| 🟠 High | {sev_counts['high']} |",
        f"| 🟡 Medium | {sev_counts['medium']} |",
        f"| 🟢 Low | {sev_counts['low']} |",
        f"",
        f"**Technologies:** {', '.join(crawl_result.get('technologies', ['Unknown']))}  ",
        f"**Pages Crawled:** {crawl_result.get('pages_crawled', 0)}  ",
        f"",
        f"## Findings",
        f"",
    ]

    if not findings:
        lines.append("No vulnerabilities identified.")
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "medium").upper()
            lines.extend([
                f"### F{i:02d}: {f.get('name', 'Unknown')} [{sev}]",
                f"",
                f"**Category:** {f.get('category', 'N/A')}  ",
                f"**OWASP:** {', '.join(f.get('owasp_top10', [])) or 'N/A'}  ",
                f"",
                f"**Description:** {f.get('notes', 'See evidence.')}",
                f"",
                f"**Evidence:**",
                f"```",
                f"{f.get('evidence', 'N/A')}",
                f"```",
                f"",
                f"**Remediation:** {f.get('remediation', 'Refer to OWASP guidelines.')}",
                f"",
                f"---",
                f"",
            ])

    return "\n".join(lines)


def _compute_risk(sev_counts: dict) -> str:
    if sev_counts.get("critical", 0) > 0:
        return "CRITICAL"
    if sev_counts.get("high", 0) > 0:
        return "HIGH"
    if sev_counts.get("medium", 0) > 0:
        return "MEDIUM"
    if sev_counts.get("low", 0) > 0:
        return "LOW"
    return "INFORMATIONAL"
