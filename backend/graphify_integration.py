"""
graphify_integration.py — Knowledge Graph builder for AA-VAPT findings.

Uses graphifyy (https://github.com/safishamsi/graphify) to convert Nessus
scan findings into a queryable knowledge graph.

Token reduction: ~71.5x vs reading raw findings files.
Extraction: Tree-sitter (code) + LLM semantic (findings/CVEs/reports).

Workflow:
  1. findings → temp markdown files
  2. graphify CLI on temp dir → graph.json + graph.html
  3. graphify query API → 71.5x-reduced token answers to analyst questions
"""

import os
import json
import logging
import asyncio
import tempfile
import subprocess
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime

log = logging.getLogger("aavapt.graphify")

# Output dir for graph artifacts
GRAPH_OUT_DIR = Path(os.environ.get("GRAPHIFY_OUT_DIR", "./graphify-out"))


# ──────────────────────────────────────────────────────────────────────────────
#  Availability check
# ──────────────────────────────────────────────────────────────────────────────

def is_graphify_available() -> bool:
    """Check if graphify CLI is installed and accessible."""
    return shutil.which("graphify") is not None


def get_graphify_version() -> Optional[str]:
    """Return installed graphify version string, or None."""
    try:
        result = subprocess.run(
            ["graphify", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  Findings → Markdown export
# ──────────────────────────────────────────────────────────────────────────────

def _finding_to_markdown(finding: dict) -> str:
    """
    Serialize a single Nessus finding dict into a markdown document that
    graphify can extract concepts/relationships from.
    """
    lines = [
        f"# {finding.get('plugin_name', 'Unknown Finding')}",
        "",
        f"**Plugin ID:** {finding.get('plugin_id', 'N/A')}  ",
        f"**Risk:** {finding.get('risk', 'N/A')}  ",
        f"**CVSS Score:** {finding.get('cvss_score', 'N/A')}  ",
        f"**Host:** {finding.get('host', 'N/A')}  ",
        f"**Port/Protocol:** {finding.get('port', 'N/A')}/{finding.get('protocol', 'N/A')}  ",
        "",
    ]

    if finding.get("synopsis"):
        lines += ["## Synopsis", "", finding["synopsis"], ""]

    if finding.get("description"):
        lines += ["## Description", "", finding["description"], ""]

    if finding.get("solution"):
        lines += ["## Solution / Remediation", "", finding["solution"], ""]

    cves = finding.get("cves", [])
    if cves:
        lines += ["## CVEs", ""]
        for cve in (cves if isinstance(cves, list) else [cves]):
            lines.append(f"- {cve}")
        lines.append("")

    if finding.get("plugin_output"):
        lines += ["## Plugin Output", "", "```", finding["plugin_output"][:2000], "```", ""]

    return "\n".join(lines)


def export_findings_to_markdown(findings: list, output_dir: Path) -> list:
    """
    Write each finding as a .md file in output_dir.
    Returns list of written file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for i, finding in enumerate(findings):
        plugin_id = finding.get("plugin_id", f"finding_{i}")
        risk = finding.get("risk", "info").lower()
        fname = f"{risk}_{plugin_id}_{i:04d}.md"
        fpath = output_dir / fname
        try:
            fpath.write_text(_finding_to_markdown(finding), encoding="utf-8")
            written.append(str(fpath))
        except Exception as e:
            log.warning("Failed to write finding %s: %s", fname, e)

    log.info("Exported %d findings as markdown to %s", len(written), output_dir)
    return written


# ──────────────────────────────────────────────────────────────────────────────
#  graphify CLI runner
# ──────────────────────────────────────────────────────────────────────────────

async def build_knowledge_graph(
    findings: list,
    scan_label: str = "scan",
    mode: str = "standard",
    extra_files: Optional[list] = None,
) -> dict:
    """
    Build a knowledge graph from VAPT findings using graphify.

    Args:
        findings:    List of finding dicts (from findings_store or Nessus parser).
        scan_label:  Label used to name the output directory (e.g. "client_scan_2024").
        mode:        "standard" or "deep" (--mode deep = more INFERRED edges).
        extra_files: Optional list of additional file paths to include in graph
                     (e.g. nessus-analyzer.html, existing reports).

    Returns:
        dict with keys: success, graph_json_path, graph_html_path,
                        report_md_path, token_reduction, stats, error
    """
    if not is_graphify_available():
        return {
            "success": False,
            "error": "graphify not installed. Run: pip install graphifyy && graphify install",
        }

    if not findings:
        return {"success": False, "error": "No findings provided to build graph from."}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = Path(tempfile.mkdtemp(prefix=f"aavapt_graph_{timestamp}_"))
    out_dir = GRAPH_OUT_DIR / f"{scan_label}_{timestamp}"

    try:
        # 1. Export findings as markdown
        md_dir = work_dir / "findings"
        export_findings_to_markdown(findings, md_dir)

        # 2. Copy any extra files (HTML reports, scripts, etc.)
        if extra_files:
            extras_dir = work_dir / "extra"
            extras_dir.mkdir(exist_ok=True)
            for fpath in extra_files:
                p = Path(fpath)
                if p.exists():
                    shutil.copy2(p, extras_dir / p.name)
                    log.info("Added extra file to graph input: %s", p.name)

        # 3. Run graphify on work_dir
        cmd = [
            "graphify", str(work_dir),
            "--output", str(out_dir),
        ]
        if mode == "deep":
            cmd += ["--mode", "deep"]

        log.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            log.error("graphify failed (rc=%d): %s", proc.returncode, stderr_str)
            return {
                "success": False,
                "error": f"graphify exited with code {proc.returncode}",
                "stderr": stderr_str[:2000],
            }

        # 4. Collect output paths
        graph_json  = out_dir / "graph.json"
        graph_html  = out_dir / "graph.html"
        report_md   = out_dir / "GRAPH_REPORT.md"

        # 5. Parse token reduction from stdout
        token_reduction = _parse_token_reduction(stdout_str)

        # 6. Parse GRAPH_REPORT.md for summary
        graph_report_summary = ""
        if report_md.exists():
            report_text = report_md.read_text(encoding="utf-8", errors="replace")
            graph_report_summary = report_text[:3000]

        result = {
            "success": True,
            "graph_json_path": str(graph_json) if graph_json.exists() else None,
            "graph_html_path": str(graph_html) if graph_html.exists() else None,
            "report_md_path": str(report_md) if report_md.exists() else None,
            "output_dir": str(out_dir),
            "token_reduction": token_reduction,
            "stats": {
                "findings_processed": len(findings),
                "extra_files": len(extra_files) if extra_files else 0,
                "mode": mode,
                "scan_label": scan_label,
                "timestamp": timestamp,
            },
            "report_summary": graph_report_summary,
            "stdout": stdout_str[:1000],
        }

        log.info(
            "Graph built: %s | token_reduction=%s | findings=%d",
            out_dir, token_reduction, len(findings)
        )
        return result

    except asyncio.TimeoutError:
        return {"success": False, "error": "graphify timed out after 300s (large scan?)"}
    except Exception as e:
        log.exception("Unexpected error in build_knowledge_graph")
        return {"success": False, "error": str(e)}
    finally:
        # Clean up temp work dir
        shutil.rmtree(work_dir, ignore_errors=True)


def _parse_token_reduction(stdout: str) -> Optional[str]:
    """Extract token reduction ratio from graphify stdout."""
    import re
    # graphify prints something like: "Token benchmark: 71.5x reduction"
    match = re.search(r"(\d+(?:\.\d+)?)[xX]\s*(?:fewer tokens|reduction|token)", stdout, re.I)
    if match:
        return f"{match.group(1)}x"
    # fallback: look for any "Nx" pattern near "token"
    match = re.search(r"token[^.]*?(\d+(?:\.\d+)?)[xX]", stdout, re.I)
    if match:
        return f"{match.group(1)}x"
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  graphify query (post-build)
# ──────────────────────────────────────────────────────────────────────────────

async def query_graph(graph_json_path: str, question: str) -> dict:
    """
    Query an existing graph.json using graphify's query command.
    Uses 71.5x fewer tokens than re-reading raw finding files.

    Args:
        graph_json_path: Path to graph.json produced by build_knowledge_graph.
        question:        Natural language question about the findings.

    Returns:
        dict with keys: success, answer, error
    """
    if not is_graphify_available():
        return {"success": False, "error": "graphify not installed."}

    if not Path(graph_json_path).exists():
        return {"success": False, "error": f"graph.json not found at: {graph_json_path}"}

    try:
        cmd = ["graphify", "query", question, "--graph", graph_json_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        if proc.returncode != 0:
            return {
                "success": False,
                "error": stderr.decode("utf-8", errors="replace")[:1000],
            }

        answer = stdout.decode("utf-8", errors="replace").strip()
        return {"success": True, "answer": answer, "question": question}

    except asyncio.TimeoutError:
        return {"success": False, "error": "graphify query timed out."}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def explain_node(graph_json_path: str, node: str) -> dict:
    """
    Run `graphify explain <node>` to get a deep explanation of a concept/CVE/host.
    """
    if not is_graphify_available():
        return {"success": False, "error": "graphify not installed."}

    try:
        cmd = ["graphify", "explain", node, "--graph", graph_json_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            return {"success": False, "error": stderr.decode("utf-8", errors="replace")[:500]}
        return {"success": True, "explanation": stdout.decode("utf-8", errors="replace").strip(), "node": node}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
#  Graph listing (for /api/graphify/list)
# ──────────────────────────────────────────────────────────────────────────────

def list_graphs() -> list:
    """
    List all built graphs in GRAPH_OUT_DIR.
    Returns list of dicts with path, label, timestamp, has_html, has_json.
    """
    if not GRAPH_OUT_DIR.exists():
        return []

    graphs = []
    for d in sorted(GRAPH_OUT_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        graph_json = d / "graph.json"
        graph_html = d / "graph.html"
        report_md  = d / "GRAPH_REPORT.md"
        graphs.append({
            "output_dir": str(d),
            "label": d.name,
            "has_json": graph_json.exists(),
            "has_html": graph_html.exists(),
            "has_report": report_md.exists(),
            "graph_json_path": str(graph_json) if graph_json.exists() else None,
            "graph_html_path": str(graph_html) if graph_html.exists() else None,
        })

    return graphs
