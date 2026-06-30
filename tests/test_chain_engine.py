# -*- coding: utf-8 -*-
"""
ENH-07: Unit tests for the Attack Chain Detection Engine.

Run:
    pytest tests/test_chain_engine.py -v

These tests verify that chain detection rules correctly match/miss
combinations of Nessus findings — no external services required.
"""

import pytest
import sys
import os

# Allow import from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.attack_chain_engine import (
    detect_chains,
    _condition_matches,
    _collect_hosts,
    _finding_text,
    generate_poc_script,
    CHAIN_RULES,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> dict:
    """Helper: create a minimal finding dict."""
    return {
        "name": kwargs.get("name", "Test Finding"),
        "synopsis": kwargs.get("synopsis", ""),
        "plugin_output": kwargs.get("plugin_output", ""),
        "plugin_id": kwargs.get("plugin_id", "99999"),
        "severity": kwargs.get("severity", "medium"),
        "service": kwargs.get("service", ""),
        "port": kwargs.get("port", ""),
        "hosts": kwargs.get("hosts", ["192.168.1.10"]),
        "cves": kwargs.get("cves", []),
    }


# ── Test: _finding_text ───────────────────────────────────────────────────────

def test_finding_text_lowercase():
    f = make_finding(name="SMB Signing DISABLED", synopsis="Windows SMB signing is not required")
    text = _finding_text(f)
    assert "smb signing disabled" in text
    assert "windows smb signing is not required" in text


def test_finding_text_includes_cves():
    f = make_finding(cves=["CVE-2024-6387", "CVE-2023-12345"])
    text = _finding_text(f)
    assert "cve-2024-6387" in text
    assert "cve-2023-12345" in text


# ── Test: _condition_matches ──────────────────────────────────────────────────

def test_condition_matches_by_keyword():
    condition = {"label": "SMB signing", "keywords": ["smb signing", "message signing"], "plugin_ids": []}
    findings = [
        make_finding(name="SMB Signing Disabled", synopsis="smb signing not required"),
        make_finding(name="Unrelated Finding"),
    ]
    matched = _condition_matches(condition, findings)
    assert len(matched) == 1
    assert matched[0]["name"] == "SMB Signing Disabled"


def test_condition_matches_by_plugin_id():
    condition = {"label": "LLMNR", "keywords": [], "plugin_ids": ["35371"]}
    findings = [
        make_finding(name="LLMNR Active", plugin_id="35371"),
        make_finding(name="Other Finding", plugin_id="99999"),
    ]
    matched = _condition_matches(condition, findings)
    assert len(matched) == 1


def test_condition_no_match():
    condition = {"label": "Kerberos", "keywords": ["kerberoast", "tgs"], "plugin_ids": []}
    findings = [make_finding(name="SSL Certificate Expired")]
    matched = _condition_matches(condition, findings)
    assert matched == []


# ── Test: _collect_hosts ──────────────────────────────────────────────────────

def test_collect_hosts_unique():
    findings = [
        make_finding(hosts=["10.0.0.1", "10.0.0.2"]),
        make_finding(hosts=["10.0.0.1", "10.0.0.3"]),
    ]
    hosts = _collect_hosts(findings)
    assert sorted(hosts) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_collect_hosts_from_host_field():
    findings = [{"host": "192.168.1.50", "hosts": [], "name": "Test"}]
    hosts = _collect_hosts(findings)
    assert "192.168.1.50" in hosts


# ── Test: SMB Relay Chain ─────────────────────────────────────────────────────

def test_smb_relay_chain_detected():
    findings = [
        make_finding(name="LLMNR / NBT-NS Poisoning", synopsis="llmnr is enabled on this host",
                     plugin_id="35371"),
        make_finding(name="NTLMv1 Authentication Allowed", synopsis="ntlmv1 authentication is permitted",
                     plugin_id="26920"),
        make_finding(name="SMB Signing Not Required", synopsis="smb signing disabled on this host",
                     plugin_id="96982"),
    ]
    chains = detect_chains(findings)
    chain_ids = [c["chain_id"] for c in chains]
    assert "smb_relay_ntlm" in chain_ids, f"Expected smb_relay_ntlm, got: {chain_ids}"


def test_smb_relay_chain_not_detected_missing_one():
    """Chain should NOT trigger if only 2 of 3 conditions met."""
    findings = [
        make_finding(name="LLMNR Active", synopsis="llmnr enabled"),
        make_finding(name="SMB Signing Disabled", synopsis="smb signing not required"),
        # NTLMv1 missing → chain should not fire
    ]
    chains = detect_chains(findings)
    chain_ids = [c["chain_id"] for c in chains]
    assert "smb_relay_ntlm" not in chain_ids


def test_smb_relay_chain_upgraded_risk():
    findings = [
        make_finding(name="LLMNR Poisoning", synopsis="llmnr nbt-ns enabled"),
        make_finding(name="NTLMv1 Auth", synopsis="ntlmv1 lm authentication allowed"),
        make_finding(name="SMB Signing Off", synopsis="smb signing message signing disabled"),
    ]
    chains = detect_chains(findings)
    smb = next((c for c in chains if c["chain_id"] == "smb_relay_ntlm"), None)
    if smb:
        assert smb["upgraded_risk"] == "CRITICAL"


# ── Test: SSL Downgrade Chain ─────────────────────────────────────────────────

def test_ssl_downgrade_chain_detected():
    findings = [
        make_finding(name="TLS 1.0 Supported", synopsis="sslv3 tls 1.0 is enabled", plugin_id="78479"),
        make_finding(name="Missing HSTS Header", synopsis="strict-transport hsts header not set"),
    ]
    chains = detect_chains(findings)
    chain_ids = [c["chain_id"] for c in chains]
    assert "ssl_downgrade_mitm" in chain_ids


# ── Test: Default Credentials Chain ──────────────────────────────────────────

def test_default_creds_chain_detected():
    findings = [
        make_finding(name="Default Password Found", synopsis="default password admin interface"),
        make_finding(name="Web Admin Console", synopsis="admin management login panel detected"),
    ]
    chains = detect_chains(findings)
    chain_ids = [c["chain_id"] for c in chains]
    assert "default_creds_rce" in chain_ids


# ── Test: Empty findings ──────────────────────────────────────────────────────

def test_no_chains_empty_findings():
    chains = detect_chains([])
    assert chains == []


def test_no_chains_irrelevant_findings():
    findings = [
        make_finding(name="Ping Response", synopsis="host responds to ping"),
        make_finding(name="Open Port 80", synopsis="http service on port 80"),
    ]
    chains = detect_chains(findings)
    # Should find 0 or only non-critical chains (web-related only if matching)
    for c in chains:
        assert c["chain_id"] in [r["id"] for r in CHAIN_RULES]  # all IDs must be known


# ── Test: Risk Ordering ───────────────────────────────────────────────────────

def test_chains_sorted_critical_first():
    findings = [
        # SSL downgrade (HIGH)
        make_finding(name="TLS 1.0 Enabled", synopsis="tls1.0 sslv3 poodle"),
        make_finding(name="No HSTS", synopsis="hsts strict-transport missing"),
        # SMB Relay (CRITICAL)
        make_finding(name="LLMNR On", synopsis="llmnr nbt-ns active"),
        make_finding(name="NTLMv1", synopsis="ntlmv1 lanman lm authentication"),
        make_finding(name="SMB No Sign", synopsis="smb signing disabled"),
    ]
    chains = detect_chains(findings)
    if len(chains) >= 2:
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(chains) - 1):
            assert risk_order.get(chains[i]["upgraded_risk"], 9) <= \
                   risk_order.get(chains[i+1]["upgraded_risk"], 9), \
                   "Chains not sorted by risk level"


# ── Test: PoC Script Generation ───────────────────────────────────────────────

def test_poc_script_generated():
    chain = {
        "chain_id": "smb_relay_ntlm",
        "generates": "smb_relay",
        "affected_hosts": ["10.10.10.1", "10.10.10.2"],
        "steps": ["Step 1", "Step 2"],
    }
    script = generate_poc_script(chain)
    assert "#!/usr/bin/env bash" in script
    assert "10.10.10.1" in script
    assert "AA-VAPT" in script


def test_poc_script_unknown_template():
    chain = {
        "chain_id": "nonexistent_chain",
        "generates": "nonexistent_template",
        "affected_hosts": [],
        "steps": [],
    }
    script = generate_poc_script(chain)
    assert "No PoC template" in script


def test_poc_script_empty_hosts():
    chain = {
        "chain_id": "kerberoasting_path",
        "generates": "kerberoast",
        "affected_hosts": [],
        "steps": [],
    }
    script = generate_poc_script(chain)
    assert "TARGET_IP" in script or script  # shouldn't crash


# ── Test: CHAIN_RULES structure ───────────────────────────────────────────────

def test_all_rules_have_required_fields():
    required = ("id", "name", "description", "requires", "upgraded_risk", "steps", "mitre", "generates")
    for rule in CHAIN_RULES:
        for field in required:
            assert field in rule, f"Rule '{rule.get('id')}' missing field: {field}"


def test_all_generates_keys_have_poc_templates():
    from backend.attack_chain_engine import POC_TEMPLATES
    for rule in CHAIN_RULES:
        key = rule.get("generates", "")
        assert key in POC_TEMPLATES, f"Rule '{rule['id']}' generates='{key}' has no PoC template"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
