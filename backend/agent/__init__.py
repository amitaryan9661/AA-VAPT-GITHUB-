# -*- coding: utf-8 -*-
"""
AA-VAPT Agent System
====================
Full autonomous AI agent for penetration testing.

Architecture:
  NaturalLanguage → Planner → ReAct Loop → Tools → Observations → Response

Components:
  tool_registry   — All tools the agent can call
  kali_tools      — Real Kali Linux tool runners (nmap, testssl, nikto, etc.)
  react_loop      — Reason → Act → Observe → Repeat engine
  planner         — Natural language → structured goal → task DAG
  memory          — Episodic + semantic memory (ChromaDB backed)
  hitl            — Human-in-the-loop approval for dangerous actions
  agents/         — Specialized sub-agents (Recon, Vuln, WebPT, Report)
  router          — FastAPI routes for /api/agent/*
"""
