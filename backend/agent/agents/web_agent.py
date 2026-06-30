# -*- coding: utf-8 -*-
"""
Web Agent 🕷️
============
Specialist in web application security.
Tools: nikto_scan, http_headers_check, check_ssl
"""
from backend.agent.agents.base_agent import BaseAgent


class WebAgent(BaseAgent):
    NAME  = "web"
    ROLE  = "Web Application Security Specialist"
    EMOJI = "🕷️"
    TOOLS = [
        {
            "name": "check_ssl",
            "description": "Deep SSL/TLS audit — ciphers, cert validity, vulnerabilities",
            "parameters": {"host": "target", "port": "443 or custom HTTPS port"},
        },
        {
            "name": "http_headers_check",
            "description": "Check HTTP security headers — CSP, HSTS, X-Frame-Options etc.",
            "parameters": {"url": "full URL e.g. http://10.0.0.1/"},
        },
        {
            "name": "nikto_scan",
            "description": "Web vulnerability scanner — finds misconfigs, outdated software, XSS, SQLi hints",
            "parameters": {"url": "full URL to scan", "timeout": "seconds (default 120)"},
        },
        {
            "name": "finish",
            "description": "Done — return web security findings",
            "parameters": {"answer": "summary of web vulnerabilities found"},
        },
    ]
