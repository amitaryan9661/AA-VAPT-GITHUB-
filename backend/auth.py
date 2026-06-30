# -*- coding: utf-8 -*-
"""
AA-VAPT — API Authentication (ENH-01)
======================================
Simple API-key based authentication via X-API-Key header or ?api_key= query param.

Configuration:
  Set  AAVAPT_API_KEY  environment variable to enable authentication.
  If not set, authentication is DISABLED (dev mode — backward compatible).

Usage in endpoints:
  from backend.auth import require_auth
  @app.get("/api/something")
  async def something(auth: None = Depends(require_auth)):
      ...

Exempted routes (no auth needed):
  /health, /ws, /ws/terminal, /api/status
"""
import os
import logging
from fastapi import Header, HTTPException, Query, Depends
from fastapi.security import APIKeyHeader, APIKeyQuery

log = logging.getLogger("aavapt.auth")

_API_KEY = os.environ.get("AAVAPT_API_KEY", "").strip()
_AUTH_ENABLED = bool(_API_KEY)

if _AUTH_ENABLED:
    log.info("API key authentication ENABLED")
else:
    log.info("API key authentication DISABLED (set AAVAPT_API_KEY env var to enable)")

_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_key_query  = APIKeyQuery(name="api_key",    auto_error=False)

# Routes that bypass auth entirely
_EXEMPT_PATHS = {"/health", "/ws", "/ws/terminal", "/api/status", "/docs", "/openapi.json"}


async def require_auth(
    header_key: str = Depends(_key_header),
    query_key:  str = Depends(_key_query),
):
    """FastAPI dependency — call Depends(require_auth) to protect an endpoint."""
    if not _AUTH_ENABLED:
        return None   # dev mode: no auth required

    provided = header_key or query_key
    if not provided:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Pass X-API-Key header or ?api_key= query param.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if provided != _API_KEY:
        log.warning("Invalid API key attempt")
        raise HTTPException(status_code=403, detail="Invalid API key.")
    return True


def auth_status() -> dict:
    """Return current auth config (for /api/status endpoint)."""
    return {
        "enabled": _AUTH_ENABLED,
        "method": "X-API-Key header or ?api_key= query param" if _AUTH_ENABLED else "none",
        "note": "Set AAVAPT_API_KEY env var to enable" if not _AUTH_ENABLED else "",
    }
