#!/usr/bin/env bash
set -e
PROJ="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJ"
exec "$PROJ/.venv/bin/python3" -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
