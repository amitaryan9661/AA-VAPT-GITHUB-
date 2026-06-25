#!/usr/bin/env bash
set -e

OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"

echo "[+] Waiting for Ollama at ${OLLAMA_HOST}..."
until curl -sf "${OLLAMA_HOST}/api/tags" > /dev/null 2>&1; do
  echo "[~] Ollama not ready yet — retrying in 3s..."
  sleep 3
done
echo "[+] Ollama is up"

# Pull a model if none installed
MODEL_COUNT=$(curl -sf "${OLLAMA_HOST}/api/tags" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('models',[])))" 2>/dev/null || echo "0")

if [[ "${MODEL_COUNT}" -lt 1 ]]; then
  echo "[+] No models found — pulling deepseek-r1:1.5b (fast, ~1GB)..."
  curl -sf -X POST "${OLLAMA_HOST}/api/pull" \
    -H "Content-Type: application/json" \
    -d '{"name":"deepseek-r1:1.5b","stream":false}' > /dev/null
  echo "[+] Model ready"
else
  echo "[+] Model already installed (${MODEL_COUNT} model(s))"
fi

echo "[+] Starting FastAPI backend..."
exec python3 -m uvicorn backend.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --log-level info
