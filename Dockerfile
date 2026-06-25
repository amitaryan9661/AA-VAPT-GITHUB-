# ── AA-VAPT Nessus Analyzer — Backend Image ──────────────────────
FROM python:3.11-slim

# System deps: curl (health checks inside container), gcc (some chromadb deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache — only re-runs when requirements change)
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend source
COPY backend/ ./backend/

# Create persistent-data dirs (overridden by volume mounts at runtime)
RUN mkdir -p memory/chromadb history logs

# PYTHONPATH so `from backend.xxx import` works
ENV PYTHONPATH=/app

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
