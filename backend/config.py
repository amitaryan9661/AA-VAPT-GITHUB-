"""AA-VAPT Nessus Analyzer — Backend Config"""
import os

# Ollama settings
OLLAMA_HOST        = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL       = os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")
OLLAMA_MODEL_SMALL = os.getenv("OLLAMA_MODEL_SMALL", "deepseek-r1:1.5b")  # fallback

# ChromaDB settings
CHROMA_PERSIST_DIR = os.getenv("CHROMA_DIR", "./memory/chromadb")
CHROMA_COLLECTION  = "nessus_findings"

# API settings
API_HOST = "0.0.0.0"
API_PORT = 8000
FRONTEND_PORT = 8181

# MCP settings
MCP_SERVER_NAME    = "aa-vapt-nessus"
MCP_SERVER_VERSION = "1.0.0"
