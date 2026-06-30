@echo off
title AA-VAPT Agent Launcher
color 0A

echo.
echo  ========================================
echo   AA-VAPT AI Agent - Starting All Services
echo  ========================================
echo.

:: ── Check Python ─────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+
    pause & exit /b 1
)

:: ── Check Ollama ─────────────────────────────────────────────
where ollama >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama not found - AI features will be limited.
    echo        Install from: https://ollama.ai
) else (
    echo [1/3] Starting Ollama...
    tasklist /FI "IMAGENAME eq ollama.exe" 2>nul | find /I "ollama.exe" >nul
    if errorlevel 1 (
        start /B "" ollama serve >nul 2>&1
        timeout /t 3 /nobreak >nul
        echo       Ollama started.
    ) else (
        echo       Ollama already running.
    )
)

:: ── Install dependencies (first run) ─────────────────────────
echo [2/3] Checking dependencies...
if not exist ".deps_installed" (
    echo       Installing Python packages...
    pip install -r backend\requirements.txt -q --break-system-packages 2>nul
    if not errorlevel 1 echo. > .deps_installed
)

:: ── Start Backend ─────────────────────────────────────────────
echo [3/3] Starting AA-VAPT Backend on http://localhost:8000
echo.
echo  Agent UI  : http://localhost:8000/agent.html
echo  Main UI   : http://localhost:8000/index.html
echo  API Docs  : http://localhost:8000/docs
echo  Status    : http://localhost:8000/api/status
echo.
echo  Press Ctrl+C to stop.
echo  ========================================
echo.

:: Open browser after 3s
start /B "" cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8000/agent.html"

:: Run uvicorn
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

pause
