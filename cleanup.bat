@echo off
cd /d "C:\Users\Amit Aryan\Downloads\N-PRO\AA-VAPT\AA-AGENT-V3-CHAINS"

echo Deleting unused files...

del /f /q "nessus-analyzer.html.bak" 2>nul
del /f /q "nessus-analyzer.html.bak_20260617_170216" 2>nul
del /f /q "webapp-pt.html.bak" 2>nul
del /f /q "webapp-pt.html.bak2" 2>nul
del /f /q "TAFE-WEB-extracted.xml" 2>nul
del /f /q "vapt_results_20260612_163127.txt" 2>nul
del /f /q "vapt_results_20260612_163138.txt" 2>nul
del /f /q "FABLE_AUDIT_LOG.md" 2>nul
del /f /q "FABLE_MASTER_PROMPT.md" 2>nul
del /f /q "NESSUS-ANALYZER-PROGRESS.md" 2>nul
del /f /q "UPGRADE-NOTES.md" 2>nul
del /f /q "Dockerfile" 2>nul
del /f /q "docker-compose.yml" 2>nul
del /f /q "docker-entrypoint.sh" 2>nul
del /f /q "nginx.conf" 2>nul
del /f /q "daemon.sh" 2>nul
del /f /q "run.sh" 2>nul
del /f /q "run-forever.sh" 2>nul
del /f /q "start-all.sh" 2>nul
del /f /q "START.sh" 2>nul
del /f /q "install.sh" 2>nul
del /f /q "keepalive-247.sh" 2>nul
del /f /q "DELETED_FILES_BACKUP_20260619_114229.zip" 2>nul
del /f /q "zi98fnkM" 2>nul
del /f /q "DELETED_FILES_BACKUP_20260619.zip" 2>nul

rmdir /s /q "logs" 2>nul
rmdir /s /q "backend" 2>nul
rmdir /s /q "memory" 2>nul
rmdir /s /q "_backups" 2>nul
rmdir /s /q "history" 2>nul

echo.
echo Done! Remaining files:
dir /b
echo.
pause
