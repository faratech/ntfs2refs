@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Request-LabHyperVAccess.ps1"
if errorlevel 1 echo Hyper-V access setup did not complete. Review the error above.
pause
