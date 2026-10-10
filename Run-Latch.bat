@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-Latch.ps1"
if errorlevel 1 exit /b 1
endlocal
