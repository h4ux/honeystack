@echo off
REM Windows helper: run the PowerShell installer with the same arguments.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
