@echo off
REM Purpose: fixed Windows YARA launcher; owner [ASTRA]; updated 2026-09-09.
REM Status: native validation pending; source: Wazuh 4.14 AR / T-15.
REM Build soc-yara.exe from yara.py and deploy beside this launcher.
REM Never interpolate JSON into cmd.exe or PowerShell; stdin goes untouched.
setlocal DisableDelayedExpansion
"%~dp0soc-yara.exe"
exit /b %errorlevel%
