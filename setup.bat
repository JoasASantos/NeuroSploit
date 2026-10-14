@echo off
REM NeuroSploit installer for Windows (CMD) — by Joas A Santos & Red Team Leaders
REM
REM   Double-click setup.bat, or run it from a terminal. It bootstraps the
REM   PowerShell installer (install.ps1), which detects the platform, installs
REM   Rust if missing, downloads or builds the binary, finds and installs
REM   dependencies (Node, Nmap, Git, typst), configures PATH + NEUROSPLOIT_BASE,
REM   and can launch NeuroSploit at the end.
REM
REM   Env (optional): NEUROSPLOIT_REF, NEUROSPLOIT_DIR, NEUROSPLOIT_BUILD=1,
REM                   NEUROSPLOIT_NO_DEPS=1, NEUROSPLOIT_RUN=1
setlocal
echo.
echo   NeuroSploit installer (Windows) v4.3.0
echo   --------------------------------------

where powershell >nul 2>&1
if errorlevel 1 (
  echo   [x] PowerShell not found. Install PowerShell, or use WSL with setup.sh.
  exit /b 1
)

REM Prefer the install.ps1 sitting next to this file; fall back to the published one.
set "PS1=%~dp0install.ps1"
if exist "%PS1%" (
  echo   Running local installer: %PS1%
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
) else (
  echo   Fetching installer from GitHub...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex"
)

set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo   [ok] Done. Open a NEW terminal, then run:  neurosploit
) else (
  echo   [x] Installer exited with code %RC%.
)
endlocal & exit /b %RC%
