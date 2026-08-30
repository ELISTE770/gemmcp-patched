@echo off
title GemMCP Windows Bridge Server
echo ========================================================
echo     GemMCP Local Bridge Server (Port 3000)
echo ========================================================

where node >nul 2>&1
if %errorlevel% neq 0 goto no_node

cd /d "%~dp0bridge-server"

REM Ask npm what is actually missing, instead of only checking whether the
REM node_modules folder exists.
REM
REM "if exist node_modules" was the old check, and it skipped the install for
REM anyone updating an existing copy: the folder was there, but the new
REM dependencies in it were not, so the server died with "Cannot find module".
REM `npm ls` returns non-zero when anything declared in package.json is
REM missing, which covers a first install, an update, and a broken install.
echo.
echo [i] Checking dependencies...
call npm ls --depth=0 --silent >nul 2>&1
if %errorlevel% neq 0 goto install_deps
echo [i] All dependencies present.
goto run_server

:install_deps
echo [i] Installing dependencies with npm. This can take a minute...
call npm install
if %errorlevel% neq 0 goto install_failed
echo [i] Dependencies installed.

:run_server
echo.
echo [i] Starting server... Press Ctrl+C to stop.
echo.
node server.js
goto server_stopped

:no_node
echo.
echo [X] Node.js is not installed or not in PATH.
echo     Opening https://nodejs.org/ ...
start https://nodejs.org/
echo.
echo     Install Node.js (LTS), then close this window and run this file again.
pause
exit /b 1

:install_failed
echo.
echo [X] npm install failed.
echo     Check your internet connection and run this file again.
echo     If your network filters TLS, npm may need a proxy configured.
pause
exit /b 1

:server_stopped
echo.
echo [X] The server stopped (exit code %errorlevel%).
echo     Read the error above. If it says "Cannot find module", run:
echo         npm install
echo     inside the bridge-server folder, then start this file again.
pause
