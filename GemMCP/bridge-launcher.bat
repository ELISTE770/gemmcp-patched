@echo off
setlocal enabledelayedexpansion

REM The script's own folder is always correct and needs no decoding, so it is
REM tried first. The cached path is only a fallback for when this .bat is
REM invoked from somewhere else - and `set /p` reads it using the console
REM codepage, which mangles any non-ASCII path, so it must not be preferred.
set "TARGET_DIR="

if exist "%~dp0bridge-server\server.js" (
    set "TARGET_DIR=%~dp0"
) else (
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0find-and-start.ps1"
    set "LAST_PATH_FILE=%LOCALAPPDATA%\GemMCP\last_path.txt"
    if exist "%LAST_PATH_FILE%" (
        set /p TARGET_DIR=<"%LAST_PATH_FILE%"
    )
)

if "!TARGET_DIR!"=="" (
    set "TARGET_DIR=%~dp0"
)

where node >nul 2>&1
if %errorlevel% neq 0 (
    start https://nodejs.org/
    exit /b 1
)

cd /d "!TARGET_DIR!\bridge-server"

REM `npm ls` reports what is missing, not merely whether node_modules exists.
REM The old "if not exist node_modules" check skipped the install for anyone
REM updating an existing copy: the folder was present but the new dependencies
REM were not, and the server died with "Cannot find module" on startup - here,
REM where it starts hidden, with nobody to read the error.
call npm ls --depth=0 --silent >nul 2>&1
if %errorlevel% neq 0 (
    call npm install
)

netstat -ano | findstr ":3000 " | findstr "LISTENING" >nul
if %errorlevel% neq 0 (
    node server.js
)
