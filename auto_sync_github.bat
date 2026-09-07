@echo off
setlocal enabledelayedexpansion
title GitHub Auto-Sync Watcher
cd /d "%~dp0"

echo ======================================================
echo    GitHub Auto-Sync Watcher for Anti-Spam Shield
echo ======================================================
echo Target Repo: https://github.com/SohamDas18/anti-spam-shield
echo Branch     : main
echo Status     : Monitoring folder for any saved changes...
echo.
echo (Keep this window open or minimized while coding.
echo  Press Ctrl+C at any time to pause/stop auto-sync.)
echo ======================================================
echo.

:loop
set "CHANGES="
for /f "delims=" %%i in ('git status --porcelain 2^>nul') do (
    set "CHANGES=1"
    goto :has_changes
)

:: No changes detected, wait 15 seconds
timeout /t 15 /nobreak >nul
goto :loop

:has_changes
for /f "tokens=*" %%a in ('powershell -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set TIMESTAMP=%%a

echo ======================================================
echo [%TIMESTAMP%] Changes detected in files!
echo ======================================================

echo [1/3] Staging all modified and new files...
git add -A

echo [2/3] Creating commit...
git commit -m "Auto-update: %TIMESTAMP%"

echo [3/3] Pushing to GitHub (origin main)...
git push origin main

if %errorlevel% equ 0 (
    echo.
    echo ======================================================
    echo [%TIMESTAMP%] SUCCESS: Changes pushed to GitHub!
    echo ======================================================
) else (
    echo.
    echo [WARNING] Push failed (Internet disconnected or conflict).
    echo Retrying in next cycle...
)

echo.
echo Resuming watcher (checking every 15 seconds)...
timeout /t 15 /nobreak >nul
goto :loop
