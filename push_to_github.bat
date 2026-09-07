@echo off
setlocal enabledelayedexpansion
title Push to GitHub
cd /d "%~dp0"

echo ======================================================
echo           Push Project to GitHub
echo ======================================================
echo Target Repo: https://github.com/SohamDas18/anti-spam-shield
echo Branch     : main
echo ======================================================
echo.

git status -s
echo.

for /f "delims=" %%i in ('git status --porcelain 2^>nul') do (
    goto :has_changes
)

echo No changes detected! Your repository is already up to date with GitHub.
echo.
pause
exit /b 0

:has_changes
set "MSG="
set /p "MSG=Enter commit message (Press Enter for auto-timestamp): "

if "!MSG!"=="" (
    for /f "tokens=*" %%a in ('powershell -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set TIMESTAMP=%%a
    set "MSG=Update: !TIMESTAMP!"
)

echo.
echo [1/3] Staging changes...
git add -A

echo [2/3] Committing changes with message: "!MSG!"
git commit -m "!MSG!"

echo [3/3] Pushing to origin main...
git push origin main

if %errorlevel% equ 0 (
    echo.
    echo ======================================================
    echo  SUCCESS: Successfully uploaded to GitHub!
    echo  URL: https://github.com/SohamDas18/anti-spam-shield
    echo ======================================================
) else (
    echo.
    echo [ERROR] Push failed. Please check your internet connection or git permissions.
)

echo.
pause
