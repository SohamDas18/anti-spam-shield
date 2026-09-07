@echo off
title Spam Sentinel AI - Live Public Website
cd /d "%~dp0"
echo ======================================================================
echo    Spam Mail & SMS Cyber Threat Detection - Public Website Launcher
echo ======================================================================
echo.
echo [1/2] Starting Flask Backend Server on http://127.0.0.1:5000...
start "Flask Server" /b python app.py
timeout /t 3 /nobreak >nul

echo [2/2] Launching Secure Public HTTPS Cloudflare Tunnel...
echo.
echo Look for the public HTTPS link below (e.g., https://xxxx.trycloudflare.com):
echo ======================================================================
.\cloudflared.exe tunnel --url http://127.0.0.1:5000
pause
