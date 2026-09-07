@echo off
title Stop GitHub Auto-Sync
echo Stopping all running GitHub Auto-Sync instances...
taskkill /fi "WINDOWTITLE eq GitHub Auto-Sync Watcher*" /f >nul 2>&1
taskkill /im cmd.exe /fi "WINDOWTITLE eq GitHub Auto-Sync Watcher*" /f >nul 2>&1
echo.
echo GitHub Auto-Sync has been stopped.
timeout /t 3 >nul
