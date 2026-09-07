@echo off
title Upload to GitHub
echo Uploading project to GitHub...
cd /d "%~dp0"
git init
git add .
git commit -m "Anti-Spam Threat System with Geo Map and Bilingual Support"
git branch -M main
git remote remove origin 2>nul
git remote add origin https://github.com/SohamDas18/anti-spam-shield.git
git push -u origin main --force
echo.
echo Upload complete! Check https://github.com/SohamDas18/anti-spam-shield
pause
