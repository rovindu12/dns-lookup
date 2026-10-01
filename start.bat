@echo off
REM Starts the lookup server and opens it in your browser (Windows). Close this window to stop it.
REM   start.bat            uses port 8765
REM   set PORT=9000 & start.bat   to use another port
cd /d "%~dp0"
if not defined PORT set PORT=8765
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Install it from https://nodejs.org ^(the LTS version^), then run this again.
  pause
  exit /b 1
)
start "DNS lookup server" cmd /c "node server.js & pause"
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:%PORT%"
echo Open http://127.0.0.1:%PORT% if your browser did not open automatically.
echo The server is running in the other window; close it (or Ctrl+C there) to stop.
