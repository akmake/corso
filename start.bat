@echo off
title WEBINT Platform

echo.
echo  ==========================================
echo   WEBINT  --  OSINT Platform Launcher
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+
    pause & exit /b 1
)

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install Node.js
    pause & exit /b 1
)

:: Install Python deps if needed
echo [1/3] Checking Python dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo       Installing...
    pip install -r python\requirements.txt
    if errorlevel 1 ( echo [ERROR] pip install failed & pause & exit /b 1 )
) else (
    echo       OK
)

:: Install Node deps if needed
echo [2/3] Checking Node dependencies...
if not exist "client\node_modules" (
    echo       Running npm install...
    cd client && npm install && cd ..
    if errorlevel 1 ( echo [ERROR] npm install failed & pause & exit /b 1 )
) else (
    echo       OK
)

:: Launch servers
echo [3/3] Starting servers...
echo.
echo  API  : http://localhost:8000
echo  Docs : http://localhost:8000/docs
echo  UI   : http://localhost:5173
echo.

start "WEBINT API" cmd /k "cd /d %~dp0python && python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
timeout /t 2 /nobreak >nul
start "WEBINT UI" cmd /k "cd /d %~dp0client && npm run dev"
timeout /t 4 /nobreak >nul
start "" "http://localhost:5173"

echo  Done. Close the server windows to stop.
pause
