@echo off
echo ===================================================
echo   Starting IPsec VPN Analyzer (Backend + Frontend)
echo ===================================================

echo [1/2] Starting Python FastAPI Backend on port 8000...
start "IPsec Backend (Port 8000)" cmd /k "cd /d %~dp0backend && .\venv\Scripts\python.exe main.py"

echo [2/2] Starting Next.js Frontend on port 3000...
start "IPsec Frontend (Port 3000)" cmd /k "cd /d %~dp0 && npm run dev"

echo.
echo Both servers are starting!
echo Frontend: http://localhost:3000
echo Backend API: http://127.0.0.1:8000
echo Backend Docs: http://127.0.0.1:8000/docs
echo ===================================================
