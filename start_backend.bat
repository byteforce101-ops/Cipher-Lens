@echo off
echo Starting IPsec FastAPI Backend on http://127.0.0.1:8000 ...
cd /d %~dp0backend
.\venv\Scripts\python.exe main.py
pause
