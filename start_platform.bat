@echo off
title SENTINEL-X SOC Cyber Range Launcher
echo ===============================================================
echo   SENTINEL-X: Live SOC Monitoring & Cyber Range Platform
echo ===============================================================
echo.
echo [*] Checking Python environment...
python --version
if %errorlevel% neq 0 (
    echo [!] Python was not found in PATH. Please install Python 3.10+
    pause
    exit /b 1
)

echo [*] Installing / Verifying Python dependencies...
python -m pip install -r requirements.txt --quiet

echo [*] Launching SENTINEL-X Unified Platform on http://127.0.0.1:5000 ...
start "" http://127.0.0.1:5000

cd backend
python app.py
pause
