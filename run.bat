@echo off
echo ====================================================================
echo  CyberCast AI - AI-Powered Network Attack Forecasting System
echo  Smart India Hackathon 2026 (SIH 2026) ^| Team South Techno (196601)
echo ====================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo [*] Installing / verifying dependencies from requirements.txt...
pip install -r requirements.txt --quiet

echo [*] Running system integrity and test suite...
python tests\test_cybercast_suite.py

echo.
echo [*] Starting CyberCast AI Interactive Dashboard and REST API...
echo [*] Access the application in your browser at: http://127.0.0.1:8000
echo [*] Press Ctrl+C to terminate the server.
echo.
python app.py
pause
