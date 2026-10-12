#!/usr/bin/env bash
set -e

echo "===================================================================="
echo " CyberCast AI - AI-Powered Network Attack Forecasting System"
echo " Smart India Hackathon 2026 (SIH 2026) | Team South Techno (196601)"
echo "===================================================================="
echo ""

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[*] Installing / verifying dependencies from requirements.txt..."
pip install -r requirements.txt --quiet

echo "[*] Running system integrity and test suite..."
python3 tests/test_cybercast_suite.py

echo ""
echo "[*] Starting CyberCast AI Interactive Dashboard and REST API..."
echo "[*] Access the application in your browser at: http://127.0.0.1:8000"
echo "[*] Press Ctrl+C to terminate the server."
echo ""
python3 app.py
