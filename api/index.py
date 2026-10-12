"""
CyberCast AI - Vercel Serverless Function Entrypoint
FastAPI ASGI Bridge for Vercel Serverless Platform
"""

import os
import sys
import shutil

# Ensure workspace root is in python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Handle serverless ephemeral storage for SQLite on Vercel
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    tmp_db = "/tmp/cybercast_vault.db"
    seed_db = os.path.join(ROOT_DIR, "cybercast_vault.db")
    if not os.path.exists(tmp_db) and os.path.exists(seed_db):
        try:
            shutil.copyfile(seed_db, tmp_db)
        except Exception:
            pass
    os.environ["CYBERCAST_DB_PATH"] = tmp_db

from app import app
