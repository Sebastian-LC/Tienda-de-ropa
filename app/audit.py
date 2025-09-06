# app/audit.py
import sqlite3
from config import settings
from datetime import datetime
import os

def log_db_action(user_id, action):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("INSERT INTO audit_log (user_id, action) VALUES (?, ?)", (user_id, action))
        db.commit()
    finally:
        db.close()
    # Also append human-readable audit
    os.makedirs(os.path.dirname(settings.AUDIT_LOG), exist_ok=True)
    with open(settings.AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} | user:{user_id} | {action}\n")

def log_access_attempt(user_id, ip, success):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("INSERT INTO access_log (user_id, ip_address, success) VALUES (?, ?, ?)", (user_id, ip, int(bool(success))))
        db.commit()
    finally:
        db.close()
    os.makedirs(os.path.dirname(settings.ACCESS_LOG), exist_ok=True)
    with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} | ip:{ip} | user:{user_id} | success:{int(bool(success))}\n")
