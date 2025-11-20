#!/usr/bin/env python3
"""
One-off script to delete all rows from the producto table while keeping the schema.
Usage: python tools/clear_producto.py
It will create a backup copy of the DB file before modifying it.
"""
import shutil
import os
import sys
import sqlite3

# Ensure project root is on sys.path so `from config import settings` works when
# running this script directly from the tools folder or from other CWDs.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from config import settings

DB_PATH = settings.DB_PATH
BACKUP_PATH = DB_PATH + ".backup_before_clear"

print(f"DB path: {DB_PATH}")
if not os.path.exists(DB_PATH):
    print("Database file not found. Aborting.")
    raise SystemExit(1)

# Make a backup copy
print(f"Creating backup: {BACKUP_PATH}")
shutil.copy2(DB_PATH, BACKUP_PATH)

# Connect and delete rows
conn = sqlite3.connect(DB_PATH)
try:
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = OFF;")
    # Optional: get count before
    cur.execute("SELECT COUNT(*) FROM producto;")
    before = cur.fetchone()[0]
    print(f"Rows in producto before delete: {before}")
    cur.execute("DELETE FROM producto;")
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM producto;")
    after = cur.fetchone()[0]
    print(f"Rows in producto after delete: {after}")
finally:
    conn.close()

print("Done. DB backed up and producto cleared.")