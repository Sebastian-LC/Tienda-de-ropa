#!/usr/bin/env python3
"""Add `talla` column to producto table if it doesn't exist."""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from config import settings
import sqlite3

db_path = settings.DB_PATH
print('DB path:', db_path)
conn = sqlite3.connect(db_path)
try:
    cur = conn.cursor()
    # Check columns
    cur.execute("PRAGMA table_info(producto)")
    cols = [r[1] for r in cur.fetchall()]
    print('producto columns:', cols)
    if 'talla' in cols:
        print('Column talla already exists. Nothing to do.')
    else:
        print('Adding column talla to producto...')
        cur.execute("ALTER TABLE producto ADD COLUMN talla TEXT")
        conn.commit()
        print('Column added.')
finally:
    conn.close()

print('Done')
