#!/usr/bin/env python3
"""Script para inicializar la base de datos SQLite usando migrations.sql"""
import sqlite3, os, sys

BASE_DIR = os.path.dirname(__file__)
SQL_PATH = os.path.join(BASE_DIR, "migrations.sql")
DB_PATH = os.path.join(BASE_DIR, "database.sqlite")

if not os.path.exists(SQL_PATH):
    print("No se encontró migrations.sql en", SQL_PATH)
    sys.exit(1)

with open(SQL_PATH, "r", encoding="utf-8") as f:
    sql = f.read()

conn = sqlite3.connect(DB_PATH)
try:
    conn.executescript(sql)
    conn.commit()
    print("Base de datos creada/actualizada en:", DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cur.fetchall()]
    print("Tablas en la base de datos:", tables)
finally:
    conn.close()
