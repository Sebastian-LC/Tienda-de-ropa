#!/usr/bin/env python3
"""
Comprueba el esquema de la tabla producto y lista sus columnas.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from config import settings
import sqlite3

db = sqlite3.connect(settings.DB_PATH)
cur = db.cursor()
cur.execute("PRAGMA table_info(producto)")
rows = cur.fetchall()
print('PRAGMA table_info(producto):')
for r in rows:
    print(r)

# Also show first 5 rows
print('\nSample rows:')
cur.execute('SELECT id_producto, descripcion, id_prenda, id_estilo, id_tela, talla, id_estado, created_at FROM producto ORDER BY id_producto DESC LIMIT 5')
for row in cur.fetchall():
    print(row)

db.close()
print('\nDone')
