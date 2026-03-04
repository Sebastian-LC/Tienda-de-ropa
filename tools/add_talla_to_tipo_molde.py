#!/usr/bin/env python3
"""
Añade la columna `talla` a la tabla `tipo_molde` si no existe.
Uso: python tools/add_talla_to_tipo_molde.py
"""
import sqlite3, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from config import settings

db = sqlite3.connect(settings.DB_PATH)
cur = db.cursor()
cur.execute("PRAGMA table_info(tipo_molde)")
cols = [r[1] for r in cur.fetchall()]
if 'talla' in cols:
    print('La columna `talla` ya existe en tipo_molde.')
    db.close()
    sys.exit(0)

print('Agregando columna `talla` a tipo_molde...')
try:
    cur.execute("ALTER TABLE tipo_molde ADD COLUMN talla TEXT DEFAULT ''")
    db.commit()
    print('Columna `talla` agregada correctamente.')
except Exception as e:
    print('Error al agregar la columna:', e)
finally:
    db.close()

print('Hecho.')
