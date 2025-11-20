#!/usr/bin/env python3
"""
Inspecciona la tabla producto y realiza JOINs con prenda/tipo_prenda, estilo/tipo_estilo, tela/tipo_tela, molde/tipo_molde
Imprime filas para entender por qué algunos campos quedan N/A en Informes.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from config import settings
import sqlite3

db = sqlite3.connect(settings.DB_PATH)
cur = db.cursor()

print('Productos (id_producto, id_prenda, id_estilo, id_molde, id_tela, id_cliente, id_estado, descripcion, created_at):')
cur.execute('SELECT id_producto, id_prenda, id_estilo, id_molde, id_tela, id_cliente, id_estado, descripcion, created_at FROM producto ORDER BY id_producto DESC')
rows = cur.fetchall()
for r in rows:
    print(r)

print('\nAttempt JOINs (producto -> prenda, tipo_prenda, estilo, tipo_estilo, tela, tipo_tela, molde, tipo_molde):')
for r in rows:
    pid, id_prenda, id_estilo, id_molde, id_tela, id_cliente, id_estado, desc, created_at = r
    # lookup prenda
    prenda_name = None
    tipo_prenda_name = None
    try:
        if id_prenda:
            cur.execute('SELECT nombre FROM prenda WHERE id_prenda = ?', (id_prenda,))
            row = cur.fetchone()
            if row:
                prenda_name = row[0]
            # also check tipo_prenda
            cur.execute('SELECT nombre FROM tipo_prenda WHERE id_tipo_prenda = ?', (id_prenda,))
            row = cur.fetchone()
            if row:
                tipo_prenda_name = row[0]
    except Exception as e:
        prenda_name = f'ERR:{e}'
    # estilo
    estilo_name = None
    tipo_estilo_name = None
    try:
        if id_estilo:
            cur.execute('SELECT nombre FROM estilo WHERE id_estilo = ?', (id_estilo,))
            row = cur.fetchone()
            if row:
                estilo_name = row[0]
            cur.execute('SELECT nombre FROM tipo_estilo WHERE id_tipo_estilo = ?', (id_estilo,))
            row = cur.fetchone()
            if row:
                tipo_estilo_name = row[0]
    except Exception as e:
        estilo_name = f'ERR:{e}'
    # tela
    tela_name = None
    tipo_tela_name = None
    try:
        if id_tela:
            cur.execute('SELECT nombre FROM tela WHERE id_tela = ?', (id_tela,))
            row = cur.fetchone()
            if row:
                tela_name = row[0]
            cur.execute('SELECT nombre FROM tipo_tela WHERE id_tipo_tela = ?', (id_tela,))
            row = cur.fetchone()
            if row:
                tipo_tela_name = row[0]
    except Exception as e:
        tela_name = f'ERR:{e}'
    # molde
    molde_name = None
    tipo_molde_name = None
    try:
        if id_molde:
            cur.execute('SELECT nombre FROM molde WHERE id_molde = ?', (id_molde,))
            row = cur.fetchone()
            if row:
                molde_name = row[0]
            cur.execute('SELECT nombre FROM tipo_molde WHERE id_tipo_molde = ?', (id_molde,))
            row = cur.fetchone()
            if row:
                tipo_molde_name = row[0]
    except Exception as e:
        molde_name = f'ERR:{e}'

    print(f'producto id={pid} prenda(id={id_prenda})->prenda:"{prenda_name}" tipo_prenda:"{tipo_prenda_name}" | estilo(id={id_estilo})->estilo:"{estilo_name}" tipo_estilo:"{tipo_estilo_name}" | tela(id={id_tela})->tela:"{tela_name}" tipo_tela:"{tipo_tela_name}" | molde(id={id_molde})->molde:"{molde_name}" tipo_molde:"{tipo_molde_name}" desc:"{desc}" created_at:{created_at}')

db.close()
print('\nDone')
