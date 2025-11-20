import sqlite3
from config import settings

DB = settings.DB_PATH

def ensure_id_talla():
    db = sqlite3.connect(DB)
    try:
        cur = db.cursor()
        cur.execute("PRAGMA table_info(producto)")
        cols = [r[1] for r in cur.fetchall()]
        if 'id_talla' in cols:
            print('id_talla already present in producto')
            return
        # Add column as TEXT to accommodate both numeric ids or string sizes
        try:
            cur.execute("ALTER TABLE producto ADD COLUMN id_talla TEXT")
            db.commit()
            print('Added id_talla column to producto')
        except Exception as e:
            print('Failed to add id_talla column:', e)
    finally:
        db.close()

if __name__ == '__main__':
    ensure_id_talla()
