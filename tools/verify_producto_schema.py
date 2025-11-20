import sys
sys.path.append(r'D:\cambio\Tienda-de-rop')
from config import settings
import sqlite3

def show():
    db = sqlite3.connect(settings.DB_PATH)
    cur = db.cursor()
    cur.execute("PRAGMA table_info(producto)")
    for r in cur.fetchall():
        print(r)
    db.close()

if __name__ == '__main__':
    show()
