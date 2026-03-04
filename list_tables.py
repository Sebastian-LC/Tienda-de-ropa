import sqlite3

conn = sqlite3.connect('db/database.sqlite')
cur = conn.cursor()
cur.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = [r[0] for r in cur.fetchall()]
print(tables)
conn.close()
