PRAGMA foreign_keys=off;
BEGIN TRANSACTION;

-- Crear nueva tabla sin las columnas a eliminar
CREATE TABLE orders_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id_usuario)
);

-- Copiar datos existentes, omitiendo las columnas eliminadas
INSERT INTO orders_new (id, user_id, created_at) SELECT id, user_id, created_at FROM orders;

-- Eliminar tabla antigua
DROP TABLE orders;

-- Renombrar nueva tabla
ALTER TABLE orders_new RENAME TO orders;

COMMIT;
PRAGMA foreign_keys=on;
