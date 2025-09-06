-- ========================
-- Tablas de seguridad (HU)
-- ========================

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    blocked BOOLEAN DEFAULT 0
);

CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id INTEGER,
    role_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address TEXT,
    success BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE maintenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time DATETIME,
    end_time DATETIME,
    message TEXT
);

-- ========================
-- Tablas de negocio (Ropa)
-- ========================

CREATE TABLE fabrics ( -- tipos de tela
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE colors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    hex_code TEXT
);

CREATE TABLE patterns ( -- estampados
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE garments ( -- prendas
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    fabric_id INTEGER,
    color_id INTEGER,
    pattern_id INTEGER,
    FOREIGN KEY(fabric_id) REFERENCES fabrics(id),
    FOREIGN KEY(color_id) REFERENCES colors(id),
    FOREIGN KEY(pattern_id) REFERENCES patterns(id)
);

CREATE TABLE orders ( -- pedidos de ropa personalizada
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    garment_id INTEGER,
    size TEXT,
    quantity INTEGER,
    status TEXT DEFAULT 'pendiente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(garment_id) REFERENCES garments(id)
);
