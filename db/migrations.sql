-- ========================
-- Tablas de seguridad (HU)
-- ========================

CREATE TABLE users (
    id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    correo TEXT,
    contraseña TEXT,
    rol TEXT,
    failed_attempts INTEGER,
    blocked INTEGER,
    enabled INTEGER,
    blocked_until BOOLEAN
);

CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id INTEGER,
    role_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id_usuario),
    FOREIGN KEY(role_id) REFERENCES roles(id)
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id_usuario)
);

CREATE TABLE access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address TEXT,
    success BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id_usuario)
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
    FOREIGN KEY(user_id) REFERENCES users(id_usuario),
    FOREIGN KEY(garment_id) REFERENCES garments(id)
);

-- ========================
-- Nuevas tablas de negocio
-- ========================

CREATE TABLE estados (
    id_estado INTEGER PRIMARY KEY AUTOINCREMENT,
    descripcion TEXT
);

CREATE TABLE tipo_documento (
    id_tipo_documento INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    Number INTEGER
);

INSERT INTO tipo_documento (nombre, Number) VALUES ('CC - Cédula de Ciudadanía', 1);
INSERT INTO tipo_documento (nombre, Number) VALUES ('CE - Cédula de Extranjería', 2);
INSERT INTO tipo_documento (nombre, Number) VALUES ('TI - Tarjeta de Identidad', 3);
INSERT INTO tipo_documento (nombre, Number) VALUES ('PA - Pasaporte', 4);

CREATE TABLE usuario (
    id_cliente INTEGER PRIMARY KEY AUTOINCREMENT,
    id_usuario INTEGER,
    nombre1 TEXT,
    nombre2 TEXT,
    apellido1 TEXT,
    apellido2 TEXT,
    direccion TEXT,
    telefono1 TEXT,
    telefono2 TEXT,
    id_tipo_documento INTEGER,
    FOREIGN KEY(id_usuario) REFERENCES users(id_usuario),
    FOREIGN KEY(id_tipo_documento) REFERENCES tipo_documento(id_tipo_documento)
);

CREATE TABLE tipo_prenda (
    id_tipo_prenda INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT
);

CREATE TABLE tipo_tela (
    id_tipo_tela INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT
);

CREATE TABLE tipo_molde (
    id_tipo_molde INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT
);

CREATE TABLE tipo_estilo (
    id_tipo_estilo INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT
);

CREATE TABLE prenda (
    id_prenda INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT,
    id_tipo_prenda INTEGER,
    FOREIGN KEY(id_tipo_prenda) REFERENCES tipo_prenda(id_tipo_prenda)
);

CREATE TABLE molde (
    id_molde INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT,
    id_tipo_molde INTEGER,
    FOREIGN KEY(id_tipo_molde) REFERENCES tipo_molde(id_tipo_molde)
);

CREATE TABLE tela (
    id_tela INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT,
    id_tipo_tela INTEGER,
    FOREIGN KEY(id_tipo_tela) REFERENCES tipo_tela(id_tipo_tela)
);

CREATE TABLE estilo (
    id_estilo INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    descripcion TEXT,
    id_tipo_estilo INTEGER,
    FOREIGN KEY(id_tipo_estilo) REFERENCES tipo_estilo(id_tipo_estilo)
);

CREATE TABLE producto (
    id_producto INTEGER PRIMARY KEY AUTOINCREMENT,
    descripcion TEXT,
    id_prenda INTEGER,
    id_estilo INTEGER,
    id_molde INTEGER,
    id_tela INTEGER,
    id_cliente INTEGER,
    id_estado INTEGER,
    FOREIGN KEY(id_prenda) REFERENCES prenda(id_prenda),
    FOREIGN KEY(id_estilo) REFERENCES estilo(id_estilo),
    FOREIGN KEY(id_molde) REFERENCES molde(id_molde),
    FOREIGN KEY(id_tela) REFERENCES tela(id_tela),
    FOREIGN KEY(id_cliente) REFERENCES usuario(id_cliente),
    FOREIGN KEY(id_estado) REFERENCES estados(id_estado)
);
