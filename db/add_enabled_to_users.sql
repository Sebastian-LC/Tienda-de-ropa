-- Migración: agregar columna 'enabled' a la tabla users
ALTER TABLE users ADD COLUMN enabled BOOLEAN DEFAULT 1;