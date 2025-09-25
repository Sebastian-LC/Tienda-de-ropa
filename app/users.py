# app/users.py
import sqlite3
from .audit import log_db_action
from config import settings

def assign_role(requesting_user_id, target_user_id, role_name):
    """Asigna un rol a un usuario, validando permisos del solicitante."""
    # check requesting_user has 'admin' role
    from .auth import get_roles_for_user
    if "admin" not in get_roles_for_user(requesting_user_id):
        return False, "No autorizado."
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id FROM roles WHERE role_name = ?", (role_name,))
        row = cur.fetchone()
        if not row:
            cur.execute("INSERT INTO roles (role_name) VALUES (?)", (role_name,))
            db.commit()
            role_id = cur.lastrowid
        else:
            role_id = row[0]
        # Insert user_role (guardando duplicados)
        cur.execute("SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?", (target_user_id, role_id))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (target_user_id, role_id))
            db.commit()
        log_db_action(requesting_user_id, f"ASSIGNED ROLE {role_name} to {target_user_id}")
        return True, "Role asignado correctamente."
    finally:
        db.close()

def update_user(requesting_user_id, target_user_id, new_username, new_email):
    """Actualiza username y email de un usuario, validando permisos y unicidad."""
    from .auth import get_roles_for_user
    if "admin" not in get_roles_for_user(requesting_user_id):
        return False, "No autorizado."
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Verificar que el usuario objetivo existe
        cur.execute("SELECT id FROM users WHERE id = ?", (target_user_id,))
        if not cur.fetchone():
            return False, "Usuario no encontrado."
        # Validar unicidad de email
        cur.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, target_user_id))
        if cur.fetchone():
            return False, "El email ya está en uso."
        # Validar unicidad de username
        cur.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, target_user_id))
        if cur.fetchone():
            return False, "El username ya está en uso."
        # Actualizar usuario
        cur.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (new_username, new_email, target_user_id))
        db.commit()
        log_db_action(requesting_user_id, f"UPDATED USER {target_user_id} to username={new_username}, email={new_email}")
        return True, "Usuario actualizado correctamente."
    finally:
        db.close()

def create_user(username, email, password):
    """Crea un nuevo usuario usando la función existente en auth.py."""
    from . import auth
    return auth.create_user(username, email, password)

def delete_user(requesting_user_id, target_user_id, password_confirmation):
    """Deshabilita un usuario tras reautenticación y validaciones de dependencias."""
    # require reauthentication of requesting user (HU-10)
    from .auth import reauthenticate, get_roles_for_user
    if "admin" not in get_roles_for_user(requesting_user_id):
        return False, "No autorizado."
    if not reauthenticate(requesting_user_id, password_confirmation):
        return False, "Reautenticación fallida."
    # check dependencies: orders, other relations
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Verificar pedidos activos
        cur.execute("SELECT COUNT(1) FROM orders WHERE user_id = ? AND status != 'finalizado'", (target_user_id,))
        if cur.fetchone()[0] > 0:
            return False, "El usuario tiene pedidos activos; no se puede deshabilitar."
        # Verificar otras dependencias (ejemplo: registros en otras tablas)
        cur.execute("SELECT COUNT(1) FROM audit_log WHERE user_id = ?", (target_user_id,))
        if cur.fetchone()[0] > 0:
            return False, "El usuario tiene registros de auditoría; no se puede deshabilitar."
        # Deshabilitar usuario en vez de eliminar
        cur.execute("UPDATE users SET enabled = 0 WHERE id = ?", (target_user_id,))
        db.commit()
        log_db_action(requesting_user_id, f"DISABLED USER {target_user_id}")
        return True, "Usuario deshabilitado."
    finally:
        db.close()
