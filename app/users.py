# app/users.py
import sqlite3
from .audit import log_db_action
from config import settings

def assign_role(requesting_user_id, target_user_id, role_name):
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

def delete_user(requesting_user_id, target_user_id, password_confirmation):
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
        cur.execute("SELECT COUNT(1) FROM orders WHERE user_id = ?", (target_user_id,))
        if cur.fetchone()[0] > 0:
            return False, "El usuario tiene pedidos activos; no se puede eliminar."
        # else delete
        cur.execute("DELETE FROM user_roles WHERE user_id = ?", (target_user_id,))
        cur.execute("DELETE FROM users WHERE id = ?", (target_user_id,))
        db.commit()
        log_db_action(requesting_user_id, f"DELETED USER {target_user_id}")
        return True, "Usuario eliminado."
    finally:
        db.close()
