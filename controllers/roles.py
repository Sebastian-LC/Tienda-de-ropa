# app/roles.py
import sqlite3
from config import settings
from .audit import log_db_action

def request_role_change(requesting_admin_id, target_user_id, new_role):
    """Solicita un cambio de rol para un usuario, requiere administrator."""
    # requesting_admin must be administrator
    from .auth import get_roles_for_user
    if "administrator" not in get_roles_for_user(requesting_admin_id):
        return False, "No autorizado."
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("INSERT INTO maintenance (start_time, message) VALUES (?, ?)", (None, f"ROLE_REQUEST:{requesting_admin_id}:{target_user_id}:{new_role}"))
        db.commit()
        log_db_action(requesting_admin_id, f"REQUESTED ROLE CHANGE {new_role} for {target_user_id}")
        return True, "Solicitud registrada, otro administrador debe aprobar."
    finally:
        db.close()

def approve_role_change(approving_admin_id, request_id):
    """Aprueba una solicitud de cambio de rol y la aplica si es válida."""
    from .auth import get_roles_for_user
    if "administrator" not in get_roles_for_user(approving_admin_id):
        return False, "No autorizado."
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT message FROM maintenance WHERE id = ?", (request_id,))
        r = cur.fetchone()
        if not r:
            return False, "Solicitud no encontrada."
        msg = r[0]
        if not msg.startswith("ROLE_REQUEST:"):
            return False, "Solicitud inválida."
        parts = msg.split(":")
        requester_id = int(parts[1])
        target_user_id = int(parts[2])
        new_role = parts[3]
        # assign role
        from .users import assign_role
        ok, m = assign_role(approving_admin_id, target_user_id, new_role)
        if ok:
            # mark maintenance entry as processed (set start_time now)
            cur.execute("UPDATE maintenance SET start_time = datetime('now'), message = ? WHERE id = ?", (f"ROLE_REQUEST_APPROVED_BY:{approving_admin_id}:{msg}", request_id))
            db.commit()
            log_db_action(approving_admin_id, f"APPROVED ROLE CHANGE {new_role} for {target_user_id}")
            return True, "Aprobado y rol asignado."
        else:
            return False, m
    finally:
        db.close()
