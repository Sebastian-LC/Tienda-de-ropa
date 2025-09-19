# app/auth.py
import sqlite3
import time
from datetime import datetime, timedelta
from config import settings
from .utils import gen_salt, hash_password, verify_password, gen_2fa_code, send_email, now
from .validation import validate_password, validate_email, validate_required
from .audit import log_db_action, log_access_attempt
import os

# Sessions simple en memoria: session_id -> {user_id, expires_at, last_activity, roles, pending_2fa}
SESSIONS = {}

def create_user(username, email, password) -> tuple[bool, str]:
    print("==== DEBUG CREATE_USER ====")
    print("Username:", username)
    print("Email:", email)
    print("Password:", password)
    ok, msg = validate_required({"username": username, "email": email, "password": password})
    if not ok:
        print("Fallo en required:", msg)
        return False, msg
    if not validate_email(email):
        print("Fallo en email")
        return False, "Correo inválido."
    okp, pmsg = validate_password(password)
    if not okp:
        print("Fallo en password:", pmsg)
        return False, pmsg

    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Verificar correo único (HU-04)
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            return False, "El correo ya está registrado."
        cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return False, "El nombre de usuario ya existe."
        salt = gen_salt()
        phash = hash_password(password, salt)
        cur.execute("INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)", (username, email, phash, salt))
        user_id = cur.lastrowid
        # Asignar rol 'usuario' automáticamente
        cur.execute("SELECT id FROM roles WHERE role_name = 'usuario'")
        row = cur.fetchone()
        if row:
            usuario_role_id = row[0]
            cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, usuario_role_id))
        db.commit()
        print("Usuario creado con id:", user_id)
        log_db_action(user_id, "CREATED USER")
        return True, "Usuario creado."
    except sqlite3.IntegrityError as e:
        print("IntegrityError:", e)
        return False, "Error de integridad."
    finally:
        db.close()


def find_user_by_email(email):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id, username, email, password_hash, salt, failed_attempts, blocked, enabled FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        db.close()

def get_user_orders(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Nota: esta consulta es un ejemplo, puede que necesites unir más tablas
        # para obtener nombres de prendas, colores, etc.
        cur.execute("""
            SELECT o.created_at, g.name, o.size, o.status
            FROM orders o
            JOIN garments g ON o.garment_id = g.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC
        """, (user_id,))
        orders = []
        for row in cur.fetchall():
            orders.append({
                "date": row[0],
                "garment": row[1],
                "size": row[2],
                "status": row[3]
            })
        return orders
    finally:
        db.close()

def get_user_by_id(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id, username, email FROM users WHERE id = ? AND enabled = 1", (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "email": row[2]}
    finally:
        db.close()

def increment_failed_attempts(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_id,))
        db.commit()
        cur.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
        fa = cur.fetchone()[0]
        if fa >= settings.MAX_FAILED_ATTEMPTS:
            # Bloqueo temporal: 10 minutos
            blocked_until = int(time.time()) + 600
            cur.execute("UPDATE users SET blocked = 1, blocked_until = ? WHERE id = ?", (blocked_until, user_id))
            db.commit()
            # alert email (look up user email)
            cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
            email = cur.fetchone()[0]
            try:
                send_email(email, "Cuenta bloqueada", "Su cuenta ha sido bloqueada temporalmente después de varios intentos fallidos. Podrá intentar de nuevo en 10 minutos.")
            except Exception:
                # fallback: write to access log
                with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
                    f.write(f"{now()} | ALERT: no se pudo enviar email de bloqueo para user {user_id}\n")
    finally:
        db.close()

def reset_failed_attempts(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
        db.commit()
    finally:
        db.close()

def login(email, password, client_ip):
    user = find_user_by_email(email)
    if not user:
        log_access_attempt(None, client_ip, False)
        return False, "Credenciales inválidas.", None, None
    user_id, username, email, phash, salt, failed_attempts, blocked, enabled = user
    # Verificar bloqueo temporal
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT blocked, blocked_until FROM users WHERE id = ?", (user_id,))
        blocked_val, blocked_until = cur.fetchone()
        if blocked_val:
            now_ts = int(time.time())
            if blocked_until and now_ts >= blocked_until:
                # Desbloquear automáticamente
                cur.execute("UPDATE users SET blocked = 0, blocked_until = NULL, failed_attempts = 0 WHERE id = ?", (user_id,))
                db.commit()
            else:
                log_access_attempt(user_id, client_ip, False)
                mins = int((blocked_until - now_ts) / 60) + 1 if blocked_until else 10
                return False, f"Cuenta bloqueada temporalmente. Intente de nuevo en {mins} minutos.", None, None
    finally:
        db.close()
    if not enabled:
        log_access_attempt(user_id, client_ip, False)
        return False, "Usuario deshabilitado. Contacte a un administrador.", None, None
    if not verify_password(password, salt, phash):
        increment_failed_attempts(user_id)
        log_access_attempt(user_id, client_ip, False)
        # Calcular intentos restantes
        remaining = max(0, settings.MAX_FAILED_ATTEMPTS - (failed_attempts + 1))
        return False, f"Credenciales inválidas. Te quedan {remaining} intento(s) antes del bloqueo temporal.", None, remaining
    reset_failed_attempts(user_id)
    code = gen_2fa_code()
    token = os.urandom(16).hex()
    expires = datetime.utcnow() + timedelta(minutes=5)
    SESSIONS[token] = {"user_id": user_id, "expires_at": expires, "verified": False, "pending_2fa": code, "last_activity": datetime.utcnow()}
    try:
        from .utils import build_2fa_email
        html_msg = build_2fa_email(username, code)
        send_email(email, "Código 2FA - JAANSTYLE", html_msg, html=True)
    except Exception as e:
        with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now()} | 2FA for user:{user_id} code:{code} (SMTP_ERROR: {e})\n")
    log_access_attempt(user_id, client_ip, True)
    return True, "Se ha enviado un código 2FA al correo.", token, None

def verify_2fa(token, code, client_ip):
    ses = SESSIONS.get(token)
    if not ses:
        return False, "Token inválido o expirado.", None
    if datetime.utcnow() > ses["expires_at"]:
        del SESSIONS[token]
        return False, "Token expirado.", None
    if ses.get("pending_2fa") != code:
        log_access_attempt(ses["user_id"], client_ip, False)
        return False, "Código incorrecto.", None

    # Validar que el usuario esté habilitado antes de crear la sesión
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT enabled FROM users WHERE id = ?", (ses["user_id"],))
        row = cur.fetchone()
        if not row or row[0] != 1:
            del SESSIONS[token]
            log_access_attempt(ses["user_id"], client_ip, False)
            return False, "Usuario deshabilitado. Contacte a un administrador.", None
    finally:
        db.close()
    # 2FA OK -> crear sesión persistente
    session_id = os.urandom(16).hex()
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_TIMEOUT_SECONDS)
    SESSIONS[session_id] = {
        "user_id": ses["user_id"],
        "expires_at": expires_at,
        "last_activity": datetime.utcnow(),
        "roles": get_roles_for_user(ses["user_id"])
    }
    # cleanup
    del SESSIONS[token]
    log_db_action(ses["user_id"], "LOGIN_SUCCESS_2FA")
    return True, "Autenticado.", session_id


def require_session(session_id):
    s = SESSIONS.get(session_id)
    if not s:
        return False, None
    # check inactivity (HU-19)
    now_ = datetime.utcnow()
    if now_ > s["expires_at"]:
        del SESSIONS[session_id]
        return False, None
    # Si han pasado más de 10 minutos desde la última actividad, cerrar sesión
    if (now_ - s["last_activity"]).total_seconds() > 600:
        del SESSIONS[session_id]
        return False, None
    # update last activity y renovar expiración
    s["last_activity"] = now_
    s["expires_at"] = now_ + timedelta(seconds=settings.SESSION_TIMEOUT_SECONDS)
    return True, s

def logout(session_id):
    if session_id in SESSIONS:
        user_id = SESSIONS[session_id]["user_id"]
        del SESSIONS[session_id]
        log_db_action(user_id, "LOGOUT")

def get_roles_for_user(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT r.role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?", (user_id,))
        return [row[0] for row in cur.fetchall()]
    finally:
        db.close()

def get_user_role_id(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT role_id FROM user_roles WHERE user_id = ? LIMIT 1", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        db.close()

def reauthenticate(user_id, password_attempt):
    # used for sensitive actions (HU-10)
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            return False
        phash, salt = row
        return verify_password(password_attempt, salt, phash)
    finally:
        db.close()
