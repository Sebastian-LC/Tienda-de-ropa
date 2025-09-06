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

def create_user(username, email, password) -> (bool, str):
    ok, msg = validate_required({"username": username, "email": email, "password": password})
    if not ok:
        return False, msg
    if not validate_email(email):
        return False, "Correo inválido."
    okp, pmsg = validate_password(password)
    if not okp:
        return False, pmsg
    salt = gen_salt()
    phash = hash_password(password, salt)
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)", (username, email, phash, salt))
        db.commit()
        user_id = cur.lastrowid
        log_db_action(user_id, "CREATED USER")
        return True, "Usuario creado."
    except sqlite3.IntegrityError as e:
        if "email" in str(e).lower():
            return False, "El correo ya está registrado."
        if "username" in str(e).lower():
            return False, "El nombre de usuario ya existe."
        return False, "Error de integridad."
    finally:
        db.close()

def find_user_by_email(email):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id, username, email, password_hash, salt, failed_attempts, blocked FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return row
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
            cur.execute("UPDATE users SET blocked = 1 WHERE id = ?", (user_id,))
            db.commit()
            # alert email (look up user email)
            cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
            email = cur.fetchone()[0]
            try:
                send_email(email, "Cuenta bloqueada", "Su cuenta ha sido bloqueada después de varios intentos fallidos.")
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
        # log attempt with user_id = None
        log_access_attempt(None, client_ip, False)
        return False, "Credenciales inválidas.", None
    user_id, username, email, phash, salt, failed_attempts, blocked = user
    if blocked:
        log_access_attempt(user_id, client_ip, False)
        return False, "Cuenta bloqueada. Contacte a un administrador.", None
    if not verify_password(password, salt, phash):
        increment_failed_attempts(user_id)
        log_access_attempt(user_id, client_ip, False)
        return False, "Credenciales inválidas.", None
    # password OK -> reset attempts
    reset_failed_attempts(user_id)
    # generate 2FA
    code = gen_2fa_code()
    # save pending 2fa in SESSIONS temporary token
    token = os.urandom(16).hex()
    expires = datetime.utcnow() + timedelta(minutes=5)
    SESSIONS[token] = {"user_id": user_id, "expires_at": expires, "verified": False, "pending_2fa": code, "last_activity": datetime.utcnow()}
    # send email with code
    try:
        send_email(email, "Código 2FA", f"Tu código de autenticación es: {code}")
    except Exception as e:
        # fallback: write to logs so dev can see code if SMTP not configured
        with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now()} | 2FA for user:{user_id} code:{code} (SMTP_ERROR: {e})\n")
    log_access_attempt(user_id, client_ip, True)
    return True, "Se ha enviado un código 2FA al correo.", token

def verify_2fa(token, code, client_ip):
    ses = SESSIONS.get(token)
    if not ses:
        return False, "Token inválido o expirado."
    if datetime.utcnow() > ses["expires_at"]:
        del SESSIONS[token]
        return False, "Token expirado."
    if ses.get("pending_2fa") != code:
        log_access_attempt(ses["user_id"], client_ip, False)
        return False, "Código incorrecto."
    # 2FA OK -> crear sesión persistente
    session_id = os.urandom(16).hex()
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_TIMEOUT_SECONDS)
    SESSIONS[session_id] = {"user_id": ses["user_id"], "expires_at": expires_at, "last_activity": datetime.utcnow(), "roles": get_roles_for_user(ses["user_id"])}
    # cleanup
    del SESSIONS[token]
    log_db_action(ses["user_id"], "LOGIN_SUCCESS_2FA")
    return True, "Autenticado.", session_id

def require_session(session_id):
    s = SESSIONS.get(session_id)
    if not s:
        return False, None
    # check inactivity
    if datetime.utcnow() > s["expires_at"]:
        del SESSIONS[session_id]
        return False, None
    # update last activity and expiry
    s["last_activity"] = datetime.utcnow()
    s["expires_at"] = datetime.utcnow() + timedelta(seconds=settings.SESSION_TIMEOUT_SECONDS)
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
