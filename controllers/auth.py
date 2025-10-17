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

def create_user(username, email, password, first_name="", middle_name="", last_name="", second_last_name="", address1="", address2="", phone1="", phone2="", id_tipo_documento=1, numero_documento="") -> tuple[bool, str]:
    """Crea un nuevo usuario con validaciones y rol por defecto, incluyendo datos adicionales en 'usuario'."""
    print("==== DEBUG CREATE_USER ====")
    print("Username:", username)
    print("Email:", email)
    print("Password:", password)
    print("First Name:", first_name)
    print("Middle Name:", middle_name)
    print("Last Name:", last_name)
    print("Second Last Name:", second_last_name)
    print("Address1:", address1)
    print("Address2:", address2)
    print("Phone1:", phone1)
    print("Phone2:", phone2)
    print("Id Tipo Documento:", id_tipo_documento)
    print("Numero Documento:", numero_documento)
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
        cur.execute("SELECT 1 FROM users WHERE correo = ?", (email,))
        if cur.fetchone():
            return False, "El correo ya está registrado."
        cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return False, "El nombre de usuario ya existe."
        salt = gen_salt()
        phash = hash_password(password, salt)
        stored_hash = f"{salt}:{phash}"
        cur.execute("INSERT INTO users (username, correo, contraseña, rol, enabled) VALUES (?, ?, ?, 'usuario', 1)", (username, email, stored_hash))
        user_id = cur.lastrowid
        # Asignar rol 'usuario' automáticamente
        cur.execute("SELECT id FROM roles WHERE role_name = 'usuario'")
        row = cur.fetchone()
        if row:
            usuario_role_id = row[0]
            cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, usuario_role_id))
        # Obtener el nombre del tipo de documento
        cur.execute("SELECT nombre FROM tipo_documento WHERE id_tipo_documento = ?", (id_tipo_documento,))
        tipo_row = cur.fetchone()
        if not tipo_row:
            return False, "Tipo de documento inválido."
        nombre_tipo = tipo_row[0]
        # Insertar nuevo registro en tipo_documento con el nombre del tipo y el número de documento
        cur.execute("INSERT INTO tipo_documento (nombre, Number) VALUES (?, ?)", (nombre_tipo, numero_documento))
        nuevo_id_tipo_documento = cur.lastrowid
        # Insertar datos adicionales en 'usuario' con el nuevo id_tipo_documento
        direccion = f"{address1} {address2}".strip()
        cur.execute("INSERT INTO usuario (id_usuario, nombre1, nombre2, apellido1, apellido2, direccion, telefono1, telefono2, id_tipo_documento) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (user_id, first_name, middle_name, last_name, second_last_name, direccion, phone1, phone2, nuevo_id_tipo_documento))
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
    """Busca un usuario por email y retorna sus datos."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id_usuario, username, correo, contraseña, failed_attempts, blocked, enabled FROM users WHERE correo = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        db.close()

def get_user_orders(user_id):
    """Obtiene los pedidos de un usuario por su ID."""
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

def get_user_products(user_id):
    """Obtiene los productos creados por un usuario por su ID."""
    print(f"DEBUG get_user_products: user_id={user_id}")
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Obtener id_cliente
        cur.execute("SELECT id_cliente FROM usuario WHERE id_usuario = ?", (user_id,))
        cliente_row = cur.fetchone()
        if not cliente_row:
            print("DEBUG: No id_cliente encontrado para user_id")
            return []
        id_cliente = cliente_row[0]
        print(f"DEBUG: id_cliente={id_cliente}")
        # Verificar productos sin JOIN
        cur.execute("SELECT id_prenda, id_estilo, id_estado, created_at FROM producto WHERE id_cliente = ?", (id_cliente,))
        raw_products = cur.fetchall()
        print(f"DEBUG: Productos raw para id_cliente={id_cliente}: {raw_products}")
        # Consulta con JOIN para obtener toda la información del producto
        cur.execute("""
            SELECT p.created_at, pr.nombre AS prenda, e.nombre AS estilo, es.descripcion AS estado, p.descripcion, t.nombre AS tela, m.nombre AS molde
            FROM producto p
            JOIN prenda pr ON p.id_prenda = pr.id_prenda
            JOIN estilo e ON p.id_estilo = e.id_estilo
            JOIN estados es ON p.id_estado = es.id_estado
            JOIN tela t ON p.id_tela = t.id_tela
            JOIN molde m ON p.id_molde = m.id_molde
            WHERE p.id_cliente = ?
            ORDER BY p.created_at DESC
        """, (id_cliente,))
        rows = cur.fetchall()
        print(f"DEBUG: Resultados del JOIN: {rows}")
        products = []
        for row in rows:
            products.append({
                "date": row[0] or "Sin fecha",
                "prenda": row[1] or "N/A",
                "estilo": row[2] or "N/A",
                "estado": row[3] or "N/A",
                "descripcion": row[4] or "N/A",
                "tela": row[5] or "N/A",
                "molde": row[6] or "N/A"
            })
        print(f"DEBUG: Products list: {products}")
        return products
    finally:
        db.close()

def get_user_by_id(user_id):
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id_usuario, username, correo FROM users WHERE id_usuario = ? AND enabled = 1", (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "email": row[2]}
    finally:
        db.close()

def increment_failed_attempts(user_id):
    """Incrementa el contador de intentos fallidos de login para un usuario."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id_usuario = ?", (user_id,))
        db.commit()
        cur.execute("SELECT failed_attempts FROM users WHERE id_usuario = ?", (user_id,))
        fa = cur.fetchone()[0]
        if fa >= settings.MAX_FAILED_ATTEMPTS:
            # Bloqueo temporal: 10 minutos
            blocked_until = int(time.time()) + 600
            cur.execute("UPDATE users SET blocked = 1, blocked_until = ? WHERE id_usuario = ?", (blocked_until, user_id))
            db.commit()
            # alert email (look up user email)
            cur.execute("SELECT correo FROM users WHERE id_usuario = ?", (user_id,))
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
    """Reinicia el contador de intentos fallidos de login para un usuario."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("UPDATE users SET failed_attempts = 0 WHERE id_usuario = ?", (user_id,))
        db.commit()
    finally:
        db.close()

import time

def login(email, password, client_ip):
    """Realiza el proceso de login, validando credenciales y estado del usuario."""
    start_time = time.time()
    user = find_user_by_email(email)
    if not user:
        log_access_attempt(None, client_ip, False)
        return False, "Credenciales inválidas.", None, None
    user_id, username, email, phash, failed_attempts, blocked, enabled = user
    # Verificar bloqueo temporal
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT blocked, blocked_until FROM users WHERE id_usuario = ?", (user_id,))
        blocked_val, blocked_until = cur.fetchone()
        if blocked_val:
            now_ts = int(time.time())
            if blocked_until and now_ts >= blocked_until:
                # Desbloquear automáticamente
                cur.execute("UPDATE users SET blocked = 0, blocked_until = NULL, failed_attempts = 0 WHERE id_usuario = ?", (user_id,))
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
    if not verify_password(password, None, phash):
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
    import threading
    def send_2fa_email():
        try:
            from .utils import build_2fa_email
            html_msg = build_2fa_email(username, code)
            send_email(email, "Código 2FA - JAANSTYLE", html_msg, html=True)
        except Exception as e:
            with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
                f.write(f"{now()} | 2FA for user:{user_id} code:{code} (SMTP_ERROR: {e})\n")
    threading.Thread(target=send_2fa_email).start()
    log_access_attempt(user_id, client_ip, True)
    end_time = time.time()
    duration = end_time - start_time
    with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write(f"{now()} | LOGIN duration: {duration:.2f} seconds for user {user_id}\n")
    return True, "Se ha enviado un código 2FA al correo.", token, None

def verify_2fa(token, code, client_ip):
    """Verifica el código 2FA y crea la sesión si es correcto."""
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
        cur.execute("SELECT enabled FROM users WHERE id_usuario = ?", (ses["user_id"],))
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
    """Valida y renueva una sesión activa por session_id."""
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

def require_session_no_renew(session_id):
    """Valida una sesión activa por session_id sin renovarla."""
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
    return True, s

def logout(session_id):
    """Cierra la sesión del usuario y registra el logout."""
    if session_id in SESSIONS:
        user_id = SESSIONS[session_id]["user_id"]
        del SESSIONS[session_id]
        log_db_action(user_id, "LOGOUT")

def get_roles_for_user(user_id):
    """Obtiene la lista de roles asignados a un usuario desde user_roles."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT r.role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?", (user_id,))
        return [row[0] for row in cur.fetchall()]
    finally:
        db.close()

def get_user_role_id(user_id):
    """Obtiene el ID de rol principal de un usuario."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT role_id FROM user_roles WHERE user_id = ? LIMIT 1", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        db.close()

def reauthenticate(user_id, password_attempt):
    """Verifica la contraseña del usuario para reautenticación en acciones sensibles."""
    # used for sensitive actions (HU-10)
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT contraseña FROM users WHERE id_usuario = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            return False
        phash = row[0]
        return verify_password(password_attempt, None, phash)
    finally:
        db.close()
