# app/auth.py
# Este módulo maneja la autenticación de usuarios, incluyendo registro, login, 2FA,
# gestión de sesiones, roles y recuperación de contraseñas.
# Utiliza sesiones en memoria para simplicidad, pero en producción se recomienda Redis o similar.

import sqlite3
import time
from datetime import datetime, timedelta
from config import settings
from .utils import gen_salt, hash_password, verify_password, gen_2fa_code, send_email, now, build_reset_email
from .validation import validate_password, validate_email, validate_required
from .audit import log_db_action, log_access_attempt
import os

# Sesiones simples en memoria: session_id -> {user_id, expires_at, last_activity, roles, pending_2fa}
# Nota: En un entorno de producción, usar una base de datos o Redis para persistencia.
SESSIONS = {}

def create_user(username, email, password, first_name="", middle_name="", last_name="", second_last_name="", address1="", address2="", phone1="", phone2="", id_tipo_documento=1, numero_documento="") -> tuple[bool, str]:
    """
    Crea un nuevo usuario con validaciones y rol por defecto, incluyendo datos adicionales en 'usuario'.

    Args:
        username (str): Nombre de usuario único.
        email (str): Correo electrónico único.
        password (str): Contraseña en texto plano (se hashea antes de almacenar).
        first_name (str): Primer nombre.
        middle_name (str): Segundo nombre.
        last_name (str): Apellido paterno.
        second_last_name (str): Apellido materno.
        address1 (str): Primera línea de dirección.
        address2 (str): Segunda línea de dirección.
        phone1 (str): Primer teléfono.
        phone2 (str): Segundo teléfono.
        id_tipo_documento (int): ID del tipo de documento.
        numero_documento (str): Número del documento.

    Returns:
        tuple[bool, str]: (éxito, mensaje)
    """
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
    """
    Busca un usuario por email y retorna sus datos.

    Args:
        email (str): Correo electrónico del usuario.

    Returns:
        tuple or None: (id_usuario, username, correo, contraseña, failed_attempts, blocked, enabled) o None si no encontrado.
    """
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id_usuario, username, correo, contraseña, failed_attempts, blocked, enabled FROM users WHERE correo = ?", (email,))
        row = cur.fetchone()
        return row
    finally:
        db.close()

def get_user_orders(user_id):
    """
    Obtiene los pedidos de un usuario por su ID.

    Args:
        user_id (int): ID del usuario.

    Returns:
        list: Lista de diccionarios con información de pedidos (date, garment, size, status).
    """
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
    """
    Obtiene los productos creados por un usuario por su ID.

    Args:
        user_id (int): ID del usuario.

    Returns:
        list: Lista de diccionarios con información de productos (date, prenda, estilo, estado, descripcion, tela, molde).
    """
    # Fetch products but use LEFT JOINs so rows aren't excluded when related rows are missing.
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT id_cliente FROM usuario WHERE id_usuario = ?", (user_id,))
        cliente_row = cur.fetchone()
        if not cliente_row:
            return []
        id_cliente = cliente_row[0]

        query = '''
            SELECT
                p.id_producto,
                p.created_at,
                COALESCE(pr.nombre, tp.nombre, CAST(p.id_prenda AS TEXT)) AS prenda,
                COALESCE(e.nombre, te.nombre, CAST(p.id_estilo AS TEXT)) AS estilo,
                COALESCE(t.nombre, tt.nombre, CAST(p.id_tela AS TEXT)) AS tela,
                COALESCE(CAST(p.id_talla AS TEXT), tm.talla, '') AS talla,
                COALESCE(m.nombre, tm.nombre, CAST(p.id_molde AS TEXT)) AS molde,
                p.descripcion,
                COALESCE(es.descripcion, '') AS estado
            FROM producto p
            LEFT JOIN prenda pr ON p.id_prenda = pr.id_prenda
            LEFT JOIN tipo_prenda tp ON p.id_prenda = tp.id_tipo_prenda
            LEFT JOIN estilo e ON p.id_estilo = e.id_estilo
            LEFT JOIN tipo_estilo te ON p.id_estilo = te.id_tipo_estilo
            LEFT JOIN tela t ON p.id_tela = t.id_tela
            LEFT JOIN tipo_tela tt ON p.id_tela = tt.id_tipo_tela
            LEFT JOIN molde m ON p.id_molde = m.id_molde
            LEFT JOIN tipo_molde tm ON m.id_tipo_molde = tm.id_tipo_molde
            LEFT JOIN estados es ON p.id_estado = es.id_estado
            WHERE p.id_cliente = ?
            ORDER BY p.created_at DESC
        '''

        cur.execute(query, (id_cliente,))
        rows = cur.fetchall()

        products = []
        for row in rows:
            products.append({
                "date": row[1] or "",
                "prenda": row[2] or "N/A",
                "estilo": row[3] or "N/A",
                "estado": row[8] or "N/A",
                "descripcion": row[7] or "N/A",
                "tela": row[4] or "N/A",
                "molde": row[6] or "N/A",
                "talla": row[5] or ""
            })
        return products
    finally:
        db.close()

def get_user_by_id(user_id):
    """
    Obtiene información básica de un usuario por su ID si está habilitado.

    Args:
        user_id (int): ID del usuario.

    Returns:
        dict or None: Diccionario con 'id', 'username', 'email' o None si no encontrado o deshabilitado.
    """
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
    """
    Incrementa el contador de intentos fallidos de login para un usuario.

    Si el número de intentos fallidos alcanza el máximo permitido, bloquea la cuenta temporalmente
    y envía un email de alerta.

    Args:
        user_id (int): ID del usuario.
    """
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
    """
    Reinicia el contador de intentos fallidos de login para un usuario.

    Args:
        user_id (int): ID del usuario.
    """
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

def generate_reset_token(user_id):
    """Genera un token único para reset de contraseña y lo guarda en la DB."""
    token = os.urandom(32).hex()
    expires_at = datetime.utcnow() + timedelta(minutes=30)
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                    (user_id, token, expires_at.isoformat()))
        db.commit()
        return token
    finally:
        db.close()

def verify_reset_token(token):
    """Verifica si un token de reset es válido y no expirado. Retorna user_id si válido."""
    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        cur.execute("SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = ? AND used = 0", (token,))
        row = cur.fetchone()
        if not row:
            return None
        user_id, expires_at_str, used = row
        expires_at = datetime.fromisoformat(expires_at_str)
        if datetime.utcnow() > expires_at:
            return None
        return user_id
    finally:
        db.close()

def reset_user_password(token, new_password):
    """Cambia la contraseña del usuario usando el token de reset."""
    user_id = verify_reset_token(token)
    if not user_id:
        return False, "Token inválido o expirado."

    # Validar nueva contraseña
    ok, msg = validate_password(new_password)
    if not ok:
        return False, msg

    # Generar nuevo hash
    salt = gen_salt()
    phash = hash_password(new_password, salt)
    stored_hash = f"{salt}:{phash}"

    db = sqlite3.connect(settings.DB_PATH)
    try:
        cur = db.cursor()
        # Actualizar contraseña
        cur.execute("UPDATE users SET contraseña = ? WHERE id_usuario = ?", (stored_hash, user_id))
        # Marcar token como usado
        cur.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
        db.commit()
        log_db_action(user_id, "PASSWORD_RESET")
        return True, "Contraseña cambiada exitosamente."
    finally:
        db.close()

def request_password_reset(email):
    """Inicia el proceso de reset de contraseña enviando email si el usuario existe."""
    user = find_user_by_email(email)
    if not user:
        # No revelar si el email existe o no por seguridad
        return True, "Si el correo existe, se ha enviado un enlace de recuperación."

    user_id, username, email_addr, _, _, _, enabled = user
    if not enabled:
        return True, "Si el correo existe, se ha enviado un enlace de recuperación."

    # Generar token
    token = generate_reset_token(user_id)

    # Enviar email
    import threading
    def send_reset_email():
        try:
            html_msg = build_reset_email(token)
            send_email(email_addr, "Recuperar contraseña - JAANSTYLE", html_msg, html=True)
        except Exception as e:
            with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
                f.write(f"{now()} | RESET_EMAIL_FAILED for user:{user_id} ({e})\n")

    threading.Thread(target=send_reset_email).start()
    return True, "Se ha enviado un enlace de recuperación a tu correo."
