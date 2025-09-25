import sys, os

#  Fix: aseguramos que la raíz (un nivel arriba de /app) esté en sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import json
import sqlite3
import re
from datetime import datetime

# Ahora ya puede importar config y los módulos locales
from config import settings
from . import auth, maintenance, security
from .audit import log_db_action

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

def render_template(name, **ctx):
    """Renderiza una plantilla HTML con variables y loops simples."""
    with open(os.path.join(TEMPLATES_DIR, name), "r", encoding="utf-8") as f:
        content = f.read()

    if not ctx:
        return content

    # Simple template engine:
    # 1. Handles loops: <!-- loop orders -->...<!-- endloop -->
    # 2. Handles variables: {user.username}, {item.name}, {message}

    # Handle loops
    loop_regex = re.compile(r"<!-- loop (\w+) -->(.*?)<!-- endloop -->", re.DOTALL)

    def handle_loop(match):
        list_name = match.group(1)
        loop_template = match.group(2)
        items = ctx.get(list_name, [])

        print(f"DEBUG TEMPLATE: Procesando loop '{list_name}' con {len(items)} items")

        rendered_loop = ""
        if not items:
            return "<tr><td colspan='99' class='text-center'>No hay datos.</td></tr>"

        for i, item in enumerate(items):
            print(f"DEBUG TEMPLATE: Item {i} - {item}")
            item_html = loop_template
            for key, value in item.items():
                item_html = item_html.replace(f"{{item.{key}}}", str(value))
            rendered_loop += item_html
        return rendered_loop

    content = loop_regex.sub(handle_loop, content)

    # Handle object variables like {user.username}
    for key, data in ctx.items():
        if isinstance(data, dict):
            for sub_key, sub_value in data.items():
                content = content.replace(f"{{{key}.{sub_key}}}", str(sub_value))

    # Handle item.field format for loops
    for key, data in ctx.items():
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for field, value in item.items():
                        content = content.replace(f"{{item.{field}}}", str(value))

    # Handle simple variables like {message}
    for key, value in ctx.items():
        if not isinstance(value, (dict, list)):
            content = content.replace(f"{{{key}}}", str(value))

    return content


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Maneja las peticiones GET: rutas, estáticos, dashboards, AJAX."""
        # Servir archivos estáticos
        if self.path.startswith("/static/"):
            static_path = self.path.lstrip("/")
            static_file = os.path.join(os.path.dirname(__file__), static_path)
            if os.path.isfile(static_file):
                # Determinar el tipo de contenido
                if static_file.endswith('.css'):
                    content_type = 'text/css'
                elif static_file.endswith('.js'):
                    content_type = 'application/javascript'
                elif static_file.endswith('.png'):
                    content_type = 'image/png'
                elif static_file.endswith('.jpg') or static_file.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                elif static_file.endswith('.gif'):
                    content_type = 'image/gif'
                else:
                    content_type = 'application/octet-stream'
                with open(static_file, 'rb') as f:
                    self.respond(200, f.read(), content_type=content_type)
                return
            else:
                self.respond(404, "Archivo estático no encontrado")
                return

        if maintenance.is_maintenance():
            self.respond(200, render_template("maintenance.html"))
            return

        if self.path == "/":
            self.respond(200, render_template("login.html", error_message_div="", email=""))
        elif self.path == "/forms":
            self.respond(200, render_template("forms.html", error_message_div="", username="", email=""))
        elif self.path == "/dashboard":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok:
                self.redirect("/")
                return

            user_id = session_data["user_id"]
            user = auth.get_user_by_id(user_id)
            orders = auth.get_user_orders(user_id)
            
            # Render a different dashboard based on role
            if "admin" in session_data.get("roles", []):
                template_name = "dashboard_admin.html"
            else:
                template_name = "dashboard_user.html"
            
            self.respond(200, render_template(template_name, user=user, orders=orders))
        
        elif self.path == "/admin/users":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.redirect("/")
                return
            user = auth.get_user_by_id(session_data["user_id"])
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id, username, email, enabled FROM users")
                users = []
                for row in cur.fetchall():
                    enabled = row[3]
                    enabled_label = "Habilitado" if enabled else "Deshabilitado"
                    enabled_class = "success" if enabled else "danger"
                    btn_text = "Deshabilitar" if enabled else "Habilitar"
                    btn_class = "btn-danger" if enabled else "btn-success"
                    disabled_btn_class = "btn-success" if enabled else "btn-danger"
                    disabled_btn_text = "Habilitar" if enabled else "Deshabilitar"
                    disabled = "Deshabilitado" if enabled else "Habilitado"
                    # Obtener el rol actual
                    from . import auth as authmod
                    role_id = authmod.get_user_role_id(row[0])
                    user_data = {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "enabled": enabled_label,
                        "enabled_class": enabled_class,
                        "enabled_btn_text": btn_text,
                        "enabled_btn_class": btn_class,
                        "disabled_btn_class": disabled_btn_class,
                        "disabled_btn_text": disabled_btn_text,
                        "disabled": disabled,
                        "role_id": role_id
                    }
                    print(f"DEBUG: Usuario procesado - ID: {user_data['id']}, Username: '{user_data['username']}', Email: '{user_data['email']}'")
                    users.append(user_data)
            finally:
                db.close()
            # Si es AJAX, solo devolver el <tbody> de la tabla de usuarios
            if self.headers.get("X-Requested-With") == "XMLHttpRequest":
                # Renderizar solo el loop users
                with open(os.path.join(TEMPLATES_DIR, "dashboard_admin.html"), "r", encoding="utf-8") as f:
                    content = f.read()
                import re
                m = re.search(r"<!-- loop users -->(.*?)<!-- endloop -->", content, re.DOTALL)
                if m:
                    loop_template = m.group(1)
                    rendered = ""
                    if not users:
                        rendered = "<tr><td colspan='99' class='text-center'>No hay datos.</td></tr>"
                    else:
                        for item in users:
                            item_html = loop_template
                            for key, value in item.items():
                                item_html = item_html.replace(f"{{item.{key}}}", str(value))
                            rendered += item_html
                    self.respond(200, rendered)
                    return
            # Si no es AJAX, renderizar la página completa
            html = render_template("dashboard_admin.html", user=user, users=users)

            self.respond(200, html)
        elif self.path.startswith("/admin/search_user"):
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.redirect("/")
                return
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            q = query_params.get('q', [''])[0].strip()
            users = []
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                if q:
                    cur.execute("SELECT id, username, email, enabled FROM users WHERE username LIKE ?", (f"%{q}%",))
                else:
                    # Si q vacío, cargar todos los usuarios
                    cur.execute("SELECT id, username, email, enabled FROM users")
                for row in cur.fetchall():
                    enabled = row[3]
                    enabled_label = "Habilitado" if enabled else "Deshabilitado"
                    enabled_class = "success" if enabled else "danger"
                    btn_text = "Deshabilitar" if enabled else "Habilitar"
                    btn_class = "btn-danger" if enabled else "btn-success"
                    disabled_btn_class = "btn-success" if enabled else "btn-danger"
                    disabled_btn_text = "Habilitar" if enabled else "Deshabilitar"
                    disabled = "Deshabilitado" if enabled else "Habilitado"
                    role_id = auth.get_user_role_id(row[0])
                    users.append({
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "enabled": enabled_label,
                        "enabled_class": enabled_class,
                        "enabled_btn_text": btn_text,
                        "enabled_btn_class": btn_class,
                        "disabled_btn_class": disabled_btn_class,
                        "disabled_btn_text": disabled_btn_text,
                        "disabled": disabled,
                        "role_id": role_id
                    })
            finally:
                db.close()
            # Si es AJAX, devolver el tbody renderizado
            if self.headers.get("X-Requested-With") == "XMLHttpRequest":
                # Renderizar el loop users
                with open(os.path.join(TEMPLATES_DIR, "dashboard_admin.html"), "r", encoding="utf-8") as f:
                    content = f.read()
                import re
                m = re.search(r"<!-- loop users -->(.*?)<!-- endloop -->", content, re.DOTALL)
                if m:
                    loop_template = m.group(1)
                    rendered = ""
                    if not users:
                        rendered = "<tr><td colspan='99' class='text-center'>No hay datos.</td></tr>"
                    else:
                        for item in users:
                            item_html = loop_template
                            for key, value in item.items():
                                item_html = item_html.replace(f"{{item.{key}}}", str(value))
                            rendered += item_html
                    self.respond(200, rendered)
                    return

        elif self.path == "/admin/roles":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, "No autorizado")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id, role_name FROM roles")
                roles = cur.fetchall()
                roles_list = [{"id": r[0], "name": r[1]} for r in roles]
            finally:
                db.close()
            self.respond(200, json.dumps(roles_list), content_type="application/json")
            return

        elif self.path == "/logout":
            session = self.get_session()
            auth.logout(session)
            self.redirect("/")
        elif self.path == "/session_remaining":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok:
                self.respond(403, json.dumps({"remaining": 0}), content_type="application/json")
                return
            remaining = (session_data["expires_at"] - datetime.utcnow()).total_seconds()
            remaining = max(0, int(remaining))
            self.respond(200, json.dumps({"remaining": remaining}), content_type="application/json")
            return
        elif self.path == "/extend_session":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)  # Renueva la sesión
            if not ok:
                self.respond(403, "No autorizado")
                return
            self.respond(200, "ok")
            return
        else:
            self.respond(404, "Not Found")

    def do_POST(self):
        """Maneja las peticiones POST: login, registro, 2FA, acciones admin, etc."""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        client_ip = self.client_address[0]

        # 🔎 DEBUG: imprimir lo que llega en POST
        print("\n==== DEBUG POST ====")
        print("Path:", self.path)
        print("Body:", body)
        print("Params:", params)
        print("====================\n")

        if self.path == "/reauthenticate":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            password = params.get("password", [""])[0]
            user_id = session_data["user_id"]
            if auth.reauthenticate(user_id, password):
                self.respond(200, json.dumps({"ok": True}), content_type="application/json")
            else:
                self.respond(200, json.dumps({"ok": False, "msg": "Contraseña incorrecta"}), content_type="application/json")
            return

        if self.path == "/forms":
            username = params.get("username", [""])[0]   #usar 'username'
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg = auth.create_user(username, email, password)
            if ok:
                self.redirect("/dashboard")
            else:
                error_message_div = f'<div id="error-message" class="alert alert-danger" role="alert">{msg}</div>' if msg else ''
                self.respond(400, render_template("forms.html", error_message=msg, error_message_div=error_message_div, username=username, email=email))

        # 🔹 Login de usuario
        elif self.path == "/login":
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg, token, remaining = auth.login(email, password, client_ip)
            if not ok:
                # Mostrar mensaje de error e intentos restantes en la misma página de login
                error_message_div = f'<div id="error-message" class="alert alert-danger" role="alert">{msg}</div>' if msg else ''
                self.respond(403, render_template("login.html", error_message_div=error_message_div, email=email))
                return
            # Redirigir a 2fa.html con el token y mensaje
            self.respond(200, render_template("2fa.html", token=token, msg=msg))

        # 🔹 Verificación 2FA
        elif self.path == "/verify-2fa":
            token = params.get("token", [""])[0]
            code = params.get("code", [""])[0]
            ok, msg, session_id = auth.verify_2fa(token, code, client_ip)
            if not ok:
                self.respond(403, render_template("error.html", message=msg))
                return
            self.send_response(302)
            self.send_header("Set-Cookie", f"session_id={session_id}; HttpOnly")
            self.send_header("Location", "/dashboard")
            self.end_headers()
        elif self.path == "/admin/disable_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.redirect("/")
                return
            raw_user_id = params.get("user_id", ["0"])[0]
            # Limpiar user_id para que solo contenga dígitos (eliminar caracteres no numéricos como $)
            user_id_str = ''.join(filter(str.isdigit, raw_user_id))
            if not user_id_str:
                self.respond(400, "ID de usuario inválido")
                return
            user_id = int(user_id_str)
            # No permitir que el admin se deshabilite a sí mismo
            if user_id == session_data["user_id"]:
                self.respond(400, "No puedes deshabilitar tu propio usuario.")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # Leer el estado actual
                cur.execute("SELECT enabled FROM users WHERE id = ?", (user_id,))
                row = cur.fetchone()
                if row is not None:
                    current_enabled = row[0]
                    new_enabled = 0 if current_enabled else 1
                    cur.execute("UPDATE users SET enabled = ? WHERE id = ?", (new_enabled, user_id))
                    db.commit()
            finally:
                db.close()
            # Si es AJAX, responder con texto plano
            if self.headers.get("X-Requested-With") == "XMLHttpRequest":
                self.respond(200, b"ok", content_type="text/plain")
            else:
                self.redirect("/admin/users")
            return
        elif self.path == "/admin/set_role":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, "No autorizado")
                return
            raw_user_id = params.get("user_id", ["0"])[0]
            raw_role_id = params.get("role_id", ["0"])[0]
            # Limpiar user_id y role_id para que solo contengan dígitos
            user_id_str = ''.join(filter(str.isdigit, raw_user_id))
            role_id_str = ''.join(filter(str.isdigit, raw_role_id))
            if not user_id_str or not role_id_str:
                self.respond(400, "ID de usuario o rol inválido")
                return
            user_id = int(user_id_str)
            role_id = int(role_id_str)
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # Eliminar roles actuales
                cur.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
                # Asignar nuevo rol
                cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
                db.commit()
            finally:
                db.close()
            self.respond(200, b"ok", content_type="text/plain")
            return
        elif self.path == "/admin/create_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            username = params.get("username", [""])[0]
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            from . import users
            ok, msg = users.create_user(username, email, password)
            if ok:
                self.respond(200, json.dumps({"ok": True}), content_type="application/json")
            else:
                self.respond(400, json.dumps({"ok": False, "msg": msg}), content_type="application/json")
            return
        elif self.path == "/admin/update_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            user_id = int(params.get("user_id", [0])[0])
            new_username = params.get("username", [""])[0]
            new_email = params.get("email", [""])[0]
            from . import users
            ok, msg = users.update_user(session_data["user_id"], user_id, new_username, new_email)
            if ok:
                self.respond(200, json.dumps({"ok": True}), content_type="application/json")
            else:
                self.respond(400, json.dumps({"ok": False, "msg": msg}), content_type="application/json")
            return
        elif self.path == "/admin/search_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "admin" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            print("DEBUG SEARCH POST: Params =", params)
            username = params.get("username", [""])[0]
            print("DEBUG SEARCH POST: Username =", repr(username))
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                if username:
                    print("DEBUG SEARCH POST: Executing query for username =", repr(username))
                    cur.execute("SELECT id, username, email, enabled FROM users WHERE username LIKE ?", (f"%{username}%",))
                else:
                    print("DEBUG SEARCH POST: Executing query for all users")
                    cur.execute("SELECT id, username, email, enabled FROM users")
                rows = cur.fetchall()
                print("DEBUG SEARCH POST: Rows =", rows)
                users = []
                for row in rows:
                    print(f"DEBUG SEARCH_USER: Usuario encontrado - ID: {row[0]}, Username: '{row[1]}', Email: '{row[2]}', Enabled: {row[3]}")
                    enabled = row[3]
                    enabled_label = "Habilitado" if enabled else "Deshabilitado"
                    enabled_class = "success" if enabled else "danger"
                    btn_text = "Deshabilitar" if enabled else "Habilitar"
                    btn_class = "btn-danger" if enabled else "btn-success"
                    disabled_btn_class = "btn-success" if enabled else "btn-danger"
                    disabled_btn_text = "Habilitar" if enabled else "Deshabilitar"
                    disabled = "Deshabilitado" if enabled else "Habilitado"
                    # Obtener el rol actual
                    from . import auth as authmod
                    role_id = authmod.get_user_role_id(row[0])
                    user_data = {
                        "id": str(row[0]),
                        "username": str(row[1]),
                        "email": str(row[2]),
                        "enabled": enabled_label,
                        "enabled_class": enabled_class,
                        "enabled_btn_text": btn_text,
                        "enabled_btn_class": btn_class,
                        "disabled_btn_class": disabled_btn_class,
                        "disabled_btn_text": disabled_btn_text,
                        "disabled": disabled,
                        "role_id": role_id
                    }
                    users.append(user_data)
                print(f"DEBUG SEARCH_USER: Usuarios a enviar: {users}")
            finally:
                db.close()
            self.respond(200, json.dumps({"ok": True, "users": users}), content_type="application/json")
            return
        else:
            self.respond(404, "Not Found")

    def get_session(self):
        """Obtiene el session_id de la cookie del usuario."""
        cookie = self.headers.get("Cookie")
        if not cookie:
            return None
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session_id":
                return v
        return None

    def redirect(self, path):
        """Redirige al usuario a otra ruta."""
        self.send_response(302)
        self.send_header("Location", path)
        self.end_headers()

    def respond(self, code, body, content_type="text/html"):
        """Envía una respuesta HTTP con el código, cuerpo y tipo de contenido."""
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run():
    """Inicia el servidor HTTP(S) y lo deja escuchando hasta que se detenga."""
    os.chdir(os.path.dirname(__file__))

    use_tls = security.ensure_certs_exist()
    port = settings.HTTPS_PORT if use_tls else settings.PORT
    server_address = (settings.HOST, port)
    
    httpd = HTTPServer(server_address, Handler)

    if use_tls:
        security.wrap_socket(httpd)
        print(f"✅ Server running with TLS on https://{settings.HOST}:{port}")
    else:
        print(f"⚠️ CERTS not found; running without TLS on http://{settings.HOST}:{port}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server")
    finally:
        httpd.server_close()



if __name__ == "__main__":
    run()
