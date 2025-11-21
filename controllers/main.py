import sys, os

#  Fix: aseguramos que la raíz (un nivel arriba de /app) esté en sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote
import json
import sqlite3
import re
from datetime import datetime

# Ahora ya puede importar config y los módulos locales
from config import settings
from . import auth, maintenance, security
from .audit import log_db_action

TEMPLATES_DIR = os.path.join(ROOT_DIR, "views")

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
            # Mensaje alternativo si la lista está vacía
            if list_name == "products":
                return "<tr><td colspan='4' class='text-center'>No hay productos disponibles.</td></tr>"
            else:
                return "<tr><td colspan='99' class='text-center'>No hay pedidos disponibles.</td></tr>"

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
    def log_message(self, format, *args):
        pass  # Deshabilitar logs del servidor HTTP

    def do_GET(self):
        """Maneja las peticiones GET: rutas, estáticos, dashboards, AJAX."""
        # Servir archivos estáticos
        if self.path.startswith("/static/"):
            static_path = unquote(self.path.lstrip("/"))
            static_file = os.path.join(ROOT_DIR, static_path)
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
                try:
                    with open(static_file, 'rb') as f:
                        self.respond(200, f.read(), content_type=content_type)
                except ConnectionAbortedError:
                    # Cliente cerró la conexión, ignorar
                    pass
                return
            else:
                try:
                    self.respond(404, "Archivo estático no encontrado")
                except ConnectionAbortedError:
                    pass
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
            products = auth.get_user_products(user_id)

            # Render a different dashboard based on role
            if "administrator" in session_data.get("roles", []):
                template_name = "dashboard_admin.html"
            else:
                template_name = "dashboard_user.html"

            # Consultar datos para selectores dinámicos
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # Prendas
                cur.execute("SELECT id_tipo_prenda as id, nombre FROM tipo_prenda")
                prendas = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                # Telas
                cur.execute("SELECT id_tipo_tela as id, nombre FROM tipo_tela")
                telas = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                # Estilos
                cur.execute("SELECT id_tipo_estilo as id, nombre FROM tipo_estilo")
                estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                # Moldes
                cur.execute("SELECT id_tipo_molde as id, nombre FROM tipo_molde")
                moldes = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                # Estados
                cur.execute("SELECT id_estado, descripcion FROM estados")
                estados = [{"id": r[0], "descripcion": r[1]} for r in cur.fetchall()]
                # Colores
                cur.execute("SELECT id as id, name as nombre, hex_code as codigo_hex FROM colors")
                colores = [{"id": r[0], "nombre": r[1], "codigo_hex": r[2]} for r in cur.fetchall()]
                # Órdenes para informes
                cur.execute("""
                    SELECT o.id, o.created_at, u.nombre1 || ' ' || u.apellido1 as cliente, o.descripcion, e.descripcion as estado, o.estado as id_estado
                    FROM orders o
                    JOIN usuario u ON o.user_id = u.id_usuario
                    JOIN estados e ON o.estado = e.id_estado
                    ORDER BY o.created_at DESC
                """)
                orders = [{"id": row[0], "fecha": row[1], "cliente": row[2], "descripcion": row[3], "estado": row[4], "id_estado": row[5]} for row in cur.fetchall()]
            finally:
                db.close()

            self.respond(200, render_template(template_name, user=user, products=products, prendas=prendas, telas=telas, estilos=estilos, moldes=moldes, estados=estados, colores=colores, orders=orders))
        
        elif self.path == "/admin/users":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "administrator" not in session_data.get("roles", []):
                self.redirect("/")
                return
            user = auth.get_user_by_id(session_data["user_id"])
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id_usuario, username, correo, enabled FROM users")
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
            if not ok or "administrator" not in session_data.get("roles", []):
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
                    cur.execute("SELECT id_usuario, username, correo, enabled FROM users WHERE username LIKE ?", (f"%{q}%",))
                else:
                    # Si q vacío, cargar todos los usuarios
                    cur.execute("SELECT id_usuario, username, correo, enabled FROM users")
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
            if not ok or "administrator" not in session_data.get("roles", []):
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
        elif self.path == "/admin/estados":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "administrator" not in session_data.get("roles", []):
                self.respond(403, "No autorizado")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id_estado, descripcion FROM estados")
                estados = cur.fetchall()
                estados_list = [{"id": r[0], "descripcion": r[1]} for r in estados]
            finally:
                db.close()
            self.respond(200, json.dumps(estados_list), content_type="application/json")
            return
        elif self.path == "/admin/orders":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "administrator" not in session_data.get("roles", []):
                self.redirect("/")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("""
                    SELECT o.id, o.created_at, u.nombre1 || ' ' || u.apellido1 as cliente, o.descripcion, e.descripcion as estado, o.estado as id_estado
                    FROM orders o
                    JOIN users u ON o.user_id = u.id_usuario
                    JOIN estados e ON o.estado = e.id_estado
                    ORDER BY o.created_at DESC
                """)
                orders = [{"id": row[0], "fecha": row[1], "cliente": row[2], "descripcion": row[3], "estado": row[4], "id_estado": row[5]} for row in cur.fetchall()]
            finally:
                db.close()
            # Render the tbody
            with open(os.path.join(TEMPLATES_DIR, "dashboard_admin.html"), "r", encoding="utf-8") as f:
                content = f.read()
            import re
            m = re.search(r"<!-- loop orders -->(.*?)<!-- endloop -->", content, re.DOTALL)
            if m:
                loop_template = m.group(1)
                rendered = ""
                if not orders:
                    rendered = "<tr><td colspan='4' class='text-center'>No hay pedidos disponibles.</td></tr>"
                else:
                    for item in orders:
                        item_html = loop_template
                        for key, value in item.items():
                            item_html = item_html.replace(f"{{item.{key}}}", str(value))
                        rendered += item_html
                self.respond(200, rendered)
                return
            self.respond(200, "No template found")

        elif self.path == "/logout":
            session = self.get_session()
            auth.logout(session)
            self.redirect("/")
        elif self.path.startswith("/reset-password"):
            # GET: Mostrar formulario de reset si token válido, o forgot si no hay token
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            token = query_params.get('token', [''])[0]

            if token:
                # Verificar token
                user_id = auth.verify_reset_token(token)
                if user_id:
                    self.respond(200, render_template("reset_password.html", token=token, error_message_div="", success_message_div=""))
                else:
                    self.respond(400, render_template("reset_password.html", token="", error_message_div='<div class="alert alert-danger">Token inválido o expirado</div>', success_message_div=""))
            else:
                # Mostrar formulario de solicitud de email
                message_div = ""
                self.respond(200, render_template("forgot_password.html", message_div=message_div))
            return
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
        elif self.path.startswith("/tipos_prenda"):
            # Endpoint para tipos_prenda dependientes de prenda
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            id_prenda = query_params.get('id_prenda', [''])[0]
            if not id_prenda:
                self.respond(400, json.dumps({"error": "id_prenda requerido"}), content_type="application/json")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id_tipo_prenda, nombre FROM tipo_prenda WHERE id_tipo_prenda IN (SELECT id_tipo_prenda FROM prenda WHERE id_prenda = ?)", (int(id_prenda),))
                tipos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
            finally:
                db.close()
            self.respond(200, json.dumps(tipos), content_type="application/json")
            return
        elif self.path.startswith("/estilos_prenda"):
            # Endpoint para estilos dependientes de prenda
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            # Accept either id_tipo_prenda (preferred) or id_prenda.
            id_tipo_prenda = query_params.get('id_tipo_prenda', [''])[0]
            id_prenda = query_params.get('id_prenda', [''])[0]
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                estilos = []
                if id_tipo_prenda:
                    try:
                        cur.execute("SELECT id_tipo_estilo, nombre FROM tipo_estilo WHERE id_tipo_prenda = ?", (int(id_tipo_prenda),))
                        estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                    except Exception:
                        estilos = []
                elif id_prenda:
                    # First try: maybe the caller passed an id_tipo_prenda into id_prenda (common when frontend uses tipo ids)
                    try:
                        cur.execute("SELECT id_tipo_estilo, nombre FROM tipo_estilo WHERE id_tipo_prenda = ?", (int(id_prenda),))
                        estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                    except Exception:
                        estilos = []
                    # If still empty, fall back to resolving id_tipo_prenda from prenda table
                    if not estilos:
                        cur.execute("SELECT id_tipo_prenda FROM prenda WHERE id_prenda = ?", (int(id_prenda),))
                        row = cur.fetchone()
                        if row:
                            cur.execute("SELECT id_tipo_estilo, nombre FROM tipo_estilo WHERE id_tipo_prenda = ?", (row[0],))
                            estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                else:
                    # No parameter provided, return all estilos
                    cur.execute("SELECT id_tipo_estilo, nombre FROM tipo_estilo")
                    estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
            finally:
                db.close()
            self.respond(200, json.dumps(estilos), content_type="application/json")
            return
        elif self.path == "/api/prendas":
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id_tipo_prenda as id, nombre FROM tipo_prenda")
                prendas = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
            finally:
                db.close()
            self.respond(200, json.dumps(prendas), content_type="application/json")
            return
        elif self.path == "/api/user_products":
            # Devuelve JSON con los productos del usuario para refrescar la tabla Informes
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok:
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            user_id = session_data.get("user_id")
            try:
                products = auth.get_user_products(user_id)
                self.respond(200, json.dumps({"ok": True, "products": products}), content_type="application/json")
            except Exception as e:
                print(f"Error devolviendo user_products: {e}")
                self.respond(500, json.dumps({"ok": False, "msg": "Error interno"}), content_type="application/json")
            return
        elif self.path == "/api/estilos":
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                cur.execute("SELECT id_tipo_estilo as id, nombre FROM tipo_estilo")
                estilos = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
            finally:
                db.close()
            self.respond(200, json.dumps(estilos), content_type="application/json")
            return
        elif self.path == "/api/tallas":
            # Devuelve las tallas disponibles desde la columna `talla` en `tipo_molde` (distintas, ordenadas)
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # `molde` no contiene columna `talla` en el esquema actual; leer solo de `tipo_molde`
                cur.execute("""
                    SELECT DISTINCT TRIM(talla) as talla
                    FROM tipo_molde
                    WHERE talla IS NOT NULL AND TRIM(talla) <> ''
                    ORDER BY talla COLLATE NOCASE ASC
                """)
                rows = cur.fetchall()
                tallas = [r[0] for r in rows if r and r[0] is not None]
            finally:
                db.close()
            self.respond(200, json.dumps(tallas), content_type="application/json")
            return
        elif self.path.startswith("/api/catalog/"):
            parts = self.path.split('/')
            if len(parts) == 4:  # /api/catalog/type
                _, _, _, type_ = parts
                session_id = self.get_session()
                ok, session_data = auth.require_session(session_id)
                if not ok or "administrator" not in session_data.get("roles", []):
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                db = sqlite3.connect(settings.DB_PATH)
                try:
                    cur = db.cursor()
                    if type_ == 'color':
                        cur.execute("SELECT id as id, name as nombre, hex_code as codigo_hex FROM colors")
                        items = [{"id": r[0], "nombre": r[1], "codigo_hex": r[2]} for r in cur.fetchall()]
                    elif type_ == 'tela':
                        cur.execute("SELECT id_tipo_tela as id, nombre, descripcion FROM tipo_tela")
                        items = [{"id": r[0], "nombre": r[1], "descripcion": r[2] or ""} for r in cur.fetchall()]
                    elif type_ == 'estilo':
                        print("DEBUG: Entrando a GET /api/catalog/estilo")
                        try:
                            cur.execute("SELECT te.id_tipo_estilo as id, te.nombre, te.descripcion, tp.nombre as prenda_nombre, te.id_tipo_prenda FROM tipo_estilo te LEFT JOIN tipo_prenda tp ON te.id_tipo_prenda = tp.id_tipo_prenda")
                            rows = cur.fetchall()
                            print(f"DEBUG: Filas obtenidas: {len(rows)}")
                            for row in rows:
                                print(f"DEBUG: Row: {row}")
                            items = [{"id": r[0], "nombre": r[1], "descripcion": r[2] or "", "prenda_nombre": r[3] or "", "id_tipo_prenda": r[4]} for r in rows]
                            print(f"DEBUG: Items procesados: {items}")
                        except Exception as e:
                            print(f"DEBUG: Error en consulta SQL: {e}")
                            self.respond(500, json.dumps({"ok": False, "msg": f"Error SQL: {str(e)}"}), content_type="application/json")
                            return
                    elif type_ == 'molde':
                        cur.execute("SELECT id_tipo_molde as id, nombre, descripcion, talla FROM tipo_molde")
                        items = [{"id": r[0], "nombre": r[1], "descripcion": r[2] or "", "talla": r[3] or ""} for r in cur.fetchall()]
                    elif type_ == 'prenda':
                        cur.execute("SELECT id_tipo_prenda as id, nombre FROM tipo_prenda")
                        items = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
                    else:
                        self.respond(400, json.dumps({"ok": False, "msg": "Tipo inválido"}), content_type="application/json")
                        return
                finally:
                    db.close()
                self.respond(200, json.dumps({"ok": True, "items": items}), content_type="application/json")
                return
            else:
                self.respond(404, "Not Found")
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
            if not ok or "administrator" not in session_data.get("roles", []):
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
            first_name = params.get("first_name", [""])[0]
            middle_name = params.get("middle_name", [""])[0]
            last_name = params.get("last_name", [""])[0]
            second_last_name = params.get("second_last_name", [""])[0]
            address1 = params.get("address1", [""])[0]
            address2 = params.get("address2", [""])[0]
            phone1 = params.get("phone1", [""])[0]
            phone2 = params.get("phone2", [""])[0]
            id_tipo_documento = params.get("id_tipo_documento", ["1"])[0]
            ok, msg = auth.create_user(username, email, password, first_name, middle_name, last_name, second_last_name, address1, address2, phone1, phone2, int(id_tipo_documento) if id_tipo_documento else 1)
            if ok:
                self.redirect("/dashboard")
            else:
                error_message_div = f'<div id="error-message" class="alert alert-danger" role="alert">{msg}</div>' if msg else ''
                self.respond(400, render_template("login.html", error_message=msg, error_message_div=error_message_div, username=username, email=email))

        # 🔹 Login de usuario
        elif self.path == "/login":
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg, token, remaining = auth.login(email, password, client_ip)
            if not ok:
                # Mostrar mensaje de error e intentos restantes en la misma página de login
                error_message_div = f'<div id="error-message" class="alert alert-danger" role="alert" style="border: 2px solid #dc3545; padding: 10px; margin-top: 10px;">{msg}</div>' if msg else ''
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
            if not ok or "administrator" not in session_data.get("roles", []):
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
                cur.execute("SELECT enabled FROM users WHERE id_usuario = ?", (user_id,))
                row = cur.fetchone()
                if row is not None:
                    current_enabled = row[0]
                    new_enabled = 0 if current_enabled else 1
                    cur.execute("UPDATE users SET enabled = ? WHERE id_usuario = ?", (new_enabled, user_id))
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
            if not ok or "administrator" not in session_data.get("roles", []):
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
            # No permitir que el admin cambie su propio rol
            if user_id == session_data["user_id"]:
                self.respond(400, "No puedes cambiar tu propio rol.")
                return
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # Eliminar roles actuales
                cur.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
                # Asignar nuevo rol
                cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
                # Obtener el nombre del rol para actualizar el campo 'rol' en users
                cur.execute("SELECT role_name FROM roles WHERE id = ?", (role_id,))
                role_row = cur.fetchone()
                if role_row:
                    role_name = role_row[0]
                    # Actualizar el campo 'rol' en users
                    cur.execute("UPDATE users SET rol = ? WHERE id_usuario = ?", (role_name, user_id))
                db.commit()
            finally:
                db.close()
            self.respond(200, b"ok", content_type="text/plain")
            return
        elif self.path == "/admin/create_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "administrator" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            username = params.get("username", [""])[0]
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            first_name = params.get("first_name", [""])[0]
            middle_name = params.get("middle_name", [""])[0]
            last_name = params.get("last_name", [""])[0]
            second_last_name = params.get("second_last_name", [""])[0]
            id_tipo_documento = params.get("id_tipo_documento", ["1"])[0]
            documento = params.get("documento", [""])[0]
            address1 = params.get("address1", [""])[0]
            address2 = params.get("address2", [""])[0]
            phone1 = params.get("phone1", [""])[0]
            phone2 = params.get("phone2", [""])[0]
            from . import users
            ok, msg = users.create_user(username, email, password, first_name, middle_name, last_name, second_last_name, address1, address2, phone1, phone2, int(id_tipo_documento) if id_tipo_documento else 1, documento)
            if ok:
                self.respond(200, json.dumps({"ok": True}), content_type="application/json")
            else:
                self.respond(400, json.dumps({"ok": False, "msg": msg}), content_type="application/json")
            return
        elif self.path == "/admin/update_user":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok or "administrator" not in session_data.get("roles", []):
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
            if not ok or "administrator" not in session_data.get("roles", []):
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            username = params.get("username", [""])[0]
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                if username:
                    cur.execute("SELECT id_usuario, username, correo, enabled FROM users WHERE username LIKE ?", (f"%{username}%",))
                else:
                    cur.execute("SELECT id_usuario, username, correo, enabled FROM users")
                rows = cur.fetchall()
                users = []
                for row in rows:
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
            finally:
                db.close()
            self.respond(200, json.dumps({"ok": True, "users": users}), content_type="application/json")
            return
        elif self.path == "/crear_prenda":
            session_id = self.get_session()
            ok, session_data = auth.require_session(session_id)
            if not ok:
                self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                return
            nombre = params.get("nombre", [""])[0]
            descripcion = params.get("descripcion", [""])[0]
            id_prenda = params.get("id_prenda", [""])[0]
            id_tipo_prenda = params.get("id_tipo_prenda", [""])[0]
            id_tela = params.get("id_tela", [""])[0]
            id_estilo = params.get("id_estilo", [""])[0]
            id_molde = params.get("id_molde", [""])[0]
            # Estado por defecto, por ejemplo, "En proceso" o similar
            id_estado = 1  # Asumiendo que 1 es "En proceso" o el estado inicial
            if not all([nombre, id_prenda, id_tipo_prenda, id_tela, id_estilo, id_molde]):
                self.respond(400, json.dumps({"ok": False, "msg": "Todos los campos son obligatorios"}), content_type="application/json")
                return
            user_id = session_data["user_id"]
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                # Obtener id_cliente del usuario
                cur.execute("SELECT id_cliente FROM usuario WHERE id_usuario = ?", (user_id,))
                row = cur.fetchone()
                if not row:
                    self.respond(400, json.dumps({"ok": False, "msg": "Usuario no encontrado"}), content_type="application/json")
                    return
                id_cliente = row[0]
                cur.execute("""
                    INSERT INTO producto (descripcion, id_prenda, id_estilo, id_molde, id_tela, id_estado, id_cliente, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (descripcion, int(id_prenda), int(id_estilo), int(id_molde), int(id_tela), id_estado, id_cliente))
                product_id = cur.lastrowid
                db.commit()
                log_db_action(user_id, f"CREATED PRODUCT {product_id}")
            except sqlite3.IntegrityError as e:
                self.respond(400, json.dumps({"ok": False, "msg": f"Error de integridad: {str(e)}"}), content_type="application/json")
                return
            finally:
                db.close()
            self.respond(200, json.dumps({"ok": True, "msg": "Prenda creada exitosamente"}), content_type="application/json")
            return
        elif self.path == "/api/guardar-diseno":
            # Recibe JSON con diseño y lo guarda en la tabla producto (y deja copia JSONL)
            try:
                payload = json.loads(body) if body else {}
            except Exception as e:
                self.respond(400, json.dumps({"ok": False, "msg": "JSON inválido"}), content_type="application/json")
                return

            # Permitir header de depuración `X-Debug-User` desde localhost para pruebas locales
            debug_user = self.headers.get('X-Debug-User')
            user_id = None
            if debug_user and self.client_address[0] in ('127.0.0.1', '::1', 'localhost'):
                try:
                    user_id = int(debug_user)
                except Exception:
                    user_id = None
            else:
                # Requerir sesión para asociar cliente
                session_id = self.get_session()
                if not session_id:
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                auth_ok, session_data = auth.require_session(session_id)
                if not auth_ok:
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                user_id = session_data.get("user_id")

            # Normalizar campos que el frontend puede enviar (soporta tanto id/label como la antigua forma)
            tipo_id = payload.get('tipo_id') or payload.get('tipo')
            estilo_id = payload.get('estilo_id') or payload.get('estilo')
            tela_id = payload.get('tela_id') or payload.get('tela')
            # id_talla may come as id_talla, talla_id or simple talla (string)
            id_talla_payload = payload.get('id_talla') or payload.get('talla_id') or payload.get('talla')
            color = payload.get('color') or ''
            modo = payload.get('modo') or payload.get('mode') or 'basico'
            talla = payload.get('talla') or ''
            medidas = payload.get('medidas') if isinstance(payload.get('medidas'), dict) else None
            # Determina si se debe guardar como producto (solo por acción explícita)
            save_as_product = payload.get('save_as_product')
            if isinstance(save_as_product, str):
                save_as_product = save_as_product.lower() in ('1', 'true', 'yes')
            else:
                save_as_product = bool(save_as_product)

            # Construir descripción legible para guardar en producto.descripcion
            tipo_label = payload.get('tipo_label') or ''
            estilo_label = payload.get('estilo_label') or ''
            tela_label = payload.get('tela_label') or ''
            desc_parts = []
            if tipo_label:
                desc_parts.append(str(tipo_label))
            elif tipo_id:
                desc_parts.append(f"tipo:{tipo_id}")
            if estilo_label:
                desc_parts.append(str(estilo_label))
            elif estilo_id:
                desc_parts.append(f"estilo:{estilo_id}")
            if tela_label:
                desc_parts.append(str(tela_label))
            elif tela_id:
                desc_parts.append(f"tela:{tela_id}")
            if color:
                desc_parts.append(f"color:{color}")
            if talla:
                desc_parts.append(f"talla:{talla}")
            description = ' | '.join(desc_parts) or ''

            # Obtener id_cliente desde la tabla usuario
            id_cliente = None
            db = sqlite3.connect(settings.DB_PATH)
            try:
                cur = db.cursor()
                try:
                    cur.execute("SELECT id_cliente FROM usuario WHERE id_usuario = ?", (user_id,))
                    row = cur.fetchone()
                    if row:
                        id_cliente = row[0]
                except Exception:
                    id_cliente = None
                # Si no se solicitó guardar como producto, solo escribir backup JSONL y devolver ok
                if not save_as_product:
                    product_id = None
                    try:
                        record = {
                            "ts": datetime.utcnow().isoformat() + "Z",
                            "user_id": user_id,
                            "client_ip": client_ip,
                            "design": payload,
                            "saved_product_id": None
                        }
                        save_path = os.path.join(ROOT_DIR, 'db', 'guardados.jsonl')
                        os.makedirs(os.path.dirname(save_path), exist_ok=True)
                        with open(save_path, 'a', encoding='utf-8') as f:
                            f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    except Exception as e:
                        print(f"Warning: no se pudo escribir JSONL de backup: {e}")
                    self.respond(200, json.dumps({"ok": True, "msg": "Backup guardado (no insertado como producto)"}), content_type="application/json")
                    return

                # Protección contra duplicados: buscar inserciones muy recientes iguales (10s)
                try:
                    # Normalizar ids a enteros o None
                    tid = int(tipo_id) if tipo_id not in (None, '') else None
                    seid = int(estilo_id) if estilo_id not in (None, '') else None
                    tid_tela = int(tela_id) if tela_id not in (None, '') else None
                    # id_talla may be non-numeric (strings like 'M'), keep as-is
                    tt = id_talla_payload if id_talla_payload not in (None, '') else None
                except Exception:
                    tid = seid = tid_tela = None

                try:
                    cur.execute("""
                        SELECT id_producto FROM producto
                        WHERE id_cliente = ?
                            AND COALESCE(id_prenda, -1) = COALESCE(?, -1)
                            AND COALESCE(id_estilo, -1) = COALESCE(?, -1)
                            AND COALESCE(id_tela, -1) = COALESCE(?, -1)
                            AND COALESCE(CAST(id_talla AS TEXT), '') = COALESCE(?, '')
                            AND descripcion = ?
                            AND created_at >= datetime('now', '-10 seconds')
                        LIMIT 1
                    """, (id_cliente, tid, seid, tid_tela, tt or '', description))
                    dup = cur.fetchone()
                    if dup:
                        product_id = dup[0]
                        # No insertar duplicado; devolver el id existente
                        db.commit()
                        self.respond(200, json.dumps({"ok": True, "msg": "Diseño ya guardado recientemente", "product_id": product_id}), content_type="application/json")
                        return
                except Exception as e:
                    # Si la verificación falla, continuar con el insert y reportar si falla después
                    print(f"Warning: falla verificación duplicado: {e}")

                # Insertar en producto con estado por defecto = 1
                try:
                    # Intentar obtener id_molde enviado desde el frontend (molde_id, id_molde o molde)
                    raw_molde = payload.get('molde_id') or payload.get('id_molde') or payload.get('molde')
                    try:
                        mid = int(raw_molde) if raw_molde not in (None, '') else None
                    except Exception:
                        mid = None

                    # Only persist id_molde if mode is advanced
                    if modo != 'avanzado':
                        mid_to_store = None
                    else:
                        mid_to_store = mid

                    # id_talla: store as text (may be string like 'M')
                    id_talla_to_store = tt if tt is not None else None

                    cur.execute(
                        "INSERT INTO producto (descripcion, id_prenda, id_estilo, id_molde, id_tela, id_talla, id_estado, id_cliente, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        (
                            description,
                            tid,
                            seid,
                            mid_to_store,
                            tid_tela,
                            id_talla_to_store,
                            1,  # estado predeterminado
                            id_cliente
                        )
                    )
                    db.commit()
                    product_id = cur.lastrowid
                    # Log de auditoría
                    log_db_action(user_id, f"SAVED_DESIGN_AS_PRODUCT {product_id}")
                except Exception as e:
                    db.rollback()
                    print(f"Error insertando producto: {e}")
                    self.respond(500, json.dumps({"ok": False, "msg": f"Error al insertar producto: {str(e)}"}), content_type="application/json")
                    return
            finally:
                db.close()

            # Guardar copia JSONL (backup) con metadatos
            try:
                record = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "user_id": user_id,
                    "client_ip": client_ip,
                    "design": payload,
                    "saved_product_id": product_id
                }
                save_path = os.path.join(ROOT_DIR, 'db', 'guardados.jsonl')
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                with open(save_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception as e:
                print(f"Warning: no se pudo escribir JSONL de backup: {e}")

            self.respond(200, json.dumps({"ok": True, "msg": "Guardado como producto", "product_id": product_id}), content_type="application/json")
            return
        elif self.path.startswith("/api/catalog/"):
            parts = self.path.split('/')
            if len(parts) == 4:  # /api/catalog/type
                _, _, _, type_ = parts
                session_id = self.get_session()
                ok, session_data = auth.require_session(session_id)
                if not ok or "administrator" not in session_data.get("roles", []):
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                # Parsear como form data, no JSON
                data = {k: v[0] for k, v in params.items()}
                db = sqlite3.connect(settings.DB_PATH)
                try:
                    cur = db.cursor()
                    if type_ == 'color':
                        print(f"DEBUG: Intentando crear color - nombre: {data.get('nombre')}, hex_code: {data.get('codigo_hex')}")
                        nombre = data.get("nombre")
                        hex_code = data.get("codigo_hex")
                        if not nombre or not hex_code:
                            print("DEBUG: Falla - Nombre o hex_code faltante")
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre y codigo_hex requeridos"}), content_type="application/json")
                            return
                        print("DEBUG: Datos válidos, verificando existencia...")
                        # Verificar si ya existe
                        cur.execute("SELECT 1 FROM colors WHERE name = ? OR hex_code = ?", (nombre, hex_code))
                        if cur.fetchone():
                            print("DEBUG: Falla - Color ya existe")
                            self.respond(400, json.dumps({"ok": False, "msg": "Color ya existe"}), content_type="application/json")
                            return
                        print("DEBUG: Color no existe, insertando...")
                        cur.execute("INSERT INTO colors (name, hex_code) VALUES (?, ?)", (nombre, hex_code))
                        print("DEBUG: Inserción completada")
                    elif type_ == 'tela':
                        nombre = data.get("nombre")
                        descripcion = data.get("descripcion")
                        if not nombre or not descripcion:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre y descripcion requeridos"}), content_type="application/json")
                            return
                        cur.execute("INSERT INTO tipo_tela (nombre, descripcion) VALUES (?, ?)", (nombre, descripcion))
                    elif type_ == 'estilo':
                        nombre = data.get("nombre")
                        id_prenda = data.get("id_prenda")
                        if not nombre or not id_prenda:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre e id_prenda requeridos"}), content_type="application/json")
                            return
                        cur.execute("INSERT INTO tipo_estilo (nombre, id_tipo_prenda) VALUES (?, ?)", (nombre, int(id_prenda)))
                    elif type_ == 'molde':
                        nombre = data.get("nombre")
                        descripcion = data.get("descripcion")
                        talla = data.get("talla")
                        if not nombre or not descripcion or not talla:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre, descripcion y talla requeridos"}), content_type="application/json")
                            return
                        cur.execute("INSERT INTO tipo_molde (nombre, descripcion, talla) VALUES (?, ?, ?)", (nombre, descripcion, talla))
                    elif type_ == 'prenda':
                        nombre = data.get("nombre")
                        if not nombre:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre requerido"}), content_type="application/json")
                            return
                        cur.execute("INSERT INTO tipo_prenda (nombre) VALUES (?)", (nombre,))
                    else:
                        self.respond(400, json.dumps({"ok": False, "msg": "Tipo inválido"}), content_type="application/json")
                        return
                    db.commit()
                except sqlite3.IntegrityError as e:
                    self.respond(400, json.dumps({"ok": False, "msg": f"Error de integridad: {str(e)}"}), content_type="application/json")
                    return
                finally:
                    db.close()
                self.respond(200, json.dumps({"ok": True, "msg": f"{type_} agregado exitosamente"}), content_type="application/json")
                return
            else:
                self.respond(404, "Not Found")
        elif self.path == "/reset-password":
            # POST: Procesar reset de contraseña o solicitud de email
            token = params.get("token", [""])[0]
            if token:
                # Procesar nueva contraseña
                new_password = params.get("password", [""])[0]
                confirm_password = params.get("password2", [""])[0]  # Cambiado a password2
                if new_password != confirm_password:
                    self.respond(400, render_template("reset_password.html", error_message_div='<div class="alert alert-danger">Las contraseñas no coinciden</div>', success_message_div="", token=token))
                    return
                ok, msg = auth.reset_user_password(token, new_password)
                if ok:
                    self.respond(200, render_template("reset_password.html", success_message_div='<div class="alert alert-success">Contraseña cambiada exitosamente.</div>', error_message_div="", token=""))
                else:
                    self.respond(400, render_template("reset_password.html", error_message_div=f'<div class="alert alert-danger">{msg}</div>', success_message_div="", token=token))
            else:
                # Solicitar reset por email
                email = params.get("email", [""])[0]
                ok, msg = auth.request_password_reset(email)
                message_div = f'<div class="alert alert-info">{msg}</div>' if msg else ""
                self.respond(200, render_template("forgot_password.html", message_div=message_div))
            return
        else:
            self.respond(404, "Not Found")

    def do_PUT(self):
        """Maneja las peticiones PUT: editar items del catálogo."""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        client_ip = self.client_address[0]

        if self.path.startswith("/api/catalog/"):
            parts = self.path.split('/')
            if len(parts) == 5:  # /api/catalog/type/id
                _, _, _, type_, id_ = parts
                session_id = self.get_session()
                ok, session_data = auth.require_session(session_id)
                if not ok or "administrator" not in session_data.get("roles", []):
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                data = {k: v[0] for k, v in params.items()}
                db = sqlite3.connect(settings.DB_PATH)
                try:
                    cur = db.cursor()
                    if type_ == 'color':
                        nombre = data.get("nombre")
                        hex_code = data.get("codigo_hex")
                        if not nombre or not hex_code:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre y codigo_hex requeridos"}), content_type="application/json")
                            return
                        if len(nombre) > 20:
                            self.respond(400, json.dumps({"ok": False, "msg": "El nombre no puede exceder 20 caracteres"}), content_type="application/json")
                            return
                        cur.execute("UPDATE colors SET name = ?, hex_code = ? WHERE id = ?", (nombre, hex_code, int(id_)))
                    elif type_ == 'tela':
                        nombre = data.get("nombre")
                        if not nombre:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre requerido"}), content_type="application/json")
                            return
                        cur.execute("UPDATE tipo_tela SET nombre = ? WHERE id_tipo_tela = ?", (nombre, int(id_)))
                    elif type_ == 'estilo':
                        nombre = data.get("nombre")
                        id_prenda = data.get("id_prenda")
                        if not nombre or not id_prenda:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre e id_prenda requeridos"}), content_type="application/json")
                            return
                        cur.execute("UPDATE tipo_estilo SET nombre = ?, descripcion = ? WHERE id_tipo_estilo = ?", (nombre, str(id_prenda), int(id_)))
                    elif type_ == 'molde':
                        nombre = data.get("nombre")
                        descripcion = data.get("descripcion")
                        talla = data.get("talla")
                        if not nombre or not descripcion or not talla:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre, descripcion y talla requeridos"}), content_type="application/json")
                            return
                        cur.execute("UPDATE tipo_molde SET nombre = ?, descripcion = ?, talla = ? WHERE id_tipo_molde = ?", (nombre, descripcion, talla, int(id_)))
                    elif type_ == 'prenda':
                        nombre = data.get("nombre")
                        if not nombre:
                            self.respond(400, json.dumps({"ok": False, "msg": "Nombre requerido"}), content_type="application/json")
                            return
                        cur.execute("UPDATE tipo_prenda SET nombre = ? WHERE id_tipo_prenda = ?", (nombre, int(id_)))
                    else:
                        self.respond(400, json.dumps({"ok": False, "msg": "Tipo inválido"}), content_type="application/json")
                        return
                    if cur.rowcount == 0:
                        self.respond(404, json.dumps({"ok": False, "msg": "Item no encontrado"}), content_type="application/json")
                        return
                    db.commit()
                except sqlite3.IntegrityError as e:
                    self.respond(400, json.dumps({"ok": False, "msg": f"Error de integridad: {str(e)}"}), content_type="application/json")
                    return
                finally:
                    db.close()
                self.respond(200, json.dumps({"ok": True, "msg": f"{type_} actualizado exitosamente"}), content_type="application/json")
                return
            else:
                self.respond(404, "Not Found")
        else:
            self.respond(404, "Not Found")

    def do_DELETE(self):
        """Maneja las peticiones DELETE: eliminar items del catálogo."""
        if self.path.startswith("/api/catalog/"):
            parts = self.path.split('/')
            if len(parts) == 5:  # /api/catalog/type/id
                _, _, _, type_, id_ = parts
                session_id = self.get_session()
                ok, session_data = auth.require_session(session_id)
                if not ok or "administrator" not in session_data.get("roles", []):
                    self.respond(403, json.dumps({"ok": False, "msg": "No autorizado"}), content_type="application/json")
                    return
                db = sqlite3.connect(settings.DB_PATH)
                try:
                    cur = db.cursor()
                    if type_ == 'color':
                        cur.execute("DELETE FROM colors WHERE id = ?", (int(id_),))
                    elif type_ == 'tela':
                        cur.execute("DELETE FROM tipo_tela WHERE id_tipo_tela = ?", (int(id_),))
                    elif type_ == 'estilo':
                        cur.execute("DELETE FROM tipo_estilo WHERE id_tipo_estilo = ?", (int(id_),))
                    elif type_ == 'molde':
                        cur.execute("DELETE FROM tipo_molde WHERE id_tipo_molde = ?", (int(id_),))
                    elif type_ == 'prenda':
                        cur.execute("DELETE FROM tipo_prenda WHERE id_tipo_prenda = ?", (int(id_),))
                    else:
                        self.respond(400, json.dumps({"ok": False, "msg": "Tipo inválido"}), content_type="application/json")
                        return
                    if cur.rowcount == 0:
                        self.respond(404, json.dumps({"ok": False, "msg": "Item no encontrado"}), content_type="application/json")
                        return
                    db.commit()
                except sqlite3.IntegrityError as e:
                    self.respond(400, json.dumps({"ok": False, "msg": f"Error de integridad: {str(e)}"}), content_type="application/json")
                    return
                finally:
                    db.close()
                self.respond(200, json.dumps({"ok": True, "msg": f"{type_} eliminado exitosamente"}), content_type="application/json")
                return
            else:
                self.respond(404, "Not Found")
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
        """Envía una respuesta HTTP con el código, cuerpo y tipo de contenido, manejando conexiones abortadas."""
        try:
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            # Enviar en chunks para respuestas grandes
            chunk_size = 8192
            for i in range(0, len(body), chunk_size):
                self.wfile.write(body[i:i+chunk_size])
        except (ConnectionAbortedError, BrokenPipeError):
            # Cliente cerró la conexión, ignorar para no romper el servidor
            pass


def run():
    os.chdir(os.path.dirname(__file__))

    use_tls = False  # Force HTTP for development to avoid cert issues
    port = settings.PORT  # Use HTTP port 8080
    server_address = (settings.HOST, port)

    httpd = HTTPServer(server_address, Handler)

    if use_tls:
        security.wrap_socket(httpd)
        print(f"✅ Server running with TLS on https://{settings.HOST}:{port}")
    else:
        print(f"⚠️ Running without TLS on http://{settings.HOST}:{port}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server")
    finally:
        httpd.server_close()
        



if __name__ == "__main__":
    run()
