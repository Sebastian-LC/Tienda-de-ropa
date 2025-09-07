import sys, os

# 🔧 Fix: aseguramos que la raíz (un nivel arriba de /app) esté en sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import json
import sqlite3
import re

# Ahora ya puede importar config y los módulos locales
from config import settings
from . import auth, maintenance, security
from .audit import log_db_action

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

def render_template(name, **ctx):
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
        
        rendered_loop = ""
        if not items:
            return "<tr><td colspan='99' class='text-center'>No hay datos.</td></tr>"

        for item in items:
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

    # Handle simple variables like {message}
    for key, value in ctx.items():
        if not isinstance(value, (dict, list)):
            content = content.replace(f"{{{key}}}", str(value))

    return content


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if maintenance.is_maintenance():
            self.respond(200, render_template("maintenance.html"))
            return

        if self.path == "/":
            self.respond(200, render_template("login.html"))
        elif self.path == "/forms":
            self.respond(200, render_template("forms.html"))
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
        elif self.path == "/logout":
            session = self.get_session()
            auth.logout(session)
            self.redirect("/")
        else:
            self.respond(404, "Not Found")

    def do_POST(self):
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

        if self.path == "/forms":
            username = params.get("username", [""])[0]   # ✅ usar 'username'
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg = auth.create_user(username, email, password)
            if ok:
                self.redirect("/dashboard")
            else:
                self.respond(400, render_template("error.html", message=msg))



        # 🔹 Login de usuario
        elif self.path == "/login":
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg, token = auth.login(email, password, client_ip)
            if not ok:
                self.respond(403, render_template("error.html", message=msg))
                return
            html = f"""
                <html><body>
                <h2>{msg}</h2>
                <form action="/verify-2fa" method="post">
                Código 2FA: <input name="code" /><br/>
                <input name="token" value="{token}" type="hidden" />
                <button type="submit">Verificar</button>
                </form>
                </body></html>
            """
            self.respond(200, html)

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

        else:
            self.respond(404, "Not Found")

    def get_session(self):
        cookie = self.headers.get("Cookie")
        if not cookie:
            return None
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session_id":
                return v
        return None

    def redirect(self, path):
        self.send_response(302)
        self.send_header("Location", path)
        self.end_headers()

    def respond(self, code, body, content_type="text/html"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run():
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
