# app/main.py
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import os, json
from config import settings
from . import auth, maintenance, security
from .audit import log_db_action
import sqlite3

import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

def render_template(name, **ctx):
    with open(os.path.join(TEMPLATES_DIR, name), "r", encoding="utf-8") as f:
        return f.read().format(**ctx)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if maintenance.is_maintenance():
            self.respond(200, render_template("maintenance.html"))
            return
        if self.path == "/":
            self.respond(200, render_template("login.html"))
        elif self.path == "/register":
            self.respond(200, render_template("register.html"))
        elif self.path == "/dashboard":
            # check session cookie
            session = self.get_session()
            ok, s = auth.require_session(session) if session else (False, None)
            if not ok:
                self.redirect("/")
                return
            self.respond(200, render_template("dashboard.html"))
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
        if self.path == "/register":
            username = params.get("username", [""])[0]
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg = auth.create_user(username, email, password)
            if ok:
                self.respond(200, f"OK: {msg}")
            else:
                self.respond(400, render_template("error.html", message=msg))
        elif self.path == "/login":
            email = params.get("email", [""])[0]
            password = params.get("password", [""])[0]
            ok, msg, token = auth.login(email, password, client_ip)
            if not ok:
                self.respond(403, render_template("error.html", message=msg))
                return
            # send page asking for 2FA code
            html = f"""
                <html><body>
                <h2>{msg}</h2>
                <form action="/verify-2fa" method="post">
                Código 2FA: <input name="code" /><br/>
                Token: <input name="token" value="{token}" type="hidden" />
                <button type="submit">Verificar</button>
                </form>
                </body></html>
            """
            self.respond(200, html)
        elif self.path == "/verify-2fa":
            token = params.get("token", [""])[0]
            code = params.get("code", [""])[0]
            ok, msg, session_id = auth.verify_2fa(token, code, client_ip)
            if not ok:
                self.respond(403, render_template("error.html", message=msg))
                return
            # set cookie
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
    os.chdir(os.path.dirname(__file__))  # ensure relative paths ok
    server_address = ("", settings.HTTPS_PORT)
    httpd = HTTPServer(server_address, Handler)
    # TLS
    if security.ensure_certs_exist():
        security.wrap_socket(httpd)
        print(f"Server running with TLS on port {settings.HTTPS_PORT}")
    else:
        print("CERTS not found; running without TLS on port 8080")
        httpd.server_address = ("", 8080)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    run()
