# app/utils.py
import os, hashlib, binascii, hmac, random, smtplib
from email.message import EmailMessage
from datetime import datetime

from config import settings

def gen_salt(n=16):
    """Genera un salt aleatorio en hexadecimal."""
    return binascii.hexlify(os.urandom(n)).decode()

def hash_password(password, salt, iterations=100_000):
    """Genera el hash de una contraseña usando PBKDF2-HMAC-SHA256."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), binascii.unhexlify(salt), iterations)
    return binascii.hexlify(dk).decode()

def verify_password(password, salt_hex, stored_hash):
    """Verifica si la contraseña y salt generan el hash esperado."""
    if ":" in stored_hash:
        # Nuevo formato: salt:hash
        salt_hex, stored_hash = stored_hash.split(":", 1)
    return hash_password(password, salt_hex) == stored_hash

def gen_2fa_code():
    """Genera un código 2FA de 6 dígitos aleatorio."""
    return f"{random.randint(0,999999):06d}"

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import settings

def send_email(to_email, subject, message, html=False):
    """Envía un correo electrónico usando SMTP y los datos de settings."""
    print(f"DEBUG: Intentando enviar email a {to_email} con subject '{subject}'")
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = settings.SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        if html:
            msg.attach(MIMEText(message, "html", "utf-8"))
        else:
            msg.attach(MIMEText(message, "plain", "utf-8"))

        print(f"DEBUG: Conectando a SMTP {settings.SMTP_SERVER}:{settings.SMTP_PORT}")
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            print(f"DEBUG: Logueando con user {settings.SMTP_USER}")
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            print("DEBUG: Enviando mensaje")
            server.send_message(msg)
            print("DEBUG: Email enviado exitosamente")

        return True
    except Exception as e:
        print(f"DEBUG: Failed to send email: {e}")
        import traceback
        traceback.print_exc()
        return False



def build_2fa_email(username: str, code: str) -> str:
    """Construye el HTML del correo para el código 2FA."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <table style="max-width: 500px; margin: auto; background: #ffffff; border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1); padding: 20px;">
        <tr>
            <td style="text-align: center;">
            <h2 style="color: #8c734a;">JAANSTYLE</h2>
            <p style="font-size: 16px; color: #333;">Hola <b>{username}</b>,</p>
            <p style="font-size: 15px; color: #333;">
                Tu código de verificación en dos pasos es:
            </p>
            <div style="font-size: 28px; font-weight: bold;
                        background: #8c734a; color: white;
                        padding: 12px 20px; border-radius: 8px;
                        display: inline-block; letter-spacing: 3px;">
                {code}
            </div>
            <p style="margin-top: 20px; font-size: 13px; color: #666;">
                Este código expirará en 5 minutos.<br/>
                Si no solicitaste este inicio de sesión, por favor ignora este mensaje.
            </p>
            </td>
        </tr>
        </table>
    </body>
    </html>
    """

def build_reset_email(token: str) -> str:
    """Construye el HTML del correo para recuperación de contraseña."""
    reset_url = f"http://localhost:8080/reset-password?token={token}"
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <table style="max-width: 500px; margin: auto; background: #ffffff; border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1); padding: 20px;">
        <tr>
            <td style="text-align: center;">
            <h2 style="color: #8c734a;">JAANSTYLE</h2>
            <p style="font-size: 16px; color: #333;">Recuperación de contraseña</p>
            <p style="font-size: 15px; color: #333;">
                Has solicitado restablecer tu contraseña. Haz clic en el botón de abajo para continuar:
            </p>
            <a href="{reset_url}" style="background: #8c734a; color: white; padding: 12px 20px;
               text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
               Restablecer contraseña
            </a>
            <p style="margin-top: 20px; font-size: 13px; color: #666;">
                Este enlace expirará en 30 minutos.<br/>
                Si no solicitaste este cambio, por favor ignora este mensaje.
            </p>
            <p style="font-size: 12px; color: #999;">
                Si el botón no funciona, copia y pega esta URL en tu navegador:<br/>
                {reset_url}
            </p>
            </td>
        </tr>
        </table>
    </body>
    </html>
    """


def now():
    """Retorna la fecha y hora actual en formato ISO (UTC)."""
    return datetime.utcnow().isoformat(timespec='seconds')


