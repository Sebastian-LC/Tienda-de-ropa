# app/utils.py
import os, hashlib, binascii, hmac, random, smtplib
from email.message import EmailMessage
from datetime import datetime

from config import settings

def gen_salt(n=16):
    return binascii.hexlify(os.urandom(n)).decode()

def hash_password(password, salt, iterations=100_000):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), binascii.unhexlify(salt), iterations)
    return binascii.hexlify(dk).decode()

def verify_password(password, salt_hex, stored_hash):
    return hash_password(password, salt_hex) == stored_hash

def gen_2fa_code():
    return f"{random.randint(0,999999):06d}"

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = settings.SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    # 🔧 Forzar UTF-8
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, to_email, msg.as_string())
    except Exception as e:
        print("Failed to send email:", e)
        raise



def now():
    return datetime.utcnow().isoformat(timespec='seconds')
