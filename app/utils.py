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

#def send_email(to_address, subject, body):
    # Usa SMTP configurado en settings; para pruebas puedes poner SMTP de Gmail (requiere app password)
    #msg = EmailMessage()
    #msg["From"] = settings.EMAIL_FROM
    #msg["To"] = to_address
    #msg["Subject"] = subject
    #msg.set_content(body)

    #with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
        #s.starttls()
        #s.login(settings.SMTP_USER, settings.SMTP_PASS)
        #s.send_message(msg)

def send_email(to_address, subject, body):
    with open("../logs/access_attempts.log", "a", encoding="utf-8") as f:
        f.write(f"{now()} | EMAIL_TO:{to_address} | SUBJ:{subject} | BODY:{body}\\n")


def now():
    return datetime.utcnow().isoformat(timespec='seconds')
