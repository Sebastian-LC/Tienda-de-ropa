# app/audit.py
# Este módulo maneja el registro de auditoría y accesos para el sistema.
# Proporciona funciones para loguear acciones de usuarios y intentos de login.

import sqlite3
from config import settings
from datetime import datetime
import os

def log_db_action(user_id, action):
    """
    Registra una acción en la base de datos y en el log de auditoría.

    Args:
        user_id (int): ID del usuario que realizó la acción.
        action (str): Descripción de la acción realizada.

    Esta función inserta un registro en la tabla 'audit_log' de la base de datos
    y también escribe una entrada legible por humanos en el archivo de log de auditoría.
    """
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("INSERT INTO audit_log (user_id, action) VALUES (?, ?)", (user_id, action))
        db.commit()
    finally:
        db.close()
    # También agrega una entrada legible por humanos en el log de auditoría
    os.makedirs(os.path.dirname(settings.AUDIT_LOG), exist_ok=True)
    with open(settings.AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} | user:{user_id} | {action}\n")

def log_access_attempt(user_id, ip, success):
    """
    Registra un intento de acceso (login) en la base de datos y log de accesos.

    Args:
        user_id (int or None): ID del usuario que intentó acceder (None si no se encontró).
        ip (str): Dirección IP desde donde se realizó el intento.
        success (bool): True si el intento fue exitoso, False en caso contrario.

    Esta función inserta un registro en la tabla 'access_log' de la base de datos
    y también escribe una entrada en el archivo de log de accesos.
    """
    db = sqlite3.connect(settings.DB_PATH)
    try:
        db.execute("INSERT INTO access_log (user_id, ip_address, success) VALUES (?, ?, ?)", (user_id, ip, int(bool(success))))
        db.commit()
    finally:
        db.close()
    os.makedirs(os.path.dirname(settings.ACCESS_LOG), exist_ok=True)
    with open(settings.ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} | ip:{ip} | user:{user_id} | success:{int(bool(success))}\n")
