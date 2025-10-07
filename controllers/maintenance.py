# app/maintenance.py
import os
from config import settings

def enable_maintenance():
    """Activa el modo mantenimiento creando el archivo de flag."""
    open(settings.MAINTENANCE_FLAG_FILE, "w").close()

def disable_maintenance():
    """Desactiva el modo mantenimiento eliminando el archivo de flag."""
    if os.path.exists(settings.MAINTENANCE_FLAG_FILE):
        os.remove(settings.MAINTENANCE_FLAG_FILE)

def is_maintenance():
    """Retorna True si el sistema está en modo mantenimiento."""
    return os.path.exists(settings.MAINTENANCE_FLAG_FILE)
