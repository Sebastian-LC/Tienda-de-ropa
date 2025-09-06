# app/maintenance.py
import os
from config import settings

def enable_maintenance():
    open(settings.MAINTENANCE_FLAG_FILE, "w").close()

def disable_maintenance():
    if os.path.exists(settings.MAINTENANCE_FLAG_FILE):
        os.remove(settings.MAINTENANCE_FLAG_FILE)

def is_maintenance():
    return os.path.exists(settings.MAINTENANCE_FLAG_FILE)
