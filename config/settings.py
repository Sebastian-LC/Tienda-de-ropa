import os

# Ruta base del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Base de datos
DB_PATH = os.path.join(BASE_DIR, "db", "database.sqlite")
AUDIT_LOG = os.path.join(BASE_DIR, "logs", "audit.log")
ACCESS_LOG = os.path.join(BASE_DIR, "logs", "access_attempts.log")


# Configuración del servidor
HOST = "localhost"
PORT = 8080
HTTPS_PORT = 4443  # reservado para cuando uses HTTPS

# Desactivar certificados (solo HTTP en pruebas)
CERTFILE = None
KEYFILE = None

# Seguridad básica
SESSION_TIMEOUT = 300
MAX_FAILED_ATTEMPTS = 3

# Tiempo de expiración de sesión en segundos (ej: 30 minutos)
SESSION_TIMEOUT_SECONDS = 1800  # 30 minutos


# Configuración de correo (para HU-03: 2FA por correo)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "sebastianlongas2027@gmail.com"
SMTP_PASSWORD = "bnfo daqj mbau bsem"

# Mensaje de mantenimiento
MAINTENANCE_MESSAGE = "El sistema está en mantenimiento, por favor intente más tarde."
# Archivo que activa/desactiva el modo mantenimiento
MAINTENANCE_FLAG_FILE = os.path.join(BASE_DIR, "maintenance.flag")
