import os

# Ruta base del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

# Configuración de correo (para HU-03: 2FA por correo)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "tu_correo@gmail.com"
SMTP_PASSWORD = "tu_contraseña_de_aplicacion"

# Mensaje de mantenimiento
MAINTENANCE_MESSAGE = "El sistema está en mantenimiento, por favor intente más tarde."
# Archivo que activa/desactiva el modo mantenimiento
MAINTENANCE_FLAG_FILE = os.path.join(BASE_DIR, "maintenance.flag")
