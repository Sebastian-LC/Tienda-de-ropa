# Configuración global del sistema

# Tiempo máximo de inactividad antes de cerrar sesión (segundos)
SESSION_TIMEOUT = 300  # 5 minutos

# Intentos fallidos antes de bloquear usuario
MAX_FAILED_ATTEMPTS = 3

# Configuración del servidor
HOST = "localhost"
PORT = 8080

# Configuración para 2FA por correo
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "sebastianlongas2027@gmail.com"
SMTP_PASSWORD = "sebastian64"  # NO tu clave normal, usa clave de aplicación

# Mensaje de mantenimiento
MAINTENANCE_MESSAGE = "El sistema está en mantenimiento, por favor intente más tarde."
