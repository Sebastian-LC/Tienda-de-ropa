# app/security.py
import ssl
from config import settings
import os

def ensure_certs_exist():
    from config import settings
    return settings.CERTFILE and settings.KEYFILE and \
        os.path.exists(settings.CERTFILE) and os.path.exists(settings.KEYFILE)

def wrap_socket(server):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=settings.CERTFILE, keyfile=settings.KEYFILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
