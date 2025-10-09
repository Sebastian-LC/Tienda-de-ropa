# Diagnóstico del problema con envío de correos de verificación

## Información recopilada
- El servidor se inicia correctamente con ambos comandos.
- Los comandos son:
  - `python -m controllers.main` (desde cualquier directorio)
  - `powershell -Command "cd Tienda-de-ropa-Cambio-de-estructura; python -m controllers.main"`
- Los correos no se envían en el segundo caso.
- Rutas calculadas: ROOT_DIR y BASE_DIR son absolutas y deberían ser iguales.
- Envío de correos usa SMTP fijo, sin dependencias de rutas.

## Plan de diagnóstico
- [x] Añadir prints de debug en run() para mostrar ROOT_DIR, BASE_DIR, DB_PATH, ACCESS_LOG y cwd.
- [x] Añadir prints detallados en send_email para rastrear el proceso de envío.
- [ ] Ejecutar el servidor en el entorno problemático con el comando alternativo.
- [ ] Intentar login para enviar correo y capturar la salida de consola.
- [ ] Revisar logs/access_attempts.log para errores SMTP.
- [ ] Verificar que el directorio raíz tenga el mismo nombre en ambos entornos.
- [ ] Verificar conectividad a smtp.gmail.com:587 en el entorno problemático.
- [ ] Si falla, probar cambiar SMTP_PORT a 465 y usar SSL en lugar de starttls.

## Posibles causas
1. Diferencia en el nombre del directorio raíz causando rutas incorrectas (aunque absolutas).
2. Firewall o red bloqueando SMTP en el entorno con cd.
3. Credenciales SMTP incorrectas o expiradas.
4. Gmail bloqueando el envío por seguridad.

## Cambios en UI
- [x] Modificar login.html para que los botones de mostrar/ocultar contraseña estén dentro de los campos de contraseña a la derecha.
- [x] Añadir CSS para posicionar los botones correctamente.

## Siguientes pasos
- Ejecutar en entorno problemático y reportar salida.
- Si SMTP falla, intentar con puerto 465 y server.starttls() -> server.login() sin starttls.
