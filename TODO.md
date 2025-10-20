# TODO: Implementar Sistema de Recuperación de Contraseña

## Información Recopilada
- El sistema actual tiene páginas `forgot_password.html` y `reset_password.html`.
- Hay una tabla `password_reset_tokens` definida en `add_password_reset_tokens.sql`.
- La función `send_email` en `utils.py` está configurada para enviar emails reales via SMTP.
- El enlace en `login.html` actualmente apunta a `/forgot-password`.
- Se requiere expiración de 30 minutos para los tokens.
- Validaciones de contraseña existentes se mantendrán.

## Plan
1. Cambiar el enlace en `views/login.html` de `/forgot-password` a `/reset-password`.
2. Agregar funciones en `controllers/auth.py`:
   - `generate_reset_token(user_id)`: Genera y guarda token de reset.
   - `verify_reset_token(token)`: Verifica si token es válido y no expirado.
   - `reset_user_password(token, new_password)`: Actualiza contraseña usando token.
3. Agregar ruta `/reset-password` en `controllers/main.py` que maneje:
   - GET sin token: Mostrar página de solicitud de email (`forgot_password.html`).
   - POST sin token: Enviar email con enlace de reset.
   - GET con token: Mostrar página de reset (`reset_password.html`).
   - POST con token: Cambiar contraseña.
4. Agregar función `build_reset_email(token)` en `controllers/utils.py` para construir el HTML del email.
5. Asegurar que la tabla `password_reset_tokens` esté creada ejecutando el SQL si es necesario.

## Dependencias
- Requiere que la tabla `password_reset_tokens` exista en la DB.
- Usa `send_email` de `utils.py` para enviar el email con el enlace.

## Seguimiento de Progreso
- [x] Cambiar enlace en `views/login.html`.
- [x] Agregar funciones en `controllers/auth.py`.
- [x] Agregar ruta `/reset-password` en `controllers/main.py`.
- [x] Agregar `build_reset_email` en `controllers/utils.py`.
- [x] Ejecutar SQL para crear tabla `password_reset_tokens` si no existe.
- [x] Probar el flujo completo.
