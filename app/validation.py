# app/validation.py
import re
import csv
from typing import Tuple, List

def validate_password(password: str) -> Tuple[bool, str]:
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe incluir al menos una letra minúscula."
    if not re.search(r"\d", password):
        return False, "La contraseña debe incluir al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "La contraseña debe incluir al menos un carácter especial."
    return True, ""

def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_required(fields: dict) -> Tuple[bool, str]:
    for k, v in fields.items():
        if v is None or str(v).strip() == "":
            return False, f"El campo '{k}' es obligatorio."
    return True, ""

def validate_csv_file(path: str) -> Tuple[bool, List[str]]:
    errors = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader, None)
            if headers is None:
                errors.append("Archivo CSV vacío.")
                return False, errors
            # Ejemplo: exigir columnas específicas dependiendo del CSV
            if "email" not in [h.lower() for h in headers]:
                errors.append("El CSV debe tener una columna 'email'.")
            # validar filas
            for i, row in enumerate(reader, start=2):
                if len(row) < len(headers):
                    errors.append(f"Fila {i}: columnas faltantes.")
    except Exception as e:
        errors.append(str(e))
    return (len(errors) == 0), errors
