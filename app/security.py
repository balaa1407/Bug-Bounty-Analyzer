import hashlib
import os
import re
import secrets
from pathlib import Path


def sanitize_filename(file_name: str) -> str:
    candidate = Path(file_name or "uploaded_file").name
    candidate = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
    return candidate[:120] or "uploaded_file"


def bytes_to_megabytes(value: int) -> float:
    return value / (1024 * 1024)


def ensure_upload_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    if not hashed or "$" not in hashed:
        return False
    try:
        salt, key_hex = hashed.split("$", 1)
        expected_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return secrets.compare_digest(expected_key.hex(), key_hex)
    except Exception:
        return False
