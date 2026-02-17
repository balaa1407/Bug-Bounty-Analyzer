import os
import re
from pathlib import Path


def sanitize_filename(file_name: str) -> str:
    candidate = Path(file_name or "uploaded_file").name
    candidate = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
    return candidate[:120] or "uploaded_file"


def bytes_to_megabytes(value: int) -> float:
    return value / (1024 * 1024)


def ensure_upload_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
