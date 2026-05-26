from io import BytesIO

from fastapi import HTTPException
from PIL import Image

from app.config import settings


def _validate_size(raw_bytes: bytes, max_mb: int, field_name: str):
    limit = max_mb * 1024 * 1024
    if len(raw_bytes) > limit:
        raise HTTPException(status_code=400, detail=f"{field_name} exceeds {max_mb}MB limit")


def _validate_pdf_signature(raw_bytes: bytes):
    if not raw_bytes.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="Invalid PDF signature")


def _validate_image_bytes(raw_bytes: bytes, label: str):
    try:
        image = Image.open(BytesIO(raw_bytes))
        image.verify()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"{label} is not a valid image") from exc


async def validate_files(pdf, s1=None, s2=None):
    if pdf.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Upload a valid PDF")

    pdf_bytes = await pdf.read()
    _validate_size(pdf_bytes, settings.max_pdf_size_mb, "PDF")
    _validate_pdf_signature(pdf_bytes)
    await pdf.seek(0)

    if s1 is not None:
        if not s1.content_type or not s1.content_type.startswith("image"):
            raise HTTPException(status_code=400, detail="Screenshot 1 must be image")
        s1_bytes = await s1.read()
        _validate_size(s1_bytes, settings.max_image_size_mb, "Screenshot 1")
        _validate_image_bytes(s1_bytes, "Screenshot 1")
        await s1.seek(0)

    if s2 is not None:
        if not s2.content_type or not s2.content_type.startswith("image"):
            raise HTTPException(status_code=400, detail="Screenshot 2 must be image")
        s2_bytes = await s2.read()
        _validate_size(s2_bytes, settings.max_image_size_mb, "Screenshot 2")
        _validate_image_bytes(s2_bytes, "Screenshot 2")
        await s2.seek(0)

