from io import BytesIO
import pytest
from fastapi import HTTPException, UploadFile
from PIL import Image
from app.validator import validate_files


class MockUploadFile(UploadFile):
    def __init__(self, filename: str, content_type: str, content: bytes):
        super().__init__(file=BytesIO(content), filename=filename)
        self._content_type = content_type

    @property
    def content_type(self) -> str:
        return self._content_type


def create_dummy_png() -> bytes:
    img = Image.new("RGB", (1, 1), color="red")
    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


@pytest.mark.asyncio
async def test_validate_files_valid_pdf_no_screenshots():
    pdf = MockUploadFile("report.pdf", "application/pdf", b"%PDF-1.4\n%EOF")
    await validate_files(pdf, None, None)


@pytest.mark.asyncio
async def test_validate_files_invalid_pdf_signature():
    pdf = MockUploadFile("report.pdf", "application/pdf", b"NOTAPDF-1.4")
    with pytest.raises(HTTPException) as exc:
        await validate_files(pdf, None, None)
    assert exc.value.status_code == 400
    assert "Invalid PDF signature" in exc.value.detail


@pytest.mark.asyncio
async def test_validate_files_invalid_mime():
    pdf = MockUploadFile("report.pdf", "text/plain", b"%PDF-1.4\n%EOF")
    with pytest.raises(HTTPException) as exc:
        await validate_files(pdf, None, None)
    assert exc.value.status_code == 400
    assert "Upload a valid PDF" in exc.value.detail


@pytest.mark.asyncio
async def test_validate_files_with_valid_screenshot():
    pdf = MockUploadFile("report.pdf", "application/pdf", b"%PDF-1.4\n%EOF")
    img_bytes = create_dummy_png()
    s1 = MockUploadFile("shot1.png", "image/png", img_bytes)
    await validate_files(pdf, s1, None)


@pytest.mark.asyncio
async def test_validate_files_with_invalid_screenshot_type():
    pdf = MockUploadFile("report.pdf", "application/pdf", b"%PDF-1.4\n%EOF")
    s1 = MockUploadFile("shot1.txt", "text/plain", b"fake image bytes")
    with pytest.raises(HTTPException) as exc:
        await validate_files(pdf, s1, None)
    assert exc.value.status_code == 400
    assert "Screenshot 1 must be image" in exc.value.detail
