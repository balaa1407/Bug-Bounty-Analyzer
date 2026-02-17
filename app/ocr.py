from app.utils import has_any_keyword, normalize_text, ocr_image_bytes

DATABASE_KEYWORDS = ["database", "dump", "select *", "table", "records"]
ERROR_KEYWORDS = ["stack trace", "sql syntax", "exception", "error", "traceback"]
SENSITIVE_KEYWORDS = ["password", "token", "api key", "secret", "ssn", "credit card"]
ADMIN_KEYWORDS = ["admin", "dashboard", "root", "superuser", "control panel"]


async def extract_ocr_signals(screenshots) -> dict:
    text_parts = []
    for shot in screenshots:
        data = await shot.read()
        text_parts.append(ocr_image_bytes(data))

    raw_text = normalize_text("\n".join(text_parts))

    return {
        "database_exposure": has_any_keyword(raw_text, DATABASE_KEYWORDS),
        "error_messages": has_any_keyword(raw_text, ERROR_KEYWORDS),
        "sensitive_data": has_any_keyword(raw_text, SENSITIVE_KEYWORDS),
        "admin_panels": has_any_keyword(raw_text, ADMIN_KEYWORDS),
        "raw_text": raw_text,
    }
