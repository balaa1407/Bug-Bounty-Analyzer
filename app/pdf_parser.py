from io import BytesIO

import pdfplumber

from app.utils import (
    ASSET_KEYWORDS,
    ENVIRONMENT_KEYWORDS,
    NO_AUTH_KEYWORDS,
    SECTION_PATTERNS,
    USER_INTERACTION_KEYWORDS,
    VULNERABILITY_KEYWORDS,
    extract_section,
    find_first_match,
    has_any_keyword,
    normalize_text,
)

async def parse_pdf_report(pdf_file):
    pdf_text = ""
    pdf_bytes = await pdf_file.read()

    with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            pdf_text += (page.extract_text() or "") + "\n"

    text = normalize_text(pdf_text)

    impact = extract_section(text, SECTION_PATTERNS["impact"])
    steps = extract_section(text, SECTION_PATTERNS["steps"])

    return {
        "vulnerability_type": find_first_match(text, VULNERABILITY_KEYWORDS) or "unknown",
        "affected_asset": find_first_match(text, ASSET_KEYWORDS) or "unknown",
        "authentication_required": not has_any_keyword(text, NO_AUTH_KEYWORDS),
        "user_interaction_required": has_any_keyword(text, USER_INTERACTION_KEYWORDS),
        "environment": find_first_match(text, ENVIRONMENT_KEYWORDS) or "unknown",
        "impact_description": impact,
        "steps_to_reproduce": steps,
        "raw_pdf_text": text,
    }
