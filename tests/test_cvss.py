from app.utils import parse_cvss_vector
from app.scoring import calculate_risk


def test_parse_cvss_vector_critical():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is CVSS 9.8 (Critical)
    vector_text = "The issue has CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H as base rating."
    res = parse_cvss_vector(vector_text)
    assert res is not None
    assert res["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert res["base_score"] == 9.8
    assert res["impact"] == 5.9
    assert res["exploitability"] == 3.9


def test_parse_cvss_vector_medium():
    # AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N is CVSS 4.8 (Medium)
    vector_text = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    res = parse_cvss_vector(vector_text)
    assert res is not None
    assert res["base_score"] == 4.8


def test_parse_cvss_vector_invalid():
    # Missing S metric
    assert parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H") is None
    # Completely invalid format
    assert parse_cvss_vector("not a vector") is None


def test_calculate_risk_cvss_override():
    extracted = {
        "vulnerability_type": "xss",
        "affected_asset": "user",
        "raw_pdf_text": "This issue is rated as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)"
    }
    ocr = {}
    
    result = calculate_risk(extracted, ocr)
    
    assert result["severity"] == "Critical"
    assert "overridden by parsed CVSS v3.1 vector" in result["severity_explanation"]
    assert result["score_breakdown"]["total_score"] >= 22
