TECHNICAL_IMPACT = {
    "sql injection": 9,
    "xss": 6,
    "idor": 8,
    "rce": 10,
    "ssrf": 8,
    "csrf": 5,
    "unknown": 4,
}

BUSINESS_IMPACT = {
    "payment": 9,
    "admin": 8,
    "user": 6,
    "api": 7,
    "unknown": 4,
}


def _severity_from_score(total: int) -> str:
    if total >= 22:
        return "Critical"
    if total >= 16:
        return "High"
    if total >= 10:
        return "Medium"
    return "Low"


def calculate_risk(extracted_fields: dict, ocr_signals: dict) -> dict:
    vuln = extracted_fields.get("vulnerability_type", "unknown")
    asset = extracted_fields.get("affected_asset", "unknown")

    technical = TECHNICAL_IMPACT.get(vuln, 4)
    business = BUSINESS_IMPACT.get(asset, 4)

    exploitability = 4
    if not extracted_fields.get("authentication_required", True):
        exploitability += 3
    if not extracted_fields.get("user_interaction_required", False):
        exploitability += 2
    if extracted_fields.get("environment") == "production":
        exploitability += 1
    if ocr_signals.get("sensitive_data"):
        exploitability += 1

    total_score = technical + business + exploitability
    severity = _severity_from_score(total_score)

    explanation = (
        f"Severity {severity} derived from technical impact {technical}, "
        f"exploitability {exploitability}, and business impact {business}."
    )

    return {
        "score_breakdown": {
            "technical_impact": technical,
            "exploitability": exploitability,
            "business_impact": business,
            "total_score": total_score,
        },
        "severity": severity,
        "severity_explanation": explanation,
    }
