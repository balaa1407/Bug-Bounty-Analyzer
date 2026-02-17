from app.scoring import calculate_risk


def test_calculate_risk_high_for_unauth_prod_sensitive():
    extracted = {
        "vulnerability_type": "sql injection",
        "affected_asset": "payment",
        "authentication_required": False,
        "user_interaction_required": False,
        "environment": "production",
    }
    ocr = {
        "database_exposure": True,
        "error_messages": True,
        "sensitive_data": True,
        "admin_panels": False,
    }

    result = calculate_risk(extracted, ocr)

    assert result["score_breakdown"]["total_score"] >= 20
    assert result["severity"] in {"High", "Critical"}
