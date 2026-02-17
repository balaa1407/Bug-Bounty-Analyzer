from app.quality import assess_report_quality


def test_quality_score_rewards_complete_report():
    extracted = {
        "impact_description": "This issue exposes account and billing actions, leading to unauthorized transfers in production.",
        "steps_to_reproduce": "1) Login as user A 2) Change object id in request 3) Observe unauthorized access to user B profile and payout records",
    }

    quality = assess_report_quality(extracted, screenshot_count=2)

    assert quality["score"] >= 80
    assert quality["notes"] == []
