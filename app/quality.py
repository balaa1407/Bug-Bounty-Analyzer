def assess_report_quality(extracted_fields: dict, screenshot_count: int) -> dict:
    notes = []

    poc_clarity = 25 if extracted_fields.get("steps_to_reproduce") else 8
    if poc_clarity < 25:
        notes.append("Missing clear steps to reproduce.")

    reproducibility = 25 if len(extracted_fields.get("steps_to_reproduce", "")) > 100 else 10
    if reproducibility < 25:
        notes.append("Reproduction guidance is too short.")

    screenshot_quality = 25 if screenshot_count >= 2 else 10
    if screenshot_count < 2:
        notes.append("At least 2 screenshots are expected.")

    impact_clarity = 25 if len(extracted_fields.get("impact_description", "")) > 80 else 10
    if impact_clarity < 25:
        notes.append("Impact explanation needs more business context.")

    total = poc_clarity + reproducibility + screenshot_quality + impact_clarity

    return {
        "score": total,
        "poc_clarity": poc_clarity,
        "reproducibility": reproducibility,
        "screenshot_quality": screenshot_quality,
        "impact_clarity": impact_clarity,
        "notes": notes,
    }
