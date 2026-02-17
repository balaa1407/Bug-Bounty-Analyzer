from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.config import settings
from app.ocr import extract_ocr_signals
from app.pdf_parser import parse_pdf_report
from app.quality import assess_report_quality
from app.remediation import suggest_remediation
from app.repository import analytics_summary, get_report, list_reports, save_report, storage_mode
from app.scoring import calculate_risk
from app.utils import to_feature_vector
from app.validator import validate_files

app = FastAPI(title=settings.app_name, version="0.1.0")


def _ensure_required_report_fields(extracted_fields: dict):
    missing = []
    if extracted_fields.get("vulnerability_type") in ("", "unknown"):
        missing.append("vulnerability_type")
    if extracted_fields.get("affected_asset") in ("", "unknown"):
        missing.append("affected_asset")
    if not extracted_fields.get("impact_description"):
        missing.append("impact_description")
    if not extracted_fields.get("steps_to_reproduce"):
        missing.append("steps_to_reproduce")
    if missing:
        raise HTTPException(status_code=400, detail=f"Mandatory report fields missing or unclear: {', '.join(missing)}")


@app.get("/health")
def health_check():
    return {"status": "ok", "storage_mode": storage_mode()}


@app.post("/analyze")
async def analyze(pdf: UploadFile = File(...),
                  screenshot1: UploadFile = File(...),
                  screenshot2: UploadFile = File(...)):
    try:
        await validate_files(pdf, screenshot1, screenshot2)

        extracted_fields = await parse_pdf_report(pdf)
        _ensure_required_report_fields(extracted_fields)

        ocr_signals = await extract_ocr_signals([screenshot1, screenshot2])
        feature_vector = to_feature_vector(extracted_fields, ocr_signals)

        score_payload = calculate_risk(extracted_fields, ocr_signals)
        quality = assess_report_quality(extracted_fields, screenshot_count=2)
        remediation = suggest_remediation(extracted_fields.get("vulnerability_type", "unknown"))

        report_id = str(uuid4())
        record = {
            "report_id": report_id,
            "created_at": datetime.now(timezone.utc),
            "file_names": {
                "pdf": pdf.filename,
                "screenshot1": screenshot1.filename,
                "screenshot2": screenshot2.filename,
            },
            "extracted_fields": extracted_fields,
            "ocr_signals": ocr_signals,
            "feature_vector": feature_vector,
            "score_breakdown": score_payload["score_breakdown"],
            "severity": score_payload["severity"],
            "severity_explanation": score_payload["severity_explanation"],
            "remediation": remediation,
            "quality": quality,
        }

        save_report(record)

        return {
            "report_id": report_id,
            **score_payload,
            "quality": quality,
            "remediation": remediation,
            "extracted_fields": extracted_fields,
            "ocr_signals": ocr_signals,
            "feature_vector": feature_vector,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc


@app.get("/reports")
def get_reports(limit: int = 50):
    items = list_reports(limit=limit)
    return {"items": items, "count": len(items)}


@app.get("/reports/{report_id}")
def get_report_by_id(report_id: str):
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/analytics/summary")
def get_analytics_summary():
    return analytics_summary()
