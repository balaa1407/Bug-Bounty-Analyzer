from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.ocr import extract_ocr_signals
from app.pdf_parser import parse_pdf_report
from app.quality import assess_report_quality
from app.remediation import suggest_remediation
from app.repository import analytics_summary, get_report, list_reports, save_report, storage_mode
from app.scoring import calculate_risk
from app.security import sanitize_filename
from app.utils import to_feature_vector, calculate_jaccard_similarity
from app.validator import validate_files

app = FastAPI(title=settings.app_name, version="0.1.0")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)


rate_limit_records = {}


def check_rate_limit(client_ip: str, limit: int = 10, window_seconds: int = 60) -> bool:
    import time
    now = time.time()
    if client_ip not in rate_limit_records:
        rate_limit_records[client_ip] = []

    rate_limit_records[client_ip] = [t for t in rate_limit_records[client_ip] if now - t < window_seconds]

    if len(rate_limit_records[client_ip]) >= limit:
        return False

    rate_limit_records[client_ip].append(now)
    return True


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


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "analyze_endpoint": "/analyze",
    }


@app.post("/analyze")
async def analyze(request: Request,
                  pdf: UploadFile = File(...),
                  screenshot1: UploadFile | None = None,
                  screenshot2: UploadFile | None = None):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip, limit=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")

    try:
        await validate_files(pdf, screenshot1, screenshot2)

        extracted_fields = await parse_pdf_report(pdf)
        _ensure_required_report_fields(extracted_fields)

        screenshots = [s for s in [screenshot1, screenshot2] if s is not None]
        ocr_signals = await extract_ocr_signals(screenshots)
        feature_vector = to_feature_vector(extracted_fields, ocr_signals)

        score_payload = calculate_risk(extracted_fields, ocr_signals)
        quality = assess_report_quality(extracted_fields, screenshot_count=len(screenshots))
        remediation = suggest_remediation(extracted_fields.get("vulnerability_type", "unknown"))

        report_id = str(uuid4())

        # Scan for duplicate reports (similarity > 0.65 on raw text)
        duplicates = []
        all_reports = list_reports(limit=1000)
        current_text = extracted_fields.get("raw_pdf_text", "")
        for old_report in all_reports:
            old_fields = old_report.get("extracted_fields", {})
            old_text = old_fields.get("raw_pdf_text", "")
            if old_text and old_report.get("report_id") != report_id:
                sim = calculate_jaccard_similarity(current_text, old_text)
                if sim > 0.65:
                    duplicates.append({
                        "report_id": old_report.get("report_id"),
                        "similarity": round(sim, 2)
                    })
        
        file_names = {"pdf": sanitize_filename(pdf.filename)}
        if screenshot1:
            file_names["screenshot1"] = sanitize_filename(screenshot1.filename)
        if screenshot2:
            file_names["screenshot2"] = sanitize_filename(screenshot2.filename)

        record = {
            "report_id": report_id,
            "created_at": datetime.now(timezone.utc),
            "file_names": file_names,
            "extracted_fields": extracted_fields,
            "ocr_signals": ocr_signals,
            "feature_vector": feature_vector,
            "score_breakdown": score_payload["score_breakdown"],
            "severity": score_payload["severity"],
            "severity_explanation": score_payload["severity_explanation"],
            "remediation": remediation,
            "quality": quality,
            "duplicates": duplicates,
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
            "duplicates": duplicates,
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
