from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["Low", "Medium", "High", "Critical"]


class ExtractedFields(BaseModel):
    vulnerability_type: str = "unknown"
    affected_asset: str = "unknown"
    authentication_required: bool = True
    user_interaction_required: bool = False
    environment: str = "unknown"
    impact_description: str = ""
    steps_to_reproduce: str = ""


class OcrSignals(BaseModel):
    database_exposure: bool = False
    error_messages: bool = False
    sensitive_data: bool = False
    admin_panels: bool = False
    raw_text: str = ""


class ScoreBreakdown(BaseModel):
    technical_impact: int
    exploitability: int
    business_impact: int
    total_score: int


class QualityAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    poc_clarity: int = Field(ge=0, le=25)
    reproducibility: int = Field(ge=0, le=25)
    screenshot_quality: int = Field(ge=0, le=25)
    impact_clarity: int = Field(ge=0, le=25)
    notes: list[str] = Field(default_factory=list)


class ReportRecord(BaseModel):
    report_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    file_names: dict[str, str]
    extracted_fields: ExtractedFields
    ocr_signals: OcrSignals
    feature_vector: dict[str, float]
    score_breakdown: ScoreBreakdown
    severity: Severity
    severity_explanation: str
    remediation: list[str]
    quality: QualityAssessment


class AnalyzeResponse(BaseModel):
    report_id: str
    severity: Severity
    severity_explanation: str
    score_breakdown: ScoreBreakdown
    quality: QualityAssessment
    remediation: list[str]
    extracted_fields: ExtractedFields
    ocr_signals: OcrSignals
    feature_vector: dict[str, float]
