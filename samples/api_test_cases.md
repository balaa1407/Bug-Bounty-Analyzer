# API Test Cases

## 1) Valid Submission
- Upload one structured PDF report and two screenshots.
- Expected: `200 OK`, severity, score breakdown, quality, and remediation returned.

## 2) Invalid PDF Type
- Upload `report.txt` as PDF field.
- Expected: `400`, message `Upload a valid PDF`.

## 3) Missing Screenshot
- Omit `screenshot2`.
- Expected: `422` from FastAPI body validation.

## 4) Oversized File
- Upload PDF above configured limit (`MAX_PDF_SIZE_MB`).
- Expected: `400`, size limit error.

## 5) Missing Mandatory Report Sections
- Upload PDF without clear impact and steps-to-reproduce fields.
- Expected: `400`, missing mandatory fields error.

## 6) Report Retrieval
- Call `/reports` and `/reports/{id}` after valid analysis.
- Expected: Stored report appears with extracted fields and analytics-ready payload.
