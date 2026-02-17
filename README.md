# Bug Bounty Vulnerability Report Analyzer

MVP project that simulates internal bug bounty triage workflows used by platforms like HackerOne and Bugcrowd.

## Features

- Uploads: one structured vulnerability PDF + two screenshots.
- Input validation: file type, signature, image verification, and size limits.
- Parsing: extracts vulnerability type, asset, auth requirement, user interaction, environment, impact, and reproduction steps.
- OCR pipeline: detects database exposure, error messages, sensitive data, and admin panels from screenshots.
- Hybrid scoring: rule-based CVSS-inspired technical impact + exploitability + business impact.
- Severity mapping: Low / Medium / High / Critical with explanation.
- Quality scoring: PoC clarity, reproducibility, screenshot completeness, and impact clarity.
- Remediation suggestions based on vulnerability type.
- Persistence and analytics: MongoDB-backed storage with fallback in-memory mode.
- Dashboard: Streamlit trends, critical reports, and common attack types.
- Single-page UI: reporter upload form with admin-only analysis visibility.

## Project Structure

```text
bug-bounty-analyzer/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── validator.py
│   ├── pdf_parser.py
│   ├── ocr.py
│   ├── scoring.py
│   ├── quality.py
│   ├── remediation.py
│   ├── repository.py
│   ├── analytics.py
│   ├── database.py
│   ├── security.py
│   ├── models.py
│   └── utils.py
├── dashboard/
│   └── streamlit_app.py
├── samples/
│   ├── sample_report_template.txt
│   ├── sample_payload.json
│   ├── mongodb_schema.json
│   └── api_test_cases.md
├── tests/
│   ├── test_scoring.py
│   └── test_quality.py
├── uploads/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── requirements.txt
└── README.md
```

## Local Setup

1. Install system OCR:

```bash
sudo apt-get update && sudo apt-get install -y tesseract-ocr
```

2. Create virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Optional environment file:

```bash
cp .env.example .env
```

4. Run API:

```bash
uvicorn app.main:app --reload
```

5. Run dashboard:

```bash
streamlit run dashboard/streamlit_app.py
```

## Docker Setup

```bash
docker compose up --build
```

- API: http://localhost:8000
- API docs: http://localhost:8000/docs
- Dashboard: http://localhost:8501

## Simple Uploader (No Admin)

If you want a minimal tool to upload a PDF and up to two screenshots and get the score without any admin/auth:

1. Ensure the API is running (via Docker above or `uvicorn`). Default: `http://localhost:8000`.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the simple uploader:

```bash
streamlit run dashboard/simple_uploader.py
```

4. In the web UI, upload your PDF (required) and optionally up to two screenshots, then click Analyze. The severity and score breakdown will be displayed.

Environment:
- Set `API_BASE_URL` if your API is not on `http://localhost:8000`.

### Single-Page Workflow

- Reporter side: upload 1 PDF + 2 screenshots from the dashboard submission form.
- Admin side: login in the same page using `ADMIN_PANEL_PASSWORD` to view detailed results and analytics.
- By design, detailed analysis output is visible only after admin authentication.

### Makefile Shortcuts

```bash
make up       # start all services in background with build
make ps       # list running services
make logs     # tail service logs
make down     # stop services
make clean    # stop and remove volumes
```

## API Endpoints

- `POST /analyze`
	- multipart fields: `pdf`, `screenshot1`, `screenshot2`
	- returns extracted fields, OCR signals, feature vector, risk score, quality, remediation
- `GET /reports?limit=50`
- `GET /reports/{report_id}`
- `GET /analytics/summary`
- `GET /health`

### Example Analyze Request

```bash
curl -X POST "http://localhost:8000/analyze" \
	-F "pdf=@samples/report.pdf" \
	-F "screenshot1=@samples/shot1.png" \
	-F "screenshot2=@samples/shot2.png"
```

## Scoring Model (Rule-Based MVP)

- `Total Score = Technical Impact + Exploitability + Business Impact`
- Technical impact driven by vulnerability type (SQLi, RCE, XSS, etc.)
- Exploitability factors include:
	- authentication bypass / unauthenticated access
	- user interaction requirement
	- production exposure
	- OCR-detected sensitive data
- Business impact driven by affected asset domain (payment/admin/user/api)

Severity mapping:

- `0-9`: Low
- `10-15`: Medium
- `16-21`: High
- `22+`: Critical

## Development Phases

1. Core MVP (upload, parser, scoring, API)
2. OCR integration (screenshot intelligence)
3. Dashboard + analytics
4. Security hardening and stricter sanitization
5. Future AI/NLP extensions

## Security Controls Included

- MIME/type checks
- PDF magic header validation
- Image integrity verification
- Size limits on upload fields
- Sanitized file handling design

## Future Planned Enhancements

- NLP-based classification
- Duplicate report detection
- Explainable AI layer for score traceability
- Advanced screenshot validation
- ML-enhanced context-aware risk scoring

## Tests

```bash
pytest -q
```

Unit tests include scoring and quality modules for deterministic MVP behavior.