import re
from io import BytesIO

import pytesseract
from PIL import Image, UnidentifiedImageError

VULNERABILITY_KEYWORDS = {
	"sql injection": ["sql injection", "sqli", "union select", "time based"],
	"xss": ["xss", "cross site scripting", "<script"],
	"idor": ["idor", "insecure direct object reference", "object reference"],
	"rce": ["rce", "remote code execution", "command injection"],
	"ssrf": ["ssrf", "server side request forgery"],
	"csrf": ["csrf", "cross site request forgery"],
}

ASSET_KEYWORDS = {
	"payment": ["payment", "checkout", "transaction", "billing"],
	"admin": ["admin", "administrator", "backoffice", "dashboard"],
	"user": ["user profile", "account", "settings", "customer"],
	"api": ["api", "endpoint", "graphql", "rest"],
}

NO_AUTH_KEYWORDS = [
	"no authentication",
	"without authentication",
	"unauthenticated",
	"auth bypass",
	"without login",
]

ENVIRONMENT_KEYWORDS = {
	"production": ["production", "prod", "live environment"],
	"staging": ["staging", "stage", "uat"],
	"development": ["development", "dev environment", "local env"],
}

USER_INTERACTION_KEYWORDS = [
	"requires user interaction",
	"victim clicks",
	"user must click",
	"social engineering",
]

SECTION_PATTERNS = {
	"impact": r"(?:#*\s*|\b)impact\b\s*:?\s*(.+?)(?:steps to reproduce|reproduction|proof of concept|$)",
	"steps": r"(?:#*\s*|\b)(?:steps to reproduce|reproduction|proof of concept|poc)\b\s*:?\s*(.+?)(?:impact|mitigation|$)",
}


def normalize_text(text: str) -> str:
	if not text:
		return ""
	text = text.lower()
	text = re.sub(r"\s+", " ", text)
	return text.strip()


def find_first_match(text: str, keyword_map: dict[str, list[str]]) -> str:
	normalized = normalize_text(text)
	for canonical, candidates in keyword_map.items():
		if any(candidate in normalized for candidate in candidates):
			return canonical
	return ""


def has_any_keyword(text: str, keywords: list[str]) -> bool:
	normalized = normalize_text(text)
	return any(keyword in normalized for keyword in keywords)


def extract_section(text: str, pattern: str) -> str:
	normalized = normalize_text(text)
	match = re.search(pattern, normalized, flags=re.IGNORECASE | re.DOTALL)
	if not match:
		return ""
	extracted = match.group(1).strip()
	# Strip leading/trailing markdown characters like #, *, -, _
	extracted = re.sub(r"^[#\*_\-\s]+", "", extracted)
	extracted = re.sub(r"[#\*_\-\s]+$", "", extracted)
	return extracted[:2000]


def to_feature_vector(extracted: dict, ocr_signals: dict) -> dict[str, float]:
	return {
		"is_unauthenticated": float(not extracted.get("authentication_required", True)),
		"user_interaction_required": float(extracted.get("user_interaction_required", False)),
		"is_production": float(extracted.get("environment") == "production"),
		"has_impact_text": float(bool(extracted.get("impact_description"))),
		"has_steps": float(bool(extracted.get("steps_to_reproduce"))),
		"database_exposure": float(ocr_signals.get("database_exposure", False)),
		"error_messages": float(ocr_signals.get("error_messages", False)),
		"sensitive_data": float(ocr_signals.get("sensitive_data", False)),
		"admin_panels": float(ocr_signals.get("admin_panels", False)),
	}


def ocr_image_bytes(image_bytes: bytes) -> str:
	if not image_bytes:
		return ""

	try:
		image = Image.open(BytesIO(image_bytes))
		return pytesseract.image_to_string(image) or ""
	except Exception as exc:
		import sys
		print(f"WARNING: OCR extraction failed (is Tesseract OCR installed?): {exc}", file=sys.stderr)
		return ""


def parse_cvss_vector(text: str) -> dict | None:
	if not text:
		return None
	match = re.search(r"CVSS:3\.1/[A-Z0-9:\./]+", text, re.IGNORECASE)
	if not match:
		return None

	vector = match.group(0).upper()
	parts = vector.split("/")

	metrics = {}
	for part in parts:
		if ":" in part:
			k, v = part.split(":", 1)
			metrics[k] = v

	required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
	if not all(r in metrics for r in required):
		return None

	return calculate_cvss_score(metrics, vector)


def calculate_cvss_score(metrics: dict, vector: str) -> dict:
	av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac_map = {"L": 0.77, "H": 0.44}
	ui_map = {"N": 0.85, "R": 0.62}

	scope = metrics["S"]
	if scope == "U":
		pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
	else:
		pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}

	c_map = {"H": 0.56, "L": 0.22, "N": 0.0}
	i_map = {"H": 0.56, "L": 0.22, "N": 0.0}
	a_map = {"H": 0.56, "L": 0.22, "N": 0.0}

	av = av_map.get(metrics["AV"], 0.85)
	ac = ac_map.get(metrics["AC"], 0.77)
	pr = pr_map.get(metrics["PR"], 0.85)
	ui = ui_map.get(metrics["UI"], 0.85)

	c = c_map.get(metrics["C"], 0.0)
	i = i_map.get(metrics["I"], 0.0)
	a = a_map.get(metrics["A"], 0.0)

	iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

	if scope == "U":
		impact = 6.42 * iss
	else:
		impact = 7.52 * (iss - 0.029) - 3.25 * ((max(0.0, iss - 0.02)) ** 15)

	exploitability = 8.22 * av * ac * pr * ui

	# CVSS v3.1 standard roundup function
	def roundup(val):
		int_val = int(val * 100000)
		if int_val % 10000 == 0:
			return int_val / 100000.0
		else:
			return (int(int_val / 10000) + 1) / 10.0

	if iss <= 0:
		base_score = 0.0
	else:
		if scope == "U":
			base_score = roundup(min(impact + exploitability, 10.0))
		else:
			base_score = roundup(min(1.08 * (impact + exploitability), 10.0))

	return {
		"vector": vector,
		"base_score": base_score,
		"impact": round(impact, 1),
		"exploitability": round(exploitability, 1),
	}
