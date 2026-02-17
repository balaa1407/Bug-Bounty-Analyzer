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
	"impact": r"impact\s*:\s*(.+?)(?:steps to reproduce|reproduction|proof of concept|$)",
	"steps": r"(?:steps to reproduce|reproduction)\s*:\s*(.+?)(?:impact|mitigation|$)",
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
	return match.group(1).strip()[:2000]


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
	except UnidentifiedImageError:
		return ""

	return pytesseract.image_to_string(image) or ""
