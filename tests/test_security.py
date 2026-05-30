from fastapi.testclient import TestClient
from app.main import app
from app.security import hash_password, verify_password, sanitize_filename


def test_filename_sanitization():
    # Test path traversal characters removal
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\win.ini") == "win.ini"
    
    # Test XSS tag removal/replacement (cross-platform check)
    assert sanitize_filename("<script>alert(1)</script>.pdf") in ("_script_alert_1___script_.pdf", "script_.pdf")
    
    # Test valid filenames
    assert sanitize_filename("valid_report_123.pdf") == "valid_report_123.pdf"


def test_password_hashing_and_verification():
    raw_pass = "cybersecurity_student_2026"
    hashed = hash_password(raw_pass)
    
    assert hashed != raw_pass
    assert "$" in hashed
    
    # Verify correct password
    assert verify_password(raw_pass, hashed) is True
    
    # Verify incorrect password
    assert verify_password("wrong_password", hashed) is False
    assert verify_password("", hashed) is False


def test_secure_http_headers():
    client = TestClient(app)
    response = client.get("/health")
    
    assert response.status_code == 200
    headers = response.headers
    
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert "Strict-Transport-Security" in headers
