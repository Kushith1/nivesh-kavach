"""
Unit tests for app/redact.py
"""

from app.redact import redact_text


def test_redact_phone_numbers():
    text = "Call me at +91 9876543210 or 8765432109 for hot tips."
    redacted, counts = redact_text(text)
    assert "[PHONE]" in redacted
    assert "9876543210" not in redacted
    assert "8765432109" not in redacted
    assert counts.get("PHONE", 0) >= 1


def test_redact_aadhaar():
    text = "Aadhaar number is 2345 6789 0123 submitted for KYC."
    redacted, counts = redact_text(text)
    assert "[ID]" in redacted
    assert "2345 6789 0123" not in redacted
    assert counts.get("ID") == 1


def test_redact_pan():
    text = "My PAN card is ABCDE1234F registered with broker."
    redacted, counts = redact_text(text)
    assert "[PAN]" in redacted
    assert "ABCDE1234F" not in redacted
    assert counts.get("PAN") == 1


def test_redact_upi():
    text = "Send 5000 to trader123@oksbi or payment@paytm."
    redacted, counts = redact_text(text)
    assert "[UPI]" in redacted
    assert "trader123@oksbi" not in redacted
    assert "payment@paytm" not in redacted
    assert counts.get("UPI") >= 1


def test_redact_email():
    text = "Contact advisor at analyst.support@gmail.com for details."
    redacted, counts = redact_text(text)
    assert "[EMAIL]" in redacted
    assert "analyst.support@gmail.com" not in redacted
    assert counts.get("EMAIL") == 1


def test_redact_account_number():
    text = "Bank account number 123456789012345 credited."
    redacted, counts = redact_text(text)
    assert "[ACCOUNT]" in redacted
    assert "123456789012345" not in redacted
    assert counts.get("ACCOUNT") == 1


def test_redact_otp_patterns():
    samples = [
        "Your OTP is 654321 for login",
        "One time password: 987654",
        "ओटीपी 543210 किसी को न बताएं"
    ]
    for s in samples:
        redacted, counts = redact_text(s)
        assert "[OTP]" in redacted, f"Failed for {s}"
        assert counts.get("OTP", 0) >= 1


def test_redact_empty():
    redacted, counts = redact_text("")
    assert redacted == ""
    assert counts == {}
