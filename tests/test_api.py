"""
Integration tests for FastAPI endpoints in app/main.py using TestClient
"""

import io
from PIL import Image
from fastapi.testclient import TestClient
import app.main as main
from app.main import app

client = TestClient(app)


def test_api_text_scam():
    response = client.post(
        "/api/analyze",
        data={
            "text": "Sir pakka munafa guaranteed hai. Transfer 10,000 now for double returns. OTP batao to activate.",
            "language": "en"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "risk" in data
    assert data["risk"]["score"] >= 45
    assert len(data["signals"]) >= 2
    assert len(data["official_links"]) >= 1
    assert "disclaimer" in data


def test_api_url_only():
    response = client.post(
        "/api/analyze",
        data={
            "url": "http://192.168.1.1/invest-profit.xyz",
            "language": "en"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["signals"]) >= 1
    assert any(s["category"] == "suspicious_url" for s in data["signals"])


def test_api_image_upload():
    # Generate in-memory small valid test image
    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="JPEG")
    img_byte_arr.seek(0)

    response = client.post(
        "/api/analyze",
        data={"language": "en"},
        files={"image": ("screenshot.jpg", img_byte_arr.getvalue(), "image/jpeg")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "risk" in data


def test_api_image_only_ai_scam_signals_score_high(monkeypatch):
    def fake_analyze_with_gemini(**kwargs):
        return True, {
            "extra_signals": [
                {
                    "category": "impersonation",
                    "evidence_quote": "SEBI VERIFIED INVESTOR GROUP",
                    "why_dangerous": "Uses regulator branding to create false trust."
                },
                {
                    "category": "advance_fee",
                    "evidence_quote": "pay Rs 4,999 processing fee",
                    "why_dangerous": "Demands an upfront fee before releasing fake profit."
                },
                {
                    "category": "credential_request",
                    "evidence_quote": "Share the OTP sent to your phone",
                    "why_dangerous": "Legitimate institutions never ask for OTPs."
                },
                {
                    "category": "urgency",
                    "evidence_quote": "within 2 hours",
                    "why_dangerous": "Creates pressure to act without verifying."
                },
                {
                    "category": "suspicious_url",
                    "evidence_quote": "http://sebi-profit-verify.xyz",
                    "why_dangerous": "Uses an unofficial high-risk domain."
                },
            ],
            "claims_to_verify": [],
            "plain_explanation": "The screenshot shows multiple scam warning signs.",
            "content_unclear": False,
        }

    monkeypatch.setattr(main, "analyze_with_gemini", fake_analyze_with_gemini)

    img = Image.new("RGB", (100, 100), color=(20, 80, 60))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="JPEG")
    img_byte_arr.seek(0)

    response = client.post(
        "/api/analyze",
        data={"language": "en"},
        files={"image": ("screenshot.jpg", img_byte_arr.getvalue(), "image/jpeg")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["score"] >= 70
    assert data["risk"]["level"] == "Very High"
    assert len(data["signals"]) >= 5


def test_api_image_only_unclear_fallback_is_not_low(monkeypatch):
    def fake_analyze_with_gemini(**kwargs):
        return False, {
            "extra_signals": [],
            "claims_to_verify": [],
            "plain_explanation": "Detailed explanation unavailable right now.",
            "content_unclear": False,
        }

    monkeypatch.setattr(main, "analyze_with_gemini", fake_analyze_with_gemini)

    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="JPEG")
    img_byte_arr.seek(0)

    response = client.post(
        "/api/analyze",
        data={"language": "en"},
        files={"image": ("screenshot.jpg", img_byte_arr.getvalue(), "image/jpeg")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["score"] >= 45
    assert data["risk"]["level"] == "High"
    assert any(s["id"] == "IMAGE_REVIEW_NEEDED" for s in data["signals"])


def test_api_empty_input_fails():
    response = client.post("/api/analyze", data={})
    assert response.status_code == 400


def test_api_caching():
    payload = {"text": "Guarantee 100% fixed profit daily with phone +91 9876543210"}
    res1 = client.post("/api/analyze", data=payload)
    res2 = client.post("/api/analyze", data=payload)
    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.json() == res2.json()


def test_api_metrics():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "high_risk_flagged" in data


def test_api_ai_unavailable_returns_fallback_explanation(monkeypatch):
    def fake_analyze_with_gemini(**kwargs):
        lang = kwargs.get("language", "en")
        msg = "Detailed explanation unavailable right now." if lang == "en" else "विस्तृत विवरण अभी उपलब्ध नहीं है।"
        return False, {
            "extra_signals": [],
            "claims_to_verify": [],
            "plain_explanation": msg,
            "content_unclear": False,
        }

    monkeypatch.setattr(main, "analyze_with_gemini", fake_analyze_with_gemini)

    response = client.post(
        "/api/analyze",
        data={
            "text": "Earn 10% daily guaranteed profit in our exclusive crypto doubling pool. Send 500 USDT now.",
            "language": "en"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ai_available"] is False
    assert data["plain_explanation"] == "Detailed explanation unavailable right now."
    # Rules still fired
    assert data["risk"]["score"] >= 45
    assert len(data["signals"]) >= 1

