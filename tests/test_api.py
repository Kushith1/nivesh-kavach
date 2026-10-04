"""
Integration tests for FastAPI endpoints in app/main.py using TestClient
"""

import io
from PIL import Image
from fastapi.testclient import TestClient
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
