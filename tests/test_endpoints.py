"""
Integration tests for all API endpoints.
"""
import pytest


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


# ---------------------------------------------------------------------------
# /api/scan
# ---------------------------------------------------------------------------

async def test_complete_scan_phishing(client, phishing_payload):
    response = await client.post("/api/scan", json=phishing_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert data["scan_id"] is not None
    # content_analysis may be None if model not loaded; only assert if present
    if data.get("content_analysis") is not None:
        assert data["content_analysis"]["is_phishing"] is True


async def test_complete_scan_safe(client, safe_payload):
    response = await client.post("/api/scan", json=safe_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("LOW", "MEDIUM")
    assert data["scan_id"] is not None


# ---------------------------------------------------------------------------
# /api/scan/urls
# ---------------------------------------------------------------------------

async def test_scan_urls_only(client):
    response = await client.post(
        "/api/scan/urls",
        json={"email_text": "Check: http://paypa1.com/login"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 0


# ---------------------------------------------------------------------------
# /api/scan/content
# ---------------------------------------------------------------------------

async def test_scan_content_only(client):
    response = await client.post(
        "/api/scan/content",
        json={"email_text": "Click here to verify your PayPal account immediately"},
    )
    # May be 503 if model isn't trained; accept both outcomes
    if response.status_code == 503:
        pytest.skip("ML model not available – skipping content-only test")
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is True or data["confidence"] > 0.5


# ---------------------------------------------------------------------------
# /api/feedback
# ---------------------------------------------------------------------------

async def test_feedback_submit(client, phishing_payload):
    scan_resp = await client.post("/api/scan", json=phishing_payload)
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    fb_resp = await client.post(
        "/api/feedback",
        json={"scan_id": scan_id, "verdict": "TP"},
    )
    assert fb_resp.status_code == 200
    assert fb_resp.json()["success"] is True


async def test_feedback_invalid_verdict(client):
    response = await client.post(
        "/api/feedback",
        json={"scan_id": "any", "verdict": "INVALID"},
    )
    assert response.status_code in (400, 422) or response.json().get("success") is False


async def test_feedback_nonexistent_scan(client):
    response = await client.post(
        "/api/feedback",
        json={"scan_id": "00000000-0000-0000-0000-000000000000", "verdict": "TP"},
    )
    assert response.status_code == 200
    assert response.json()["success"] is False


async def test_feedback_stats(client):
    response = await client.get("/api/feedback/stats")
    assert response.status_code == 200
    data = response.json()
    for field in ("total_scans", "total_feedback", "verdict_counts", "queue_size", "reviewed_count"):
        assert field in data, f"Missing field: {field}"


async def test_feedback_queue(client):
    response = await client.get("/api/feedback/queue")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ---------------------------------------------------------------------------
# /api/status/*
# ---------------------------------------------------------------------------

async def test_status_headers(client):
    response = await client.get("/api/status/headers")
    assert response.status_code == 200
    data = response.json()
    assert len(data.get("features", [])) > 0


async def test_status_canonicalizer(client):
    response = await client.get("/api/status/canonicalizer")
    assert response.status_code == 200
    data = response.json()
    assert data.get("redirect_following") is True
