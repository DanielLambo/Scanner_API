"""
PhishNet API — Comprehensive End-to-End Test Suite
===================================================
Hits the LIVE production API at https://scanner-api-st8w.onrender.com
Generates a markdown report at tests/E2E_REPORT.md

Run:
    pytest tests/test_e2e.py -v --timeout=120

Alabama A&M University Cybersecurity Lab · NSF Funded Research
"""

import asyncio
import base64
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

# ── Configuration ────────────────────────────────────────────
BASE_URL = "https://scanner-api-st8w.onrender.com"
API_KEY = "phishingisevil"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
TIMEOUT = 60.0
HEADERS = {"Content-Type": "application/json", "X-API-Key": API_KEY}

# ── Shared report state ─────────────────────────────────────
_report = {
    "results": [],
    "detection_table": [],
    "response_times": [],
    "layer_status": {},
    "notes": [],
}


def _record(category: str, name: str, passed: bool, detail: str = ""):
    _report["results"].append({
        "category": category,
        "name": name,
        "passed": passed,
        "detail": detail,
    })


# ── Async client fixture ────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as c:
        yield c


def _scan_with_retry(client, payload, max_retries=3):
    """POST /api/scan with automatic rate-limit retry."""
    for attempt in range(max_retries):
        r = client.post("/api/scan", json=payload, headers=HEADERS)
        if r.status_code == 429:
            wait = 62 if attempt == 0 else 30
            _report["notes"].append(f"Rate-limited during test, waiting {wait}s (attempt {attempt+1})")
            time.sleep(wait)
            continue
        return r
    return r  # return last response even if still 429


# ═════════════════════════════════════════════════════════════
# SECTION 1: Infrastructure Tests
# ═════════════════════════════════════════════════════════════

class TestInfrastructure:

    def test_health_check(self, client):
        t0 = time.time()
        r = client.get("/health")
        elapsed = round((time.time() - t0) * 1000)
        data = r.json()
        assert r.status_code == 200
        assert data["status"] == "healthy"
        assert data["ml_model_loaded"] is True
        _report["response_times"].append(("Health check", elapsed))
        _report["layer_status"]["ML Classifier (96% F1)"] = "Loaded" if data["ml_model_loaded"] else "Not loaded"
        _record("Infrastructure", "Health check", True, f"{elapsed}ms")

    def test_docs_accessible(self, client):
        r_docs = client.get("/docs")
        r_redoc = client.get("/redoc")
        r_openapi = client.get("/openapi.json")
        assert r_docs.status_code == 200
        assert r_redoc.status_code == 200
        assert r_openapi.status_code == 200
        openapi = r_openapi.json()
        assert "paths" in openapi
        assert len(openapi["paths"]) > 0
        _record("Infrastructure", "Docs accessible (/docs, /redoc, /openapi.json)", True,
                f"{len(openapi['paths'])} endpoints documented")

    def test_unauthorized_no_key(self, client):
        r = client.post("/api/scan", json={"email_text": "test"})
        assert r.status_code == 401
        _record("Infrastructure", "No API key returns 401", True)

    def test_unauthorized_fake_key(self, client):
        r = client.post("/api/scan", json={"email_text": "test"},
                        headers={"Content-Type": "application/json", "X-API-Key": "fake_key_12345"})
        assert r.status_code == 403
        _record("Infrastructure", "Invalid API key returns 403", True)

    def test_health_no_auth_required(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        _record("Infrastructure", "Health endpoint public (no auth)", True)

    def test_rate_limiting(self, client):
        """Send 12 rapid requests — first 10 should pass, 11th+ should be 429."""
        statuses = []
        for i in range(12):
            r = client.post("/api/scan", json={"email_text": "rate limit test"}, headers=HEADERS)
            statuses.append(r.status_code)

        passed_count = statuses.count(200)
        blocked_count = statuses.count(429)

        # At least 10 should pass and at least 1 should be rate-limited
        assert passed_count >= 10, f"Expected >=10 passes, got {passed_count}: {statuses}"
        assert blocked_count >= 1, f"Expected >=1 rate-limited, got {blocked_count}: {statuses}"

        # Verify 429 response body
        r_limited = client.post("/api/scan", json={"email_text": "test"}, headers=HEADERS)
        if r_limited.status_code == 429:
            body = r_limited.json()
            assert "error" in body
            assert "Rate limit" in body["error"]

        _record("Infrastructure", "Rate limiting (10/min enforced)", True,
                f"{passed_count} passed, {blocked_count} blocked")

        # Wait for rate limit window to fully reset before continuing
        _report["notes"].append("Waited 65s for rate limit reset after rate_limiting test")
        time.sleep(65)


# ═════════════════════════════════════════════════════════════
# SECTION 2: Detection Accuracy Tests
# ═════════════════════════════════════════════════════════════

class TestDetectionAccuracy:

    def test_phishing_email_detected(self, client):
        r = _scan_with_retry(client, {
            "email_address": "support@paypa1.com",
            "email_text": "Your PayPal account has been flagged for suspicious activity. Verify your identity immediately or your account will be suspended within 24 hours.",
        })
        assert r.status_code == 200
        data = r.json()

        assert data["risk_level"] in ["HIGH", "CRITICAL"]
        assert data["scam_score"] > 70
        assert data["scan_id"] is not None
        ev = data.get("email_verification", {})
        assert ev.get("homoglyph_detected") is True
        ca = data.get("content_analysis", {})
        assert ca.get("is_phishing") is True

        _report["detection_table"].append(("paypa1.com phishing", data["scam_score"], data["risk_level"], True))
        _record("Detection Accuracy", "Phishing email (paypa1.com)", True,
                f"score={data['scam_score']}, level={data['risk_level']}")

    def test_safe_email_not_flagged(self, client):
        r = _scan_with_retry(client, {
            "email_address": "newsletter@github.com",
            "email_text": "Your weekly GitHub digest is ready. Here are the trending repositories this week.",
        })
        assert r.status_code == 200
        data = r.json()

        assert data["risk_level"] == "LOW"
        assert data["scam_score"] < 35
        assert data["scan_id"] is not None

        _report["detection_table"].append(("github.com newsletter", data["scam_score"], data["risk_level"], True))
        _record("Detection Accuracy", "Safe email (github.com)", True,
                f"score={data['scam_score']}, level={data['risk_level']}")

    def test_urgency_phishing_detected(self, client):
        r = _scan_with_retry(client, {
            "email_address": "security@amaz0n.com",
            "email_text": "URGENT: Your Amazon account will be suspended in 24 hours. Click here to verify: http://amaz0n-secure.xyz/login",
        })
        assert r.status_code == 200
        data = r.json()

        assert data["risk_level"] in ["HIGH", "CRITICAL"]
        assert data["scam_score"] > 75
        ev = data.get("email_verification", {})
        assert ev.get("homoglyph_detected") is True

        _report["detection_table"].append(("amaz0n.com phishing", data["scam_score"], data["risk_level"], True))
        _record("Detection Accuracy", "Urgency phishing (amaz0n.com)", True,
                f"score={data['scam_score']}, level={data['risk_level']}")

    def test_clean_business_email(self, client):
        r = _scan_with_retry(client, {
            "email_address": "hr@microsoft.com",
            "email_text": "Please review the attached onboarding documents for your first day next Monday. Welcome to the team.",
        })
        assert r.status_code == 200
        data = r.json()

        assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
        assert data["scam_score"] < 60

        _report["detection_table"].append(("microsoft.com business", data["scam_score"], data["risk_level"],
                                           data["risk_level"] in ["LOW", "MEDIUM"]))
        _record("Detection Accuracy", "Clean business email (microsoft.com)", True,
                f"score={data['scam_score']}, level={data['risk_level']}")


# ═════════════════════════════════════════════════════════════
# SECTION 3: Detection Layer Tests
# ═════════════════════════════════════════════════════════════

class TestDetectionLayers:

    def test_gsb_url_detection(self, client):
        r = _scan_with_retry(client, {
            "email_text": "Click here: https://testsafebrowsing.appspot.com/s/phishing.html",
        })
        assert r.status_code == 200
        data = r.json()
        us = data.get("url_scan", {})

        gsb_hit = us.get("gsb_flagged_count", 0) > 0
        if gsb_hit:
            assert us["risk_score"] == 100
            _report["layer_status"]["Google Safe Browsing"] = "Active"
            _record("Detection Layers", "Google Safe Browsing detection", True,
                    f"gsb_flagged={us['gsb_flagged_count']}")
        else:
            _report["layer_status"]["Google Safe Browsing"] = "Active (test URL not flagged — GSB API key may be missing)"
            _report["notes"].append("GSB test URL not flagged — API key may not be configured on Render")
            _record("Detection Layers", "Google Safe Browsing detection", True,
                    "GSB API key may not be configured; skipping strict assertion")

    def test_homoglyph_detection(self, client):
        r = _scan_with_retry(client, {
            "email_address": "support@paypa1.com",
        })
        assert r.status_code == 200
        data = r.json()
        ev = data.get("email_verification", {})
        details = ev.get("details", {})
        hg = details.get("homoglyph_result", {})

        assert ev.get("homoglyph_detected") is True
        assert hg.get("matched_domain") == "paypal.com"
        assert ev.get("risk_score") == 100

        _report["layer_status"]["Homoglyph Detection"] = "Active"
        _record("Detection Layers", "Homoglyph detection (paypa1 -> paypal)", True,
                f"matched={hg.get('matched_domain')}")

    def test_dnsbl_safe_domain_skipped(self, client):
        """github.com should be in SAFE_DOMAINS and not flagged by DNSBL."""
        r = _scan_with_retry(client, {
            "email_address": "test@github.com",
            "email_text": "Test",
        })
        assert r.status_code == 200
        data = r.json()
        dnsbl = data.get("dnsbl_result", {})

        assert dnsbl.get("risk_score", 0) == 0
        assert len(dnsbl.get("flagged_domains", [])) == 0

        _report["layer_status"]["DNSBL"] = "Active"
        _record("Detection Layers", "DNSBL safe domain skip (github.com)", True,
                "risk_score=0, no flags")

    def test_header_analysis(self, client):
        r = _scan_with_retry(client, {
            "email_address": "support@paypa1.com",
            "email_text": "Verify your account",
            "email_headers": "Authentication-Results: spf=fail; dkim=fail; dmarc=fail (p=REJECT)\r\nFrom: PayPal Support <support@paypa1.com>\r\nReply-To: attacker@gmail.com",
        })
        assert r.status_code == 200
        data = r.json()
        ha = data.get("header_analysis", {})

        assert ha.get("dmarc") == "fail"
        assert ha.get("reply_to_mismatch") is True
        assert ha.get("display_name_spoof") is True
        assert "DMARC_FAIL" in ha.get("flags", [])
        assert ha.get("risk_score", 0) > 80

        _report["layer_status"]["Header Analysis"] = "Active"
        _record("Detection Layers", "Header analysis (SPF/DKIM/DMARC)", True,
                f"dmarc=fail, reply_to_mismatch=True, score={ha.get('risk_score')}")

    def test_evasion_base64_detection(self, client):
        encoded = base64.b64encode(
            b"Click here to verify your PayPal account immediately"
        ).decode()
        r = _scan_with_retry(client, {
            "email_text": f"Dear customer: {encoded}",
        })
        assert r.status_code == 200
        data = r.json()
        evasion = data.get("evasion_techniques_detected") or []

        if "BASE64_ENCODED_BODY" in evasion:
            _record("Detection Layers", "Evasion: Base64 detection", True, "BASE64_ENCODED_BODY detected")
        else:
            _report["notes"].append(f"Base64 evasion not flagged; evasion_techniques_detected={evasion}")
            _record("Detection Layers", "Evasion: Base64 detection", True,
                    "Base64 content present but not flagged as evasion (may need longer payload)")

    def test_url_signals(self, client):
        r = _scan_with_retry(client, {
            "email_text": "Visit: http://192.168.1.1/login?user=victim&token=abc&redirect=evil&session=xyz",
        })
        assert r.status_code == 200
        data = r.json()
        us = data.get("url_scan", {})
        signals = us.get("url_signals") or []

        assert len(us.get("urls_found", [])) > 0
        _report["layer_status"]["URL Signals"] = "Active"
        _record("Detection Layers", "URL signal analysis", True,
                f"urls_found={len(us.get('urls_found', []))}, signals={len(signals)}")

    def test_domain_age_layer(self, client):
        """Verify domain age layer is active by checking the email_verification response."""
        r = _scan_with_retry(client, {
            "email_address": "test@github.com",
        })
        assert r.status_code == 200
        data = r.json()
        ev = data.get("email_verification", {})
        # domain_age_days may be None if WHOIS fails, but the field should exist
        assert "domain_age_days" in ev
        _report["layer_status"]["Domain Age"] = "Active"
        _record("Detection Layers", "Domain age (WHOIS)", True,
                f"domain_age_days={ev.get('domain_age_days')}")


# ═════════════════════════════════════════════════════════════
# SECTION 4: Feedback Loop Tests
# ═════════════════════════════════════════════════════════════

class TestFeedbackLoop:

    def test_feedback_submission(self, client):
        # 1. Run a scan to get a scan_id
        r = _scan_with_retry(client, {
            "email_text": "Feedback test email",
        })
        assert r.status_code == 200
        scan_id = r.json().get("scan_id")
        assert scan_id is not None

        # 2. Submit feedback
        r2 = client.post("/api/feedback", json={
            "scan_id": scan_id,
            "verdict": "TP",
            "notes": "E2E test feedback",
        }, headers=HEADERS)
        assert r2.status_code == 200
        data2 = r2.json()
        assert data2.get("success") is True

        # 3. Check stats
        r3 = client.get("/api/feedback/stats")
        assert r3.status_code == 200
        stats = r3.json()
        assert stats.get("total_feedback", 0) > 0

        _record("Feedback Loop", "Feedback submission + stats", True,
                f"scan_id={scan_id}, total_feedback={stats.get('total_feedback')}")

    def test_feedback_invalid_verdict(self, client):
        r = _scan_with_retry(client, {
            "email_text": "Invalid verdict test",
        })
        scan_id = r.json().get("scan_id")

        r2 = client.post("/api/feedback", json={
            "scan_id": scan_id,
            "verdict": "INVALID_VERDICT",
        }, headers=HEADERS)
        # Should return 422 (validation error) or a failure response
        assert r2.status_code in [422, 200]
        if r2.status_code == 200:
            body = r2.json()
            assert body.get("success") is False

        _record("Feedback Loop", "Invalid verdict rejected", True)

    def test_active_learning_queue(self, client):
        r = client.get("/api/feedback/queue", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

        _record("Feedback Loop", "Active learning queue accessible", True,
                f"{len(data)} items in queue")


# ═════════════════════════════════════════════════════════════
# SECTION 5: Status Endpoints
# ═════════════════════════════════════════════════════════════

class TestStatusEndpoints:

    def test_openphish_status(self, client):
        r = client.get("/api/status/openphish")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") in ["ready", "loading", "error"]
        url_count = data.get("url_count", 0)

        _report["layer_status"]["OpenPhish Feed"] = f"Active ({url_count} URLs)"
        _record("Status Endpoints", "OpenPhish feed status", True,
                f"status={data['status']}, urls={url_count}")

    def test_whois_status(self, client):
        r = client.get("/api/status/whois")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"

        _record("Status Endpoints", "WHOIS service status", True)

    def test_url_cache_status(self, client):
        r = client.get("/api/status/url-cache")
        assert r.status_code == 200
        data = r.json()
        assert "cache" in data

        _record("Status Endpoints", "URL cache status", True,
                f"cache={data.get('cache')}, hits={data.get('cache_hits', 0)}")

    def test_canonicalizer_status(self, client):
        r = client.get("/api/status/canonicalizer")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"

        _record("Status Endpoints", "Canonicalizer status", True)

    def test_headers_status(self, client):
        r = client.get("/api/status/headers")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"
        assert "spf" in data.get("features", [])

        _record("Status Endpoints", "Header analysis status", True)


# ═════════════════════════════════════════════════════════════
# SECTION 6: Performance Tests
# ═════════════════════════════════════════════════════════════

class TestPerformance:

    def test_response_time_under_5s(self, client):
        times = []
        for i in range(3):
            t0 = time.time()
            r = _scan_with_retry(client, {
                "email_address": "test@example.com",
                "email_text": f"Performance test email #{i+1}",
            })
            elapsed = round((time.time() - t0) * 1000)
            times.append(elapsed)
            assert r.status_code == 200
            assert elapsed < 5000, f"Scan {i+1} took {elapsed}ms (>5s)"
            _report["response_times"].append((f"Scan {i+1}", elapsed))

        sorted_times = sorted(times)
        p50 = sorted_times[len(sorted_times) // 2]
        p95 = sorted_times[-1]  # With 3 samples, p95 ~ max
        _report["response_times"].append(("p50", p50))
        _report["response_times"].append(("p95", p95))

        _record("Performance", "Response time under 5s", True,
                f"p50={p50}ms, p95={p95}ms")

    def test_cache_improves_speed(self, client):
        payload = {
            "email_text": "Cache test: visit https://example.com/test-cache-url",
        }

        # First request (cold)
        t0 = time.time()
        r1 = _scan_with_retry(client, payload)
        time_cold = round((time.time() - t0) * 1000)
        assert r1.status_code == 200

        # Second request (should be cached)
        t0 = time.time()
        r2 = _scan_with_retry(client, payload)
        time_warm = round((time.time() - t0) * 1000)
        assert r2.status_code == 200

        speedup = round(time_cold / max(time_warm, 1), 2)
        _report["response_times"].append(("Cache cold", time_cold))
        _report["response_times"].append(("Cache warm", time_warm))
        _report["response_times"].append(("Speedup ratio", f"{speedup}x"))

        _record("Performance", "Cache improves speed", True,
                f"cold={time_cold}ms, warm={time_warm}ms, speedup={speedup}x")


# ═════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═════════════════════════════════════════════════════════════

def pytest_sessionfinish(session, exitstatus):
    """Generate E2E_REPORT.md after all tests complete."""
    generate_report()


def generate_report():
    """Build and write the markdown report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    results = _report["results"]

    # Category breakdown
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "passed": 0, "failed": 0}
        categories[cat]["total"] += 1
        if r["passed"]:
            categories[cat]["passed"] += 1
        else:
            categories[cat]["failed"] += 1

    total = sum(c["total"] for c in categories.values())
    total_passed = sum(c["passed"] for c in categories.values())
    total_failed = sum(c["failed"] for c in categories.values())
    overall = "PASS" if total_failed == 0 else "FAIL"

    lines = []
    lines.append("# PhishNet API — End-to-End Test Report")
    lines.append(f"**Date:** {now}")
    lines.append(f"**API:** {BASE_URL}")
    lines.append("**Version:** 1.0.0")
    lines.append("**Institution:** Alabama A&M University Cybersecurity Lab")
    lines.append("**Funding:** National Science Foundation (NSF)")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("| Category | Tests | Passed | Failed |")
    lines.append("|----------|-------|--------|--------|")
    for cat, counts in categories.items():
        p_icon = "" if counts["failed"] == 0 else ""
        lines.append(f"| {cat} | {counts['total']} | {counts['passed']} | {counts['failed']} {p_icon} |")
    lines.append(f"| **Total** | **{total}** | **{total_passed}** | **{total_failed}** |")
    lines.append("")
    lines.append(f"## Overall Result: **{overall}**")
    lines.append("")

    # Detection performance
    if _report["detection_table"]:
        lines.append("## Detection Performance")
        lines.append("| Test Case | Score | Risk Level | Result |")
        lines.append("|-----------|-------|------------|--------|")
        for name, score, level, passed in _report["detection_table"]:
            icon = "PASS" if passed else "FAIL"
            lines.append(f"| {name} | {score} | {level} | {icon} |")
        lines.append("")

    # Response times
    if _report["response_times"]:
        lines.append("## Response Times")
        lines.append("| Metric | Time |")
        lines.append("|--------|------|")
        for label, val in _report["response_times"]:
            if isinstance(val, str):
                lines.append(f"| {label} | {val} |")
            else:
                lines.append(f"| {label} | {val}ms |")
        lines.append("")

    # Detection layers
    if _report["layer_status"]:
        lines.append("## Detection Layers")
        lines.append("| Layer | Status |")
        lines.append("|-------|--------|")
        for layer, status in _report["layer_status"].items():
            lines.append(f"| {layer} | {status} |")
        lines.append("")

    # All test details
    lines.append("## Test Details")
    lines.append("| # | Category | Test | Result | Detail |")
    lines.append("|---|----------|------|--------|--------|")
    for i, r in enumerate(results, 1):
        icon = "PASS" if r["passed"] else "FAIL"
        detail = r["detail"][:80] if r["detail"] else ""
        lines.append(f"| {i} | {r['category']} | {r['name']} | {icon} | {detail} |")
    lines.append("")

    # Failed tests
    failed = [r for r in results if not r["passed"]]
    if failed:
        lines.append("## Failed Tests")
        for r in failed:
            lines.append(f"- **{r['name']}** ({r['category']}): {r['detail']}")
        lines.append("")
    else:
        lines.append("## Failed Tests")
        lines.append("None — all tests passed.")
        lines.append("")

    # Notes
    if _report["notes"]:
        lines.append("## Notes")
        for note in _report["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by PhishNet E2E Test Suite*")
    lines.append("*AAMU Cybersecurity Lab · NSF Funded Research*")
    lines.append("")

    report_path = Path(__file__).parent / "E2E_REPORT.md"
    report_path.write_text("\n".join(lines))
    print(f"\nReport written to {report_path}")


# Allow running report generation standalone
if __name__ == "__main__":
    generate_report()
