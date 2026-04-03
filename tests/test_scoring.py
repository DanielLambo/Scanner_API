"""
Unit tests for the score calculator.
"""
import pytest
import pytest_asyncio
from models.schemas import (
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult,
    CompleteScanResponse,
)
from services.score_calculator import score_calculator


def _email_result(risk_score=0.0) -> EmailVerificationResult:
    return EmailVerificationResult(
        risk_score=risk_score,
    )


def _url_result(risk_score=0.0, urls_found=None) -> URLScanResult:
    return URLScanResult(
        risk_score=risk_score,
        urls_found=urls_found or ["http://example.com"],
    )


def _content_result(risk_score=0.0, is_phishing=False, confidence=None) -> ContentAnalysisResult:
    return ContentAnalysisResult(
        prediction="Phishing Email" if is_phishing else "Safe Email",
        confidence=confidence if confidence is not None else (risk_score / 100.0 if risk_score > 0 else 1.0),
        risk_score=risk_score,
        is_phishing=is_phishing,
    )


# ---------------------------------------------------------------------------
# Weight tests
# ---------------------------------------------------------------------------

def test_score_calculator_weights():
    """With email=100, url=0, content=0 (high-conf), score should reflect proportional weighting."""
    result = score_calculator.calculate_score(
        email_result=_email_result(risk_score=100),
        url_result=_url_result(risk_score=0),
        content_result=_content_result(risk_score=0, confidence=1.0),
    )
    # email=0.25*100=25, url=0.45*0=0, content=0.30*0=0 → 25/1.0=25
    assert 20 <= result.scam_score <= 30


# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------

def test_risk_level_low():
    result = score_calculator.calculate_score(
        content_result=_content_result(risk_score=10),
    )
    assert result.risk_level == "LOW"


def test_risk_level_medium():
    result = score_calculator.calculate_score(
        content_result=_content_result(risk_score=40, confidence=0.95),
    )
    assert result.risk_level == "MEDIUM"


def test_risk_level_high():
    result = score_calculator.calculate_score(
        content_result=_content_result(risk_score=65, confidence=0.95),
    )
    assert result.risk_level == "HIGH"


def test_risk_level_critical():
    result = score_calculator.calculate_score(
        email_result=_email_result(risk_score=100),
        url_result=_url_result(risk_score=100),
        content_result=_content_result(risk_score=100, is_phishing=True, confidence=0.99),
    )
    assert result.risk_level == "CRITICAL"


# ---------------------------------------------------------------------------
# Evasion labels
# ---------------------------------------------------------------------------

def test_score_with_evasion_labels():
    result = score_calculator.calculate_score(
        content_result=_content_result(risk_score=10),
        evasion_labels=["BASE64_ENCODED_BODY"],
    )
    assert result.evasion_techniques_detected is not None
    assert "BASE64_ENCODED_BODY" in result.evasion_techniques_detected


# ---------------------------------------------------------------------------
# None inputs
# ---------------------------------------------------------------------------

def test_score_none_services():
    result = score_calculator.calculate_score(
        email_result=None,
        url_result=None,
        content_result=None,
    )
    assert result.scam_score == 0.0
    assert result.risk_level == "LOW"


# ---------------------------------------------------------------------------
# CRUD tests using async_db_session fixture from conftest.py
# ---------------------------------------------------------------------------

def _mock_scan_response(scam_score=75.0, risk_level="HIGH", confidence=0.9):
    """Build a minimal CompleteScanResponse for CRUD tests."""
    content = ContentAnalysisResult(
        prediction="Phishing Email",
        confidence=confidence,
        risk_score=scam_score,
        is_phishing=True,
    )
    return CompleteScanResponse(
        scam_score=scam_score,
        risk_level=risk_level,
        content_analysis=content,
    )


@pytest.mark.asyncio
async def test_crud_save_scan(async_db_session):
    from db.crud import save_scan
    response = _mock_scan_response()
    scan_id = await save_scan(async_db_session, response, "test@example.com")
    assert scan_id is not None
    assert isinstance(scan_id, str)
    assert len(scan_id) == 36  # UUID format


@pytest.mark.asyncio
async def test_crud_save_feedback(async_db_session):
    from db.crud import save_scan, save_feedback
    response = _mock_scan_response()
    scan_id = await save_scan(async_db_session, response, "test@example.com")
    result = await save_feedback(async_db_session, scan_id, "TP", "test notes")
    assert result is True


@pytest.mark.asyncio
async def test_crud_feedback_nonexistent(async_db_session):
    from db.crud import save_feedback
    result = await save_feedback(async_db_session, "nonexistent-id", "TP")
    assert result is False


@pytest.mark.asyncio
async def test_crud_active_learning_queue(async_db_session):
    from db.crud import save_scan, add_to_active_learning, get_review_queue
    response = _mock_scan_response()
    scan_id = await save_scan(async_db_session, response, "test@example.com")
    await add_to_active_learning(async_db_session, scan_id, confidence=0.4, disagreement=0.0)
    queue = await get_review_queue(async_db_session)
    assert len(queue) == 1
    assert queue[0]["reason"] == "low_confidence"


@pytest.mark.asyncio
async def test_crud_feedback_stats(async_db_session):
    from db.crud import save_scan, save_feedback, get_feedback_stats
    resp1 = _mock_scan_response()
    resp2 = _mock_scan_response(scam_score=30.0, risk_level="LOW")
    scan_id1 = await save_scan(async_db_session, resp1, "a@example.com")
    await save_scan(async_db_session, resp2, "b@example.com")
    await save_feedback(async_db_session, scan_id1, "TP")
    stats = await get_feedback_stats(async_db_session)
    assert stats["total_scans"] == 2
    assert stats["total_feedback"] == 1
    assert stats["verdict_counts"]["TP"] == 1
