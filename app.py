"""
FastAPI Email Scanner Backend API
Main application with all endpoints
"""
from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import asyncio
from contextlib import asynccontextmanager
import secrets
import threading

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from models.schemas import (
    EmailScanRequest,
    CompleteScanResponse,
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult,
    HeaderAnalysisResult,
    HealthResponse,
    FeedbackRequest,
)
from services.email_verifier import email_verifier
from services.url_scanner import url_scanner
from services.content_analyzer import content_analyzer
from services.score_calculator import score_calculator
from services.openphish import openphish
from services.domain_age import check_domain_age, _redis_available
from services.dnsbl import check_domains as dnsbl_check_domains
from services.url_scanner import url_scanner, _url_cache
from services.header_analyzer import analyze_headers
from middleware.auth import verify_api_key
from config import settings
from db.database import engine, SessionLocal, Base
from db.models import Scan, Feedback, ActiveLearningQueue, APIKey  # noqa: F401 — needed for Base.metadata
from db.crud import (
    save_scan, save_feedback, add_to_active_learning, get_review_queue,
    get_feedback_stats, create_api_key, list_api_keys, revoke_api_key,
    api_keys_exist,
)


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


def _download_and_load_models():
    """Download models from HuggingFace and load them (runs in background thread)."""
    from ml.download_models import download_models_if_missing
    download_models_if_missing()
    content_analyzer._load_model()


@asynccontextmanager
async def lifespan(app):
    """Initialize background services on startup."""
    thread = threading.Thread(target=_download_and_load_models, daemon=True)
    thread.start()
    await openphish.initialize()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed API keys on first run
    async with SessionLocal() as db:
        if not await api_keys_exist(db):
            master_key = await create_api_key(
                db,
                owner_email="daniel.lambo@bulldogs.aamu.edu",
                owner_name="Daniel Lambo",
                tier="research",
            )
            print(f"MASTER API KEY: {master_key}")
            await create_api_key(
                db,
                owner_email="demo@phishnet.dev",
                owner_name="Demo User",
                tier="free",
                key_override="phishingisevil",
            )
            print("DEMO  API KEY: phishingisevil")
    yield


# Initialize FastAPI app
app = FastAPI(
    lifespan=lifespan,
    title="PhishNet API",
    description="""
## Phishing Detection Infrastructure

NSF-funded research from **Alabama A&M University Cybersecurity Lab**.
Published in Springer. Presented at SAM'25 Las Vegas.

### Authentication
All endpoints require `X-API-Key` header.
Request access: daniel.lambo@bulldogs.aamu.edu

### Detection Layers
- Google Safe Browsing
- OpenPhish community feed
- DNSBL (Spamhaus, SURBL, URIBL)
- ML Classifier (TF-IDF ensemble, 96% F1)
- Email header analysis (SPF/DKIM/DMARC)
- URL structural signals
- Homoglyph detection
- Domain age (WHOIS)

### Rate Limits
- `/api/scan`: 10 requests/minute
- Other scan endpoints: 20 requests/minute
""",
    version="1.0.0",
    contact={
        "name": "Daniel Lambo — AAMU Cybersecurity Lab",
        "email": "daniel.lambo@bulldogs.aamu.edu",
    },
    license_info={"name": "MIT"},
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "message": "10 requests per minute allowed on free tier. Contact daniel.lambo@bulldogs.aamu.edu for higher limits.",
            "retry_after": "60 seconds",
        },
    )

# CORS configuration for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow landing page and any frontend to call the API
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def get_db():
    """Dependency that provides an async database session."""
    async with SessionLocal() as session:
        yield session


@app.get("/health", response_model=HealthResponse, responses={
    200: {"content": {"application/json": {"example": {
        "status": "healthy",
        "ml_model_loaded": True,
    }}}},
})
async def health_check():
    """
    Health check endpoint.
    Returns service status and ML model availability.
    No authentication required.
    """
    return HealthResponse(
        status="healthy",
        ml_model_loaded=content_analyzer.is_model_available()
    )


@app.post("/api/scan", response_model=CompleteScanResponse, responses={
    200: {"content": {"application/json": {"example": {
        "scan_id": "1a49b796-d242-448d-929a-dbec00106dcf",
        "scam_score": 83.38,
        "risk_level": "CRITICAL",
        "labels": ["Homoglyph Domain", "Phishing Content", "DMARC Fail"],
        "recommendations": [
            "Do not click any links in this email",
            "This email failed DMARC authentication — sender domain is spoofed",
        ],
        "content_analysis": {"prediction": "Phishing Email", "confidence": 0.986, "risk_score": 98.6, "is_phishing": True},
        "email_verification": {"risk_score": 100.0, "homoglyph_detected": True},
        "header_analysis": {"dmarc": "fail", "reply_to_mismatch": True, "risk_score": 100.0},
    }}}},
    429: {"content": {"application/json": {"example": {
        "error": "Rate limit exceeded",
        "message": "10 requests per minute allowed on free tier. Contact daniel@aamu.edu for higher limits.",
        "retry_after": "60 seconds",
    }}}},
})
@limiter.limit("10/minute")
async def complete_scan(
    request: Request,
    scan_request: EmailScanRequest,
    api_key: str = Depends(verify_api_key),
    db=Depends(get_db),
):
    """
    Complete email scan using all 8 detection layers concurrently.
    Returns a composite scam score (0-100), risk level, labels, and recommendations.

    **Rate limit:** 10 requests/minute
    """
    email_result = None
    url_result = None
    content_result = None
    dnsbl_result = None
    header_result = None

    # Helper to extract domains for DNSBL from email + urls
    def _domains_for_dnsbl(email_address, urls):
        from urllib.parse import urlparse
        domains = set()
        if email_address:
            domains.add(email_address.split("@")[-1].lower())
        for u in (urls or []):
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
        return list(domains)

    # Wrap synchronous analyze_headers so it can join asyncio.gather
    async def _run_header_analysis(raw: str) -> HeaderAnalysisResult:
        result = analyze_headers(raw)
        return HeaderAnalysisResult(**result)

    # Accumulated evasion labels from all services
    all_evasion_labels = []

    # Run email verification (now async) and URL scan concurrently when both present
    if scan_request.email_address and scan_request.email_text:
        tasks = [
            url_scanner.scan_urls(scan_request.email_text),
            email_verifier.verify_email(scan_request.email_address),
        ]
        if scan_request.email_headers:
            tasks.append(_run_header_analysis(scan_request.email_headers))
        gathered = await asyncio.gather(*tasks)
        url_result, email_result = gathered[0], gathered[1]
        if scan_request.email_headers:
            header_result = gathered[2]
        content_result, content_evasion = content_analyzer.analyze_content(scan_request.email_text)
        all_evasion_labels.extend(content_evasion)
        domains = _domains_for_dnsbl(scan_request.email_address, url_result.urls_found)
        dnsbl_result = await dnsbl_check_domains(domains)
    elif scan_request.email_address:
        tasks = [
            email_verifier.verify_email(scan_request.email_address),
            dnsbl_check_domains(_domains_for_dnsbl(scan_request.email_address, None)),
        ]
        if scan_request.email_headers:
            tasks.append(_run_header_analysis(scan_request.email_headers))
        gathered = await asyncio.gather(*tasks)
        email_result, dnsbl_result = gathered[0], gathered[1]
        if scan_request.email_headers:
            header_result = gathered[2]
    elif scan_request.email_text:
        tasks = [url_scanner.scan_urls(scan_request.email_text)]
        if scan_request.email_headers:
            tasks.append(_run_header_analysis(scan_request.email_headers))
        gathered = await asyncio.gather(*tasks)
        url_result = gathered[0]
        if scan_request.email_headers:
            header_result = gathered[1]
        content_result, content_evasion = content_analyzer.analyze_content(scan_request.email_text)
        all_evasion_labels.extend(content_evasion)
        domains = _domains_for_dnsbl(None, url_result.urls_found)
        dnsbl_result = await dnsbl_check_domains(domains)
    elif scan_request.email_headers:
        header_result = await _run_header_analysis(scan_request.email_headers)

    # Calculate combined score
    response = score_calculator.calculate_score(
        email_result=email_result,
        url_result=url_result,
        content_result=content_result,
        dnsbl_result=dnsbl_result,
        header_analysis=header_result,
        evasion_labels=all_evasion_labels if all_evasion_labels else None,
    )

    # Persist scan and attach scan_id to response
    scan_id = await save_scan(db, response, scan_request.email_address)
    response.scan_id = scan_id

    # Active learning: queue if low confidence or high disagreement
    confidence = response.content_analysis.confidence if response.content_analysis else 0.0
    disagreement = 0.0
    if confidence < 0.65 or disagreement > 0.3:
        await add_to_active_learning(db, scan_id, confidence, disagreement)

    return response


@app.post("/api/scan/email-address", response_model=EmailVerificationResult, responses={
    200: {"content": {"application/json": {"example": {
        "risk_score": 100.0,
        "domain_age_days": None,
        "domain_age_risk": 0.0,
        "homoglyph_detected": True,
        "details": {"homoglyph_result": {"is_homoglyph": True, "matched_domain": "paypal.com", "original": "paypa1.com"}},
    }}}},
})
@limiter.limit("20/minute")
async def scan_email_address(
    request: Request,
    scan_request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Email address verification only.
    Checks domain age (WHOIS) and homoglyph detection against known brands.

    **Rate limit:** 20 requests/minute
    """
    if not scan_request.email_address:
        raise HTTPException(
            status_code=400,
            detail="email_address is required for this endpoint"
        )

    return await email_verifier.verify_email(scan_request.email_address)


@app.post("/api/scan/urls", response_model=URLScanResult, responses={
    200: {"content": {"application/json": {"example": {
        "urls_found": ["https://paypa1.com/verify"],
        "malicious_count": 1,
        "suspicious_count": 0,
        "risk_score": 85.0,
        "gsb_flagged_count": 0,
    }}}},
})
@limiter.limit("20/minute")
async def scan_urls(
    request: Request,
    scan_request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    URL scanning only.
    Checks URLs against Google Safe Browsing, OpenPhish, DNSBL, and structural signals.

    **Rate limit:** 20 requests/minute
    """
    if not scan_request.email_text:
        raise HTTPException(
            status_code=400,
            detail="email_text is required for this endpoint"
        )

    return await url_scanner.scan_urls(scan_request.email_text)


@app.post("/api/scan/content", response_model=ContentAnalysisResult, responses={
    200: {"content": {"application/json": {"example": {
        "prediction": "Phishing Email",
        "confidence": 0.941,
        "risk_score": 94.1,
        "is_phishing": True,
        "ensemble_disagreement": 0.0,
        "models_agree": True,
    }}}},
})
@limiter.limit("20/minute")
async def scan_content(
    request: Request,
    scan_request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Content analysis only.
    Classifies email text using TF-IDF ensemble ML model (96% F1 score).

    **Rate limit:** 20 requests/minute
    """
    if not scan_request.email_text:
        raise HTTPException(
            status_code=400,
            detail="email_text is required for this endpoint"
        )

    if not content_analyzer.is_model_available():
        raise HTTPException(
            status_code=503,
            detail="ML model not available. Train the model first using ml/train_model.py"
        )

    result, _evasion = content_analyzer.analyze_content(scan_request.email_text)
    return result


@app.get("/api/status/openphish")
async def openphish_status():
    """
    OpenPhish feed status
    Returns current feed size, last update time, and readiness
    """
    return {
        "status": openphish.status,
        "url_count": openphish.url_count,
        "last_updated": openphish.last_updated,
        "source": "openphish",
    }


@app.get("/api/status/whois")
async def whois_status():
    """WHOIS service status — no auth required."""
    return {
        "status": "ok",
        "cache": "redis" if _redis_available else "none",
    }


@app.get("/api/status/url-cache")
async def url_cache_status():
    """URL scan cache status — shows hit count and Redis availability."""
    return {
        "status": "ok",
        "cache": "redis" if _url_cache.available else "none",
        "cache_hits": _url_cache.hits,
    }


@app.get("/api/status/canonicalizer")
async def canonicalizer_status():
    """Canonicalizer service status."""
    return {
        "status": "ok",
        "redirect_following": True,
        "max_hops": 5,
    }


@app.get("/api/status/headers")
async def headers_status():
    """Header analysis service status."""
    return {
        "status": "ok",
        "features": ["spf", "dkim", "dmarc", "reply_to", "hop_analysis"],
    }


@app.post("/api/feedback")
async def submit_feedback(
    request: FeedbackRequest,
    db=Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    """
    Submit feedback for a scan result.
    verdict must be one of: TP, FP, FN, TN
    """
    try:
        success = await save_feedback(db, request.scan_id, request.verdict, request.notes)
    except ValueError as exc:
        return {"success": False, "message": str(exc)}

    if success:
        return {"success": True, "message": "Feedback recorded successfully"}
    return {"success": False, "message": f"scan_id '{request.scan_id}' not found"}


@app.get("/api/feedback/queue")
async def feedback_queue(
    db=Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    """
    Return unreviewed active learning queue items (most recent first).
    """
    items = await get_review_queue(db)
    return items


@app.get("/api/feedback/stats")
async def feedback_stats(db=Depends(get_db)):
    """
    Return aggregate statistics: scan counts, feedback counts, verdict breakdown,
    and active learning queue sizes.
    """
    stats = await get_feedback_stats(db)
    return stats


# --------------- Admin endpoints ---------------

async def verify_admin_key(x_admin_key: str = Header(None)):
    """Dependency that validates the X-Admin-Key header."""
    if not x_admin_key:
        raise HTTPException(status_code=401, detail="Missing X-Admin-Key header")
    if not secrets.compare_digest(x_admin_key, settings.admin_key):
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return x_admin_key


class CreateKeyRequest(BaseModel):
    owner_email: str
    owner_name: Optional[str] = None
    tier: str = "free"


class RevokeKeyRequest(BaseModel):
    key: str


@app.post("/admin/keys/create")
async def admin_create_key(
    request: CreateKeyRequest,
    db=Depends(get_db),
    _admin: str = Depends(verify_admin_key),
):
    """Create a new API key (admin only)."""
    key = await create_api_key(db, request.owner_email, request.owner_name, request.tier)
    return {
        "key": key,
        "owner_email": request.owner_email,
        "tier": request.tier,
        "created": True,
    }


@app.get("/admin/keys/list")
async def admin_list_keys(
    db=Depends(get_db),
    _admin: str = Depends(verify_admin_key),
):
    """List all API keys with masked values (admin only)."""
    return await list_api_keys(db)


@app.post("/admin/keys/revoke")
async def admin_revoke_key(
    request: RevokeKeyRequest,
    db=Depends(get_db),
    _admin: str = Depends(verify_admin_key),
):
    """Revoke an API key (admin only)."""
    success = await revoke_api_key(db, request.key)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"success": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )
