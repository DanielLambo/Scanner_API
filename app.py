"""
FastAPI Email Scanner Backend API
Main application with all endpoints
"""
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import secrets
import threading

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


# Initialize FastAPI app
app = FastAPI(
    title="Email Scanner API",
    description="Backend API for email phishing and scam detection using multiple analysis methods",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow landing page and any frontend to call the API
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _download_and_load_models():
    """Download models from HuggingFace and load them (runs in background thread)."""
    from ml.download_models import download_models_if_missing
    download_models_if_missing()
    content_analyzer._load_model()


@app.on_event("startup")
async def startup_event():
    """Initialize background services on startup."""
    # Start model download in background thread so port binds immediately
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
                owner_email="daniel@aamu.edu",
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


async def get_db():
    """Dependency that provides an async database session."""
    async with SessionLocal() as session:
        yield session


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint
    Returns service status and ML model availability
    """
    return HealthResponse(
        status="healthy",
        ml_model_loaded=content_analyzer.is_model_available()
    )


@app.post("/api/scan", response_model=CompleteScanResponse)
async def complete_scan(
    request: EmailScanRequest,
    api_key: str = Depends(verify_api_key),
    db=Depends(get_db),
):
    """
    Complete email scan using all methods:
    - Email address verification (domain age + homoglyph detection)
    - URL scanning (Google Safe Browsing, OpenPhish, url_signals)
    - Content analysis (ML model)

    Returns comprehensive scam score and risk assessment
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
    if request.email_address and request.email_text:
        tasks = [
            url_scanner.scan_urls(request.email_text),
            email_verifier.verify_email(request.email_address),
        ]
        if request.email_headers:
            tasks.append(_run_header_analysis(request.email_headers))
        gathered = await asyncio.gather(*tasks)
        url_result, email_result = gathered[0], gathered[1]
        if request.email_headers:
            header_result = gathered[2]
        content_result, content_evasion = content_analyzer.analyze_content(request.email_text)
        all_evasion_labels.extend(content_evasion)
        domains = _domains_for_dnsbl(request.email_address, url_result.urls_found)
        dnsbl_result = await dnsbl_check_domains(domains)
    elif request.email_address:
        tasks = [
            email_verifier.verify_email(request.email_address),
            dnsbl_check_domains(_domains_for_dnsbl(request.email_address, None)),
        ]
        if request.email_headers:
            tasks.append(_run_header_analysis(request.email_headers))
        gathered = await asyncio.gather(*tasks)
        email_result, dnsbl_result = gathered[0], gathered[1]
        if request.email_headers:
            header_result = gathered[2]
    elif request.email_text:
        tasks = [url_scanner.scan_urls(request.email_text)]
        if request.email_headers:
            tasks.append(_run_header_analysis(request.email_headers))
        gathered = await asyncio.gather(*tasks)
        url_result = gathered[0]
        if request.email_headers:
            header_result = gathered[1]
        content_result, content_evasion = content_analyzer.analyze_content(request.email_text)
        all_evasion_labels.extend(content_evasion)
        domains = _domains_for_dnsbl(None, url_result.urls_found)
        dnsbl_result = await dnsbl_check_domains(domains)
    elif request.email_headers:
        header_result = await _run_header_analysis(request.email_headers)

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
    scan_id = await save_scan(db, response, request.email_address)
    response.scan_id = scan_id

    # Active learning: queue if low confidence or high disagreement
    confidence = response.content_analysis.confidence if response.content_analysis else 0.0
    disagreement = 0.0
    if confidence < 0.65 or disagreement > 0.3:
        await add_to_active_learning(db, scan_id, confidence, disagreement)

    return response


@app.post("/api/scan/email-address", response_model=EmailVerificationResult)
async def scan_email_address(
    request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Email address verification only
    Uses domain age and homoglyph detection to assess sender risk
    """
    if not request.email_address:
        raise HTTPException(
            status_code=400,
            detail="email_address is required for this endpoint"
        )

    return await email_verifier.verify_email(request.email_address)


@app.post("/api/scan/urls", response_model=URLScanResult)
async def scan_urls(
    request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    URL scanning only
    Uses Google Safe Browsing, OpenPhish, and url_signals to detect malicious links
    """
    if not request.email_text:
        raise HTTPException(
            status_code=400,
            detail="email_text is required for this endpoint"
        )
    
    return await url_scanner.scan_urls(request.email_text)


@app.post("/api/scan/content", response_model=ContentAnalysisResult)
async def scan_content(
    request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Content analysis only
    Uses ML model to classify email text as phishing or safe
    """
    if not request.email_text:
        raise HTTPException(
            status_code=400,
            detail="email_text is required for this endpoint"
        )
    
    if not content_analyzer.is_model_available():
        raise HTTPException(
            status_code=503,
            detail="ML model not available. Train the model first using ml/train_model.py"
        )
    
    result, _evasion = content_analyzer.analyze_content(request.email_text)
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
