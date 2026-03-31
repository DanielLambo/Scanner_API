"""
FastAPI Email Scanner Backend API
Main application with all endpoints
"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import asyncio

from models.schemas import (
    EmailScanRequest,
    CompleteScanResponse,
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult,
    HeaderAnalysisResult,
    HealthResponse
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
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize background services on startup."""
    await openphish.initialize()


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
    api_key: str = Depends(verify_api_key)
):
    """
    Complete email scan using all three methods:
    - Email address verification (Hunter.io)
    - URL scanning (VirusTotal)
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
        content_result = content_analyzer.analyze_content(request.email_text)
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
        content_result = content_analyzer.analyze_content(request.email_text)
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
    )

    return response


@app.post("/api/scan/email-address", response_model=EmailVerificationResult)
async def scan_email_address(
    request: EmailScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Email address verification only
    Uses Hunter.io API to validate email and check reputation
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
    Uses VirusTotal API to detect malicious links in email text
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
    
    return content_analyzer.analyze_content(request.email_text)


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )
