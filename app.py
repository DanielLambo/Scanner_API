"""
FastAPI Email Scanner Backend API
Main application with all endpoints
"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from models.schemas import (
    EmailScanRequest,
    CompleteScanResponse,
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult,
    HealthResponse
)
from services.email_verifier import email_verifier
from services.url_scanner import url_scanner
from services.content_analyzer import content_analyzer
from services.score_calculator import score_calculator
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
    
    # Run email verification if email address provided
    if request.email_address:
        email_result = email_verifier.verify_email(request.email_address)
    
    # Run URL scanning if email text provided
    if request.email_text:
        url_result = url_scanner.scan_urls(request.email_text)
        content_result = content_analyzer.analyze_content(request.email_text)
    
    # Calculate combined score
    response = score_calculator.calculate_score(
        email_result=email_result,
        url_result=url_result,
        content_result=content_result
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
    
    return email_verifier.verify_email(request.email_address)


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
    
    return url_scanner.scan_urls(request.email_text)


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )
