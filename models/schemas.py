"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict


class EmailScanRequest(BaseModel):
    """Request schema for email scanning"""
    email_address: Optional[EmailStr] = Field(None, description="Email address to verify")
    email_text: Optional[str] = Field(None, description="Email content to analyze")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email_address": "suspicious@example.com",
                "email_text": "Congratulations! Click here to claim your prize: http://phishing-site.com"
            }
        }


class EmailVerificationResult(BaseModel):
    """Result from Hunter.io email verification"""
    valid: bool = Field(description="Whether email is valid")
    score: float = Field(0.0, ge=0.0, le=100.0, description="Hunter.io quality score")
    disposable: bool = Field(False, description="Is disposable email")
    webmail: bool = Field(False, description="Is webmail provider")
    accept_all: bool = Field(False, description="Server accepts all emails")
    gibberish: bool = Field(False, description="Email appears gibberish")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    details: Optional[Dict] = Field(None, description="Additional details from Hunter.io")


class URLScanResult(BaseModel):
    """Result from VirusTotal URL scanning"""
    urls_found: List[str] = Field(default_factory=list, description="URLs extracted from email")
    malicious_count: int = Field(0, description="Number of malicious URLs detected")
    suspicious_count: int = Field(0, description="Number of suspicious URLs detected")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    details: Optional[List[Dict]] = Field(None, description="Detailed scan results per URL")


class ContentAnalysisResult(BaseModel):
    """Result from ML content analysis"""
    prediction: str = Field(description="Classification: 'Phishing Email' or 'Safe Email'")
    confidence: float = Field(ge=0.0, le=1.0, description="Model confidence (0-1)")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    is_phishing: bool = Field(description="True if classified as phishing")


class CompleteScanResponse(BaseModel):
    """Complete scan response with all results"""
    scam_score: float = Field(ge=0.0, le=100.0, description="Overall scam score (0-100)")
    risk_level: str = Field(description="Risk categorization: LOW, MEDIUM, HIGH, CRITICAL")
    labels: List[str] = Field(default_factory=list, description="UI badges/labels for detected risks")
    recommendations: List[str] = Field(default_factory=list, description="Actionable advice for the user")
    email_verification: Optional[EmailVerificationResult] = None
    url_scan: Optional[URLScanResult] = None
    content_analysis: Optional[ContentAnalysisResult] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "scam_score": 78.5,
                "risk_level": "HIGH",
                "labels": ["Malicious Link", "Suspicious Sender", "Phishing Content"],
                "recommendations": [
                    "Do not click any links in this email",
                    "Avoid providing personal information",
                    "Mark this email as spam"
                ],
                "email_verification": {
                    "valid": False,
                    "score": 20,
                    "disposable": True,
                    "risk_score": 80
                },
                "url_scan": {
                    "urls_found": ["http://phishing-site.com"],
                    "malicious_count": 1,
                    "risk_score": 95
                },
                "content_analysis": {
                    "prediction": "Phishing Email",
                    "confidence": 0.92,
                    "risk_score": 92,
                    "is_phishing": True
                }
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(description="Service status")
    ml_model_loaded: bool = Field(description="Whether ML model is available")
