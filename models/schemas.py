"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict


class EmailScanRequest(BaseModel):
    """Request schema for email scanning"""
    email_address: Optional[EmailStr] = Field(None, description="Email address to verify")
    email_text: Optional[str] = Field(None, description="Email content to analyze")
    email_headers: Optional[str] = Field(None, description="Raw email headers to analyze")

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
    domain_age_days: Optional[int] = None
    domain_age_risk: float = 0.0
    homoglyph_detected: bool = False
    details: Optional[Dict] = Field(None, description="Additional details from Hunter.io")


class URLScanResult(BaseModel):
    """Result from VirusTotal + Google Safe Browsing URL scanning"""
    urls_found: List[str] = Field(default_factory=list, description="URLs extracted from email")
    malicious_count: int = Field(0, description="Number of malicious URLs detected")
    suspicious_count: int = Field(0, description="Number of suspicious URLs detected")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    details: Optional[List[Dict]] = Field(None, description="Detailed scan results per URL")
    gsb_flagged_count: int = Field(0, description="Number of URLs flagged by Google Safe Browsing")
    gsb_details: Optional[List[str]] = Field(None, description="URLs flagged by Google Safe Browsing")
    canonical_urls: Optional[Dict] = Field(None, description="Mapping of original_url to canonicalization result dict")
    url_signals: Optional[List[dict]] = Field(None, description="URL signal scoring results per canonical URL")
    url_evasion_labels: Optional[List[str]] = Field(None, description="Evasion technique labels from URL extraction")


class ContentAnalysisResult(BaseModel):
    """Result from ML content analysis"""
    prediction: str = Field(description="Classification: 'Phishing Email' or 'Safe Email'")
    confidence: float = Field(ge=0.0, le=1.0, description="Model confidence (0-1)")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    is_phishing: bool = Field(description="True if classified as phishing")
    ensemble_disagreement: float = Field(0.0, description="Max spread in phishing probability across models")
    models_agree: bool = Field(True, description="True if all models agree (disagreement < 0.3)")
    explanation: Optional[List[dict]] = Field(None, description="Top SHAP features driving the prediction")
    single_model_mode: bool = Field(False, description="True if running LR only (low memory mode)")


class HeaderAnalysisResult(BaseModel):
    """Result from raw email header analysis"""
    spf: str = Field("missing", description="SPF result: pass/fail/softfail/neutral/none/missing")
    dkim: str = Field("missing", description="DKIM result: pass/fail/none/missing")
    dmarc: str = Field("missing", description="DMARC result: pass/fail/none/missing")
    dmarc_policy: str = Field("missing", description="DMARC policy: reject/quarantine/none/missing")
    reply_to_mismatch: bool = Field(False, description="Reply-To domain differs from From domain")
    reply_to_domain: Optional[str] = None
    from_domain: Optional[str] = None
    display_name_spoof: bool = Field(False, description="Display name impersonates a known brand")
    spoofed_brand: Optional[str] = None
    hop_count: int = Field(0, description="Number of Received headers (hops)")
    relay_mismatch: bool = Field(False, description="From domain absent from origin Received header")
    internal_relay: bool = Field(False, description="Private/internal IP found in Received chain")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated header risk score")
    flags: List[str] = Field(default_factory=list, description="Triggered risk flags")


class CompleteScanResponse(BaseModel):
    """Complete scan response with all results"""
    scan_id: Optional[str] = None
    scam_score: float = Field(ge=0.0, le=100.0, description="Overall scam score (0-100)")
    risk_level: str = Field(description="Risk categorization: LOW, MEDIUM, HIGH, CRITICAL")
    labels: List[str] = Field(default_factory=list, description="UI badges/labels for detected risks")
    recommendations: List[str] = Field(default_factory=list, description="Actionable advice for the user")
    email_verification: Optional[EmailVerificationResult] = None
    url_scan: Optional[URLScanResult] = None
    content_analysis: Optional[ContentAnalysisResult] = None
    dnsbl_result: Optional[dict] = None
    header_analysis: Optional[HeaderAnalysisResult] = None
    evasion_techniques_detected: Optional[List[str]] = Field(None, description="Evasion technique labels detected across all scan stages")
    
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


class FeedbackRequest(BaseModel):
    """Request schema for submitting scan feedback"""
    scan_id: str
    verdict: str = Field(description="One of: TP, FP, FN, TN")
    notes: Optional[str] = None
