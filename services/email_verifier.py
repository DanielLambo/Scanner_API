"""
Email verification service using Hunter.io API
Validates email addresses and calculates risk scores
"""
import requests
from typing import Dict, Optional
from models.schemas import EmailVerificationResult
from config import settings


class EmailVerifier:
    """Hunter.io email verification service"""
    
    def __init__(self):
        self.api_key = settings.hunter_api_key
        self.api_url = settings.hunter_api_url
        self.timeout = settings.external_api_timeout
    
    def verify_email(self, email_address: str) -> EmailVerificationResult:
        """
        Verify email address using Hunter.io API
        
        Args:
            email_address: Email address to verify
            
        Returns:
            EmailVerificationResult with verification details
        """
        if self.api_key == "##":
            # Return default result if API key not configured
            return EmailVerificationResult(
                valid=True,
                score=50.0,
                risk_score=50.0,
                details={"error": "Hunter.io API key not configured"}
            )
        
        try:
            params = {
                "email": email_address,
                "api_key": self.api_key
            }
            
            response = requests.get(
                self.api_url,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            
            # Extract verification details
            result = EmailVerificationResult(
                valid=data.get("result") == "deliverable",
                score=data.get("score", 0),
                disposable=data.get("disposable", False),
                webmail=data.get("webmail", False),
                accept_all=data.get("accept_all", False),
                gibberish=data.get("gibberish", False),
                risk_score=self._calculate_risk_score(data),
                details=data
            )
            
            return result
            
        except requests.exceptions.RequestException as e:
            # Return error result
            return EmailVerificationResult(
                valid=False,
                score=0,
                risk_score=100.0,
                details={"error": str(e)}
            )
    
    def _calculate_risk_score(self, data: Dict) -> float:
        """
        Calculate risk score from Hunter.io data
        Higher score = higher risk
        
        Args:
            data: Hunter.io API response data
            
        Returns:
            Risk score (0-100)
        """
        risk = 0.0
        
        # Base score on Hunter.io quality score (inverse)
        hunter_score = data.get("score", 50)
        risk += (100 - hunter_score) * 0.4
        
        # Add risk for various flags
        if data.get("disposable", False):
            risk += 30
        if data.get("gibberish", False):
            risk += 20
        if data.get("accept_all", False):
            risk += 15
        if data.get("result") != "deliverable":
            risk += 25
        
        return min(risk, 100.0)


# Singleton instance
email_verifier = EmailVerifier()
