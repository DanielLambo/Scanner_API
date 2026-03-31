"""
Email verification service using Hunter.io API
Validates email addresses and calculates risk scores
"""
import asyncio
import requests
from typing import Dict, Optional
from models.schemas import EmailVerificationResult
from services.domain_age import check_domain_age
from services.homoglyph import check_domain
from config import settings


class EmailVerifier:
    """Hunter.io email verification service"""
    
    def __init__(self):
        self.api_key = settings.hunter_api_key
        self.api_url = settings.hunter_api_url
        self.timeout = settings.external_api_timeout
    
    async def verify_email(self, email_address: str) -> EmailVerificationResult:
        """
        Verify email address using Hunter.io API, check domain age, and
        run homoglyph detection on the sender domain.

        Args:
            email_address: Email address to verify

        Returns:
            EmailVerificationResult with verification details and domain age risk
        """
        domain_age = await check_domain_age(email_address=email_address)

        # Homoglyph detection on sender domain
        sender_domain = email_address.split("@")[-1] if "@" in email_address else email_address
        homoglyph_result = check_domain(sender_domain)
        is_homoglyph = homoglyph_result.get("is_homoglyph", False)

        if self.api_key == "##":
            base_risk = max(50.0, domain_age["risk_score"])
            if is_homoglyph:
                base_risk = min(base_risk + 95.0, 100.0)
            return EmailVerificationResult(
                valid=True,
                score=50.0,
                risk_score=base_risk,
                domain_age_days=domain_age.get("youngest_age_days"),
                domain_age_risk=domain_age["risk_score"],
                homoglyph_detected=is_homoglyph,
                details={
                    "error": "Hunter.io API key not configured",
                    "homoglyph_result": homoglyph_result,
                },
            )

        try:
            params = {"email": email_address, "api_key": self.api_key}
            response = await asyncio.to_thread(
                requests.get, self.api_url, params=params, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            base_risk = self._calculate_risk_score(data)
            final_risk = max(base_risk, domain_age["risk_score"])
            if is_homoglyph:
                final_risk = min(final_risk + 95.0, 100.0)

            details = dict(data)
            details["homoglyph_result"] = homoglyph_result

            return EmailVerificationResult(
                valid=data.get("result") == "deliverable",
                score=data.get("score", 0),
                disposable=data.get("disposable", False),
                webmail=data.get("webmail", False),
                accept_all=data.get("accept_all", False),
                gibberish=data.get("gibberish", False),
                risk_score=final_risk,
                domain_age_days=domain_age.get("youngest_age_days"),
                domain_age_risk=domain_age["risk_score"],
                homoglyph_detected=is_homoglyph,
                details=details,
            )

        except requests.exceptions.RequestException as e:
            base_risk = 100.0
            if is_homoglyph:
                base_risk = min(base_risk + 95.0, 100.0)
            return EmailVerificationResult(
                valid=False,
                score=0,
                risk_score=base_risk,
                domain_age_days=domain_age.get("youngest_age_days"),
                domain_age_risk=domain_age["risk_score"],
                homoglyph_detected=is_homoglyph,
                details={"error": str(e), "homoglyph_result": homoglyph_result},
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
