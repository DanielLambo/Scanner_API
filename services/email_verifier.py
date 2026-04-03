"""
Email verification service using domain age and homoglyph detection.
"""
from models.schemas import EmailVerificationResult
from services.domain_age import check_domain_age
from services.homoglyph import check_domain


class EmailVerifier:
    """Email verification via domain age + homoglyph detection."""

    async def verify_email(self, email_address: str) -> EmailVerificationResult:
        """
        Check the sender domain for age-based risk and homoglyph spoofing.

        Returns:
            EmailVerificationResult with domain age and homoglyph signals.
        """
        domain_age = await check_domain_age(email_address=email_address)

        sender_domain = email_address.split("@")[-1] if "@" in email_address else email_address
        homoglyph_result = check_domain(sender_domain)
        is_homoglyph = homoglyph_result.get("is_homoglyph", False)

        risk = domain_age["risk_score"]
        if is_homoglyph:
            risk = min(risk + 95.0, 100.0)

        return EmailVerificationResult(
            risk_score=risk,
            domain_age_days=domain_age.get("youngest_age_days"),
            domain_age_risk=domain_age["risk_score"],
            homoglyph_detected=is_homoglyph,
            details={"homoglyph_result": homoglyph_result},
        )


# Singleton instance
email_verifier = EmailVerifier()
