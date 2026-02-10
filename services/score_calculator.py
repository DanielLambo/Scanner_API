"""
Score calculator - combines results from all scanners
Calculates unified scam score and risk level
"""
from typing import Optional
from models.schemas import (
    CompleteScanResponse,
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult
)
from config import settings


class ScoreCalculator:
    """Unified scoring system for all scan results"""
    
    def __init__(self):
        self.weight_email = settings.scoring_weights_email
        self.weight_url = settings.scoring_weights_url
        self.weight_content = settings.scoring_weights_content
    
    def calculate_score(
        self,
        email_result: Optional[EmailVerificationResult] = None,
        url_result: Optional[URLScanResult] = None,
        content_result: Optional[ContentAnalysisResult] = None
    ) -> CompleteScanResponse:
        """
        Calculate unified scam score from all results
        
        Args:
            email_result: Email verification result
            url_result: URL scanning result
            content_result: Content analysis result
            
        Returns:
            CompleteScanResponse with overall score and risk level
        """
        total_score = 0.0
        total_weight = 0.0
        
        # Add email verification score
        if email_result is not None:
            total_score += email_result.risk_score * self.weight_email
            total_weight += self.weight_email
        
        # Add URL scanning score
        if url_result is not None:
            total_score += url_result.risk_score * self.weight_url
            total_weight += self.weight_url
        
        # Add content analysis score
        if content_result is not None:
            total_score += content_result.risk_score * self.weight_content
            total_weight += self.weight_content
        
        # Calculate weighted average
        if total_weight > 0:
            scam_score = total_score / total_weight
        else:
            scam_score = 0.0
        
        # Determine risk level
        risk_level = self._get_risk_level(scam_score)
        
        # Generate labels and recommendations
        labels = self._generate_labels(email_result, url_result, content_result)
        recommendations = self._generate_recommendations(email_result, url_result, content_result, risk_level)

        return CompleteScanResponse(
            scam_score=round(scam_score, 2),
            risk_level=risk_level,
            labels=labels,
            recommendations=recommendations,
            email_verification=email_result,
            url_scan=url_result,
            content_analysis=content_result
        )

    def _generate_labels(
        self,
        email_result: Optional[EmailVerificationResult],
        url_result: Optional[URLScanResult],
        content_result: Optional[ContentAnalysisResult]
    ) -> list[str]:
        """Generate UI labels based on scan results"""
        labels = []

        if email_result:
            if not email_result.valid:
                labels.append("Invalid Sender")
            if email_result.disposable:
                labels.append("Disposable Email")
            if email_result.risk_score > 70:
                labels.append("High Risk Sender")

        if url_result:
            if url_result.malicious_count > 0:
                labels.append("Malicious Link Found")
            elif url_result.suspicious_count > 0:
                labels.append("Suspicious Link Found")

        if content_result:
            if content_result.is_phishing:
                labels.append("Phishing Content")
            elif content_result.risk_score > 60:
                labels.append("Suspicious Content")

        return labels

    def _generate_recommendations(
        self,
        email_result: Optional[EmailVerificationResult],
        url_result: Optional[URLScanResult],
        content_result: Optional[ContentAnalysisResult],
        risk_level: str
    ) -> list[str]:
        """Generate actionable advice for the user"""
        recs = []

        if risk_level in ["HIGH", "CRITICAL"]:
            recs.append("Do not click any links or download attachments from this email.")
            recs.append("Mark this email as spam or report it to your IT department.")

        if email_result and (not email_result.valid or email_result.disposable):
            recs.append("The sender's email address looks suspicious or temporary.")

        if url_result and url_result.malicious_count > 0:
            recs.append(f"We found {url_result.malicious_count} malicious link(s). Avoid interacting with them.")

        if content_result and content_result.is_phishing:
            recs.append("The message uses language typical of phishing scams (e.g., creating a sense of urgency).")

        if not recs:
            recs.append("This email appears to be safe, but always remain cautious with unexpected messages.")

        return recs
    
    def _get_risk_level(self, score: float) -> str:
        """
        Categorize score into risk level
        
        Args:
            score: Scam score (0-100)
            
        Returns:
            Risk level: LOW, MEDIUM, HIGH, CRITICAL
        """
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"


# Singleton instance
score_calculator = ScoreCalculator()
