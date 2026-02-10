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
        
        return CompleteScanResponse(
            scam_score=round(scam_score, 2),
            risk_level=risk_level,
            email_verification=email_result,
            url_scan=url_result,
            content_analysis=content_result
        )
    
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
