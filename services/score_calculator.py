"""
Score calculator - combines results from all scanners
Calculates unified scam score and risk level
"""
from typing import Optional, List
from models.schemas import (
    CompleteScanResponse,
    EmailVerificationResult,
    URLScanResult,
    ContentAnalysisResult,
    HeaderAnalysisResult,
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
        content_result: Optional[ContentAnalysisResult] = None,
        dnsbl_result: Optional[dict] = None,
        header_analysis: Optional[HeaderAnalysisResult] = None,
        evasion_labels: Optional[List[str]] = None,
    ) -> CompleteScanResponse:
        """
        Calculate unified scam score from all results

        Args:
            email_result: Email verification result
            url_result: URL scanning result
            content_result: Content analysis result
            dnsbl_result: DNSBL blocklist result
            header_analysis: Raw header analysis result

        Returns:
            CompleteScanResponse with overall score and risk level
        """
        total_score = 0.0
        total_weight = 0.0

        # Choose weight set depending on whether headers are present
        if header_analysis is not None:
            w_email   = 0.20
            w_url     = 0.30
            w_content = 0.25
            w_headers = 0.25
        else:
            w_email   = self.weight_email    # 0.30
            w_url     = self.weight_url      # 0.40
            w_content = self.weight_content  # 0.30
            w_headers = 0.0

        # Add email verification score
        if email_result is not None:
            total_score += email_result.risk_score * w_email
            total_weight += w_email

        # Add URL scanning score
        if url_result is not None:
            total_score += url_result.risk_score * w_url
            total_weight += w_url

        # Add content analysis score
        if content_result is not None:
            total_score += content_result.risk_score * w_content
            total_weight += w_content

        # Add header analysis score
        if header_analysis is not None:
            total_score += header_analysis.risk_score * w_headers
            total_weight += w_headers

        # Calculate weighted average
        if total_weight > 0:
            scam_score = total_score / total_weight
        else:
            scam_score = 0.0

        # Hard-floor: if any domain is blocklist-flagged, scam_score >= 70
        if dnsbl_result and dnsbl_result.get("risk_score", 0) == 100.0:
            scam_score = max(scam_score, 70.0)

        # Determine risk level
        risk_level = self._get_risk_level(scam_score)

        # Generate labels and recommendations
        labels = self._generate_labels(email_result, url_result, content_result, dnsbl_result, header_analysis)
        recommendations = self._generate_recommendations(
            email_result, url_result, content_result, risk_level, dnsbl_result, header_analysis
        )

        # Merge all evasion labels (from content analysis + URL scanning + caller-supplied)
        merged_evasion: List[str] = list(evasion_labels) if evasion_labels else []
        if url_result and url_result.url_evasion_labels:
            for lbl in url_result.url_evasion_labels:
                if lbl not in merged_evasion:
                    merged_evasion.append(lbl)

        return CompleteScanResponse(
            scam_score=round(scam_score, 2),
            risk_level=risk_level,
            labels=labels,
            recommendations=recommendations,
            email_verification=email_result,
            url_scan=url_result,
            content_analysis=content_result,
            dnsbl_result=dnsbl_result,
            header_analysis=header_analysis,
            evasion_techniques_detected=merged_evasion if merged_evasion else None,
        )

    def _generate_labels(
        self,
        email_result: Optional[EmailVerificationResult],
        url_result: Optional[URLScanResult],
        content_result: Optional[ContentAnalysisResult],
        dnsbl_result: Optional[dict] = None,
        header_analysis: Optional[HeaderAnalysisResult] = None,
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

        if dnsbl_result and dnsbl_result.get("flagged_domains"):
            labels.append("Domain Blocklisted")

        if header_analysis:
            for flag in header_analysis.flags:
                if flag not in labels:
                    labels.append(flag)

        return labels

    def _generate_recommendations(
        self,
        email_result: Optional[EmailVerificationResult],
        url_result: Optional[URLScanResult],
        content_result: Optional[ContentAnalysisResult],
        risk_level: str,
        dnsbl_result: Optional[dict] = None,
        header_analysis: Optional[HeaderAnalysisResult] = None,
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

        if dnsbl_result and dnsbl_result.get("flagged_domains"):
            recs.append("The sender domain appears on spam/phishing blocklists.")

        if header_analysis:
            flags = header_analysis.flags
            if "DMARC_FAIL" in flags:
                recs.append(
                    "This email failed DMARC authentication — the sender domain is likely spoofed"
                )
            if "REPLY_TO_MISMATCH" in flags:
                recs.append(
                    "Reply-To address differs from sender — replies will go to a different domain"
                )
            if "DISPLAY_NAME_SPOOF" in flags:
                brand = header_analysis.spoofed_brand or "a known brand"
                recs.append(
                    f"Display name impersonates {brand} but was not sent from their domain"
                )

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
