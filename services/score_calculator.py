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

    # Base weights (redistributed proportionally when a service is absent)
    W_EMAIL = 0.25
    W_URL = 0.45
    W_CONTENT = 0.30
    W_HEADERS = 0.25

    def _confidence_gated_weight(self, content_result: ContentAnalysisResult, base: float) -> float:
        """Scale content weight by ML confidence to dampen noisy predictions."""
        conf = content_result.confidence
        if conf > 0.90:
            return base          # full weight — model is very confident
        if conf > 0.75:
            return base * 0.40   # reduced — moderate confidence
        return base * 0.20       # minimal — model is guessing

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
        Calculate unified scam score from all results.

        Only services that actually returned a result contribute to the
        weighted average; absent services are excluded and remaining weights
        are redistributed proportionally.
        """
        # Build (weight, score) pairs for each present service
        components: list[tuple[float, float]] = []

        if email_result is not None:
            components.append((self.W_EMAIL, email_result.risk_score))

        if url_result is not None and url_result.urls_found:
            components.append((self.W_URL, url_result.risk_score))

        if content_result is not None:
            w = self._confidence_gated_weight(content_result, self.W_CONTENT)
            components.append((w, content_result.risk_score))

        if header_analysis is not None:
            components.append((self.W_HEADERS, header_analysis.risk_score))

        # Weighted average — proportional redistribution is automatic
        raw_weight = sum(w for w, _ in components)
        if raw_weight > 0:
            scam_score = sum(w * s for w, s in components) / raw_weight
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
            if email_result.homoglyph_detected:
                labels.append("Homoglyph Domain")
            if email_result.domain_age_risk > 70:
                labels.append("New Domain")
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

        if email_result and email_result.homoglyph_detected:
            recs.append("The sender domain looks like a spoofed version of a well-known brand.")

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
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"


# Singleton instance
score_calculator = ScoreCalculator()
