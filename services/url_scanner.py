"""
URL scanning service using VirusTotal and Google Safe Browsing APIs
Scans URLs for malicious content using both services in parallel
"""
import asyncio
import base64
import requests
from typing import List, Dict

from models.schemas import URLScanResult
from utils.url_extractor import extract_urls
from config import settings
from services.google_safe_browsing import gsb_service
from services.openphish import openphish


class URLScanner:
    """URL scanning service combining VirusTotal and Google Safe Browsing"""

    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.api_url = settings.virustotal_api_url
        self.timeout = settings.external_api_timeout

    async def scan_urls(self, email_text: str) -> URLScanResult:
        """
        Extract and scan URLs from email text using VirusTotal and GSB in parallel.

        Args:
            email_text: Email content to scan for URLs

        Returns:
            URLScanResult with combined scanning details
        """
        urls = extract_urls(email_text)

        if not urls:
            return URLScanResult(
                urls_found=[],
                malicious_count=0,
                suspicious_count=0,
                risk_score=0.0,
            )

        # Run VirusTotal (sync, offloaded to thread), GSB, and OpenPhish in parallel
        vt_data, gsb_data, op_data = await asyncio.gather(
            asyncio.to_thread(self._scan_urls_vt, urls),
            gsb_service.check_urls(urls),
            asyncio.to_thread(openphish.check_urls, urls),
        )

        # Combine malicious URLs from all three services (deduplicated)
        vt_malicious_urls = {
            d["url"] for d in vt_data["details"] if d.get("malicious", 0) > 0
        }
        gsb_flagged = gsb_data.get("flagged_urls", [])
        op_flagged = op_data.get("flagged_urls", [])
        combined_malicious = vt_malicious_urls | set(gsb_flagged) | set(op_flagged)

        malicious_count = len(combined_malicious)
        risk_score = max(vt_data["risk_score"], gsb_data.get("risk_score", 0), op_data.get("risk_score", 0))

        return URLScanResult(
            urls_found=urls,
            malicious_count=malicious_count,
            suspicious_count=vt_data["suspicious_count"],
            risk_score=risk_score,
            details=vt_data["details"],
            gsb_flagged_count=len(gsb_flagged),
            gsb_details=gsb_flagged if gsb_flagged else None,
        )

    def _scan_urls_vt(self, urls: List[str]) -> Dict:
        """
        Synchronous VirusTotal scan for a list of URLs.
        Runs in a thread pool via asyncio.to_thread.

        Returns:
            Dict with malicious_count, suspicious_count, risk_score, details
        """
        if self.api_key == "##":
            return {
                "malicious_count": 0,
                "suspicious_count": 0,
                "risk_score": 0.0,
                "details": [{"error": "VirusTotal API key not configured"}],
            }

        details = []
        malicious_count = 0
        suspicious_count = 0

        for url in urls:
            result = self._scan_single_url(url)
            details.append(result)
            malicious_count += result.get("malicious", 0)
            suspicious_count += result.get("suspicious", 0)

        risk_score = self._calculate_risk_score(malicious_count, suspicious_count, len(urls))

        return {
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "risk_score": risk_score,
            "details": details,
        }

    def _scan_single_url(self, url: str) -> Dict:
        """
        Scan a single URL using VirusTotal

        Args:
            url: URL to scan

        Returns:
            Dictionary with scan results
        """
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            headers = {"x-apikey": self.api_key}

            response = requests.get(
                f"{self.api_url}/{url_id}",
                headers=headers,
                timeout=self.timeout,
            )

            if response.status_code == 404:
                return self._submit_url_for_scan(url)

            response.raise_for_status()
            data = response.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }

        except requests.exceptions.RequestException as e:
            return {"url": url, "error": str(e), "malicious": 0, "suspicious": 0}

    def _submit_url_for_scan(self, url: str) -> Dict:
        """
        Submit URL for scanning if not in VirusTotal database

        Args:
            url: URL to submit

        Returns:
            Dictionary with submission status
        """
        try:
            headers = {"x-apikey": self.api_key}
            data = {"url": url}

            response = requests.post(
                self.api_url,
                headers=headers,
                data=data,
                timeout=self.timeout,
            )
            response.raise_for_status()

            return {
                "url": url,
                "status": "submitted_for_analysis",
                "malicious": 0,
                "suspicious": 0,
            }

        except requests.exceptions.RequestException as e:
            return {"url": url, "error": str(e), "malicious": 0, "suspicious": 0}

    def _calculate_risk_score(self, malicious: int, suspicious: int, total: int) -> float:
        """
        Calculate risk score from VirusTotal scan results

        Args:
            malicious: Number of malicious URLs
            suspicious: Number of suspicious URLs
            total: Total number of URLs

        Returns:
            Risk score (0-100)
        """
        if total == 0:
            return 0.0

        risk = 0.0

        if malicious > 0:
            risk = 100.0
        elif suspicious > 0:
            risk = 60.0 + (suspicious / total) * 30.0

        return min(risk, 100.0)


# Singleton instance
url_scanner = URLScanner()
