"""
URL scanning service using VirusTotal API
Scans URLs for malicious content
"""
import requests
import base64
from typing import List, Dict
from models.schemas import URLScanResult
from utils.url_extractor import extract_urls
from config import settings


class URLScanner:
    """VirusTotal URL scanning service"""
    
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.api_url = settings.virustotal_api_url
        self.timeout = settings.external_api_timeout
    
    def scan_urls(self, email_text: str) -> URLScanResult:
        """
        Extract and scan URLs from email text
        
        Args:
            email_text: Email content to scan for URLs
            
        Returns:
            URLScanResult with scanning details
        """
        # Extract URLs from text
        urls = extract_urls(email_text)
        
        if not urls:
            return URLScanResult(
                urls_found=[],
                malicious_count=0,
                suspicious_count=0,
                risk_score=0.0
            )
        
        if self.api_key == "##":
            # Return default result if API key not configured
            return URLScanResult(
                urls_found=urls,
                malicious_count=0,
                suspicious_count=0,
                risk_score=0.0,
                details=[{"error": "VirusTotal API key not configured"}]
            )
        
        # Scan each URL
        results = []
        malicious_count = 0
        suspicious_count = 0
        
        for url in urls:
            result = self._scan_single_url(url)
            results.append(result)
            
            malicious_count += result.get("malicious", 0)
            suspicious_count += result.get("suspicious", 0)
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(malicious_count, suspicious_count, len(urls))
        
        return URLScanResult(
            urls_found=urls,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            risk_score=risk_score,
            details=results
        )
    
    def _scan_single_url(self, url: str) -> Dict:
        """
        Scan a single URL using VirusTotal
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Encode URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "x-apikey": self.api_key
            }
            
            # Get URL analysis
            response = requests.get(
                f"{self.api_url}/{url_id}",
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                # URL not in database, submit for scanning
                return self._submit_url_for_scan(url)
            
            response.raise_for_status()
            data = response.json()
            
            # Extract stats
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "url": url,
                "error": str(e),
                "malicious": 0,
                "suspicious": 0
            }
    
    def _submit_url_for_scan(self, url: str) -> Dict:
        """
        Submit URL for scanning if not in VirusTotal database
        
        Args:
            url: URL to submit
            
        Returns:
            Dictionary with submission status
        """
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            data = {"url": url}
            
            response = requests.post(
                self.api_url,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            return {
                "url": url,
                "status": "submitted_for_analysis",
                "malicious": 0,
                "suspicious": 0
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "url": url,
                "error": str(e),
                "malicious": 0,
                "suspicious": 0
            }
    
    def _calculate_risk_score(self, malicious: int, suspicious: int, total: int) -> float:
        """
        Calculate risk score from URL scan results
        
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
        
        # High risk for any malicious URLs
        if malicious > 0:
            risk = 100.0
        # Medium risk for suspicious URLs
        elif suspicious > 0:
            risk = 60.0 + (suspicious / total) * 30.0
        
        return min(risk, 100.0)


# Singleton instance
url_scanner = URLScanner()
