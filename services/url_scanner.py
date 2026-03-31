"""
URL scanning service using VirusTotal, Google Safe Browsing, and OpenPhish.
Individual URL results are cached in Redis to avoid redundant scans.
"""
import asyncio
import base64
import hashlib
import json
import logging
import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse

from models.schemas import URLScanResult
from utils.url_extractor import extract_urls
from config import settings
from services.google_safe_browsing import gsb_service
from services.openphish import openphish
from services.canonicalizer import canonicalize_urls
from services.homoglyph import check_domain
from services.url_signals import score_url

logger = logging.getLogger(__name__)

TTL_CLEAN = 14400    # 4 hours for risk_score == 0
TTL_MALICIOUS = 86400  # 24 hours for risk_score > 0

try:
    import redis.asyncio as aioredis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


class URLCache:
    """Per-URL Redis cache with separate TTLs for clean vs malicious results."""

    def __init__(self):
        self._redis: Optional[object] = None
        self._checked = False
        self.hits = 0

    async def _get_redis(self):
        if not _REDIS_AVAILABLE or self._checked:
            return self._redis
        self._checked = True
        try:
            client = aioredis.from_url("redis://localhost:6379", decode_responses=True)
            await client.ping()
            self._redis = client
        except Exception:
            self._redis = None
        return self._redis

    @staticmethod
    def _key(url: str) -> str:
        canonical = url.lower().rstrip("/")
        return "url:" + hashlib.sha256(canonical.encode()).hexdigest()

    async def get(self, url: str) -> Optional[Dict]:
        redis = await self._get_redis()
        if not redis:
            return None
        try:
            raw = await redis.get(self._key(url))
            if raw:
                self.hits += 1
                logger.debug("URL cache hit: %s", url)
                return json.loads(raw)
        except Exception as exc:
            logger.warning("URL cache read error: %s", exc)
        return None

    async def set(self, url: str, result: Dict) -> None:
        redis = await self._get_redis()
        if not redis:
            return
        ttl = TTL_CLEAN if result.get("risk_score", 0) == 0 else TTL_MALICIOUS
        try:
            await redis.setex(self._key(url), ttl, json.dumps(result))
        except Exception as exc:
            logger.warning("URL cache write error: %s", exc)

    @property
    def available(self) -> bool:
        return self._redis is not None


# Module-level cache instance (shared across requests)
_url_cache = URLCache()


class URLScanner:
    """URL scanning service combining VirusTotal, Google Safe Browsing, and OpenPhish"""

    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.api_url = settings.virustotal_api_url
        self.timeout = settings.external_api_timeout

    async def scan_urls(self, email_text: str) -> URLScanResult:
        """
        Extract and scan URLs from email text.
        - Canonicalizes all URLs first (follows redirects, decodes punycode)
        - Checks each canonical domain for homoglyphs
        - Runs url_signals scoring on each canonical URL
        - Checks each canonical URL against the Redis cache;
          only cache misses are forwarded to VT / GSB / OpenPhish.
        """
        urls = extract_urls(email_text)

        if not urls:
            return URLScanResult(
                urls_found=[],
                malicious_count=0,
                suspicious_count=0,
                risk_score=0.0,
            )

        # Step 1: Canonicalize all URLs — returns dict of original -> result dict
        canonical_map = await canonicalize_urls(urls)  # original -> {canonical_url, was_shortened, redirect_chain}

        # Step 2: Homoglyph detection on canonical domains
        homoglyph_malicious: set = set()
        homoglyph_details: Dict[str, dict] = {}
        for original_url, canon_result in canonical_map.items():
            canonical_url = canon_result["canonical_url"]
            try:
                hostname = urlparse(canonical_url).hostname or ""
                if hostname:
                    hg_result = check_domain(hostname)
                    homoglyph_details[original_url] = hg_result
                    if hg_result["is_homoglyph"]:
                        homoglyph_malicious.add(original_url)
            except Exception as exc:
                logger.debug("Homoglyph check error for %s: %s", canonical_url, exc)

        # Use canonical URLs for downstream checks
        canonical_urls_list = [v["canonical_url"] for v in canonical_map.values()]

        # Step 3: Run url_signals scoring concurrently with cache lookups
        signals_map: Dict[str, dict] = {}
        for canon_url in canonical_urls_list:
            signals_map[canon_url] = score_url(canon_url)

        # Split canonical URLs into cache hits and misses
        cached_results: Dict[str, Dict] = {}
        urls_to_scan: List[str] = []

        for url in canonical_urls_list:
            hit = await _url_cache.get(url)
            if hit is not None:
                cached_results[url] = hit
            else:
                urls_to_scan.append(url)

        if urls_to_scan:
            logger.info(
                "URL scan: %d cached, %d to scan (cache hits total: %d)",
                len(cached_results), len(urls_to_scan), _url_cache.hits,
            )
            fresh = await self._scan_fresh(urls_to_scan)
            # Write each URL result to cache
            for url, result in fresh.items():
                await _url_cache.set(url, result)
            cached_results.update(fresh)
        else:
            logger.info("URL scan: all %d URLs served from cache (hits total: %d)",
                        len(urls), _url_cache.hits)

        # Aggregate across all URLs
        all_malicious: set = set()
        all_suspicious_count = 0
        max_risk = 0.0
        all_details = []
        all_gsb_flagged: set = set()
        all_url_signals: list = []

        for original_url in urls:
            canon_result = canonical_map.get(original_url, {})
            canonical_url = canon_result.get("canonical_url", original_url) if isinstance(canon_result, dict) else original_url
            r = cached_results.get(canonical_url, {})

            # url_signals result for this canonical URL
            sig = signals_map.get(canonical_url, {})
            sig_risk = sig.get("risk_score", 0.0)

            # If domain is a homoglyph, force malicious
            if original_url in homoglyph_malicious:
                r = dict(r)
                r["malicious"] = True
                r["risk_score"] = 100.0

            if r.get("malicious"):
                all_malicious.add(original_url)
            all_suspicious_count += r.get("suspicious_count", 0)

            # url_signals contributions
            if sig_risk > 90:
                all_malicious.add(original_url)
            elif sig_risk > 70:
                all_suspicious_count += 1

            max_risk = max(max_risk, r.get("risk_score", 0.0), sig_risk)

            # Build per-URL detail entry
            detail_entry: dict = {}
            if r.get("vt_detail"):
                detail_entry.update(r["vt_detail"])

            detail_entry["original_url"] = original_url
            detail_entry["canonical_url"] = canonical_url
            detail_entry["url_signals"] = sig

            # Flag redirects
            detail_notes = list(detail_entry.get("notes", []))
            if canonical_url != original_url:
                detail_notes.append("Redirect Detected")
            if original_url in homoglyph_malicious:
                detail_notes.append("Homoglyph Domain Detected")
                detail_entry["homoglyph_result"] = homoglyph_details.get(original_url)
            if canon_result.get("was_shortened"):
                detail_notes.append("URL Shortener Detected")
            if detail_notes:
                detail_entry["notes"] = detail_notes

            all_details.append(detail_entry)
            all_url_signals.append(sig)

            if r.get("gsb_flagged"):
                all_gsb_flagged.add(original_url)

        return URLScanResult(
            urls_found=urls,
            malicious_count=len(all_malicious),
            suspicious_count=all_suspicious_count,
            risk_score=max_risk,
            details=all_details if all_details else None,
            gsb_flagged_count=len(all_gsb_flagged),
            gsb_details=list(all_gsb_flagged) if all_gsb_flagged else None,
            canonical_urls=canonical_map,
            url_signals=all_url_signals if all_url_signals else None,
        )

    async def _scan_fresh(self, urls: List[str]) -> Dict[str, Dict]:
        """
        Run VT + GSB + OpenPhish for a list of uncached URLs.
        Returns a per-URL result dict ready for caching.
        """
        vt_data, gsb_data, op_data = await asyncio.gather(
            asyncio.to_thread(self._scan_urls_vt, urls),
            gsb_service.check_urls(urls),
            asyncio.to_thread(openphish.check_urls, urls),
        )

        gsb_flagged_set = set(gsb_data.get("flagged_urls", []))
        op_flagged_set = set(op_data.get("flagged_urls", []))

        # Build a per-URL result
        vt_by_url = {d["url"]: d for d in vt_data.get("details", []) if "url" in d}

        results: Dict[str, Dict] = {}
        for url in urls:
            vt = vt_by_url.get(url, {})
            vt_malicious = vt.get("malicious", 0) > 0
            gsb_hit = url in gsb_flagged_set
            op_hit = url in op_flagged_set
            is_malicious = vt_malicious or gsb_hit or op_hit

            risk_score = 100.0 if is_malicious else 0.0

            results[url] = {
                "url": url,
                "malicious": is_malicious,
                "suspicious_count": vt.get("suspicious", 0),
                "risk_score": risk_score,
                "gsb_flagged": gsb_hit,
                "op_flagged": op_hit,
                "vt_detail": vt if vt else None,
            }

        return results

    def _scan_urls_vt(self, urls: List[str]) -> Dict:
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
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.post(
                self.api_url,
                headers=headers,
                data={"url": url},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return {"url": url, "status": "submitted_for_analysis", "malicious": 0, "suspicious": 0}
        except requests.exceptions.RequestException as e:
            return {"url": url, "error": str(e), "malicious": 0, "suspicious": 0}

    def _calculate_risk_score(self, malicious: int, suspicious: int, total: int) -> float:
        if total == 0:
            return 0.0
        if malicious > 0:
            return 100.0
        if suspicious > 0:
            return min(60.0 + (suspicious / total) * 30.0, 100.0)
        return 0.0


# Singleton instance
url_scanner = URLScanner()
