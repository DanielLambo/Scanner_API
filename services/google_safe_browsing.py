"""
Google Safe Browsing v4 URL checking service
Batch-checks URLs against Google's threat database
"""
import hashlib
import json
import logging
from typing import Dict, List, Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CACHE_TTL = 3600


class GoogleSafeBrowsingService:
    """Google Safe Browsing API v4 — batch URL threat checking"""

    def __init__(self):
        self.api_key = settings.google_safe_browsing_key
        self._redis: Optional[object] = None
        self._redis_checked = False

    async def _get_redis(self):
        if not REDIS_AVAILABLE or self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            client = aioredis.from_url("redis://localhost:6379", decode_responses=True)
            await client.ping()
            self._redis = client
        except Exception:
            self._redis = None
        return self._redis

    def _cache_key(self, urls: List[str]) -> str:
        key_data = json.dumps(sorted(urls), separators=(",", ":"))
        return "gsb:" + hashlib.sha256(key_data.encode()).hexdigest()

    async def check_urls(self, urls: List[str]) -> Dict:
        """
        Batch-check up to 500 URLs against Google Safe Browsing.

        Returns dict with keys:
            flagged_urls  — URLs matched by GSB
            clean_urls    — URLs that passed
            risk_score    — 100 if any flagged, 0 otherwise
        """
        if not urls:
            return {"flagged_urls": [], "clean_urls": [], "risk_score": 0}

        if self.api_key == "##":
            return {
                "flagged_urls": [],
                "clean_urls": list(urls),
                "risk_score": 0,
                "note": "Google Safe Browsing API key not configured",
            }

        redis = await self._get_redis()
        cache_key = self._cache_key(urls)

        if redis:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        result = await self._call_api(urls)

        if redis:
            try:
                await redis.setex(cache_key, CACHE_TTL, json.dumps(result))
            except Exception:
                pass

        return result

    async def _call_api(self, urls: List[str]) -> Dict:
        payload = {
            "client": {"clientId": "email-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=settings.external_api_timeout) as client:
                response = await client.post(
                    GSB_API_URL,
                    params={"key": self.api_key},
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPError as exc:
            logger.error("GSB API request failed: %s", exc)
            return {
                "flagged_urls": [],
                "clean_urls": list(urls),
                "risk_score": 0,
                "error": str(exc),
            }

        matches = data.get("matches", [])
        flagged_urls = list({m["threat"]["url"] for m in matches})
        clean_urls = [u for u in urls if u not in flagged_urls]
        risk_score = 100 if flagged_urls else 0

        return {
            "flagged_urls": flagged_urls,
            "clean_urls": clean_urls,
            "risk_score": risk_score,
        }


gsb_service = GoogleSafeBrowsingService()
