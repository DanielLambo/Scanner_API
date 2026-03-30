"""
OpenPhish feed service
Downloads and caches the OpenPhish community phishing URL feed,
refreshes every 6 hours in the background.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
REFRESH_INTERVAL = 6 * 3600  # 6 hours in seconds


class DumpManager:
    """Manages the OpenPhish URL dump — download on startup, refresh every 6h."""

    def __init__(self):
        self._urls: set = set()
        self._last_updated: Optional[datetime] = None
        self._refresh_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """Fetch the feed immediately and start the background refresh loop."""
        await self._fetch_feed()
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def _fetch_feed(self) -> None:
        """Download feed.txt and load URLs into the in-memory set."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(FEED_URL)
                response.raise_for_status()
            new_urls = {line.strip() for line in response.text.split("\n") if line.strip()}
            self._urls = new_urls
            self._last_updated = datetime.now(timezone.utc)
            logger.info("OpenPhish feed loaded: %d URLs", len(self._urls))
        except Exception as exc:
            logger.warning("OpenPhish feed fetch failed (keeping existing set): %s", exc)

    async def _refresh_loop(self) -> None:
        """Runs forever, refreshing the feed every REFRESH_INTERVAL seconds."""
        while True:
            await asyncio.sleep(REFRESH_INTERVAL)
            await self._fetch_feed()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_urls(self, urls: List[str]) -> Dict:
        """
        Check a list of URLs against the cached OpenPhish feed.

        Returns:
            dict with flagged_urls, clean_urls, risk_score, source
        """
        flagged = [u for u in urls if u in self._urls]
        clean = [u for u in urls if u not in self._urls]
        return {
            "flagged_urls": flagged,
            "clean_urls": clean,
            "risk_score": 100 if flagged else 0,
            "source": "openphish",
        }

    @property
    def url_count(self) -> int:
        return len(self._urls)

    @property
    def last_updated(self) -> Optional[str]:
        if self._last_updated is None:
            return None
        return self._last_updated.isoformat()

    @property
    def status(self) -> str:
        return "ready" if self._urls else "empty"


# Singleton instance
openphish = DumpManager()
