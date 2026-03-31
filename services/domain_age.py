"""
Domain age checking service using WHOIS lookups.
Younger domains are a strong phishing signal.
Results are cached in Redis (TTL=86400s) to avoid redundant lookups.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import whois

logger = logging.getLogger(__name__)

# Domains we trust implicitly — skip WHOIS to save time
SAFE_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "apple.com", "google.com", "microsoft.com",
}

# Age → risk score thresholds (days)
def _age_to_risk(age_days: int) -> float:
    if age_days < 7:
        return 95.0
    if age_days < 30:
        return 75.0
    if age_days < 90:
        return 40.0
    return 0.0


def _extract_domain(value: str) -> Optional[str]:
    """Pull the registrable domain from an email address or URL."""
    value = value.strip()
    if not value:
        return None
    # Treat as URL if it has a scheme, otherwise treat as email
    if "://" in value:
        host = urlparse(value).hostname or ""
    elif "@" in value:
        host = value.split("@")[-1]
    else:
        host = value
    host = host.lower().strip()
    return host if host else None


def _whois_lookup(domain: str) -> dict:
    """Blocking WHOIS lookup — call via asyncio.to_thread."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if creation is None:
            return {"domain": domain, "age_days": None, "risk_score": 25.0, "error": "no creation date"}
        # creation_date can be a list; take the earliest
        if isinstance(creation, list):
            creation = min(creation)
        if not isinstance(creation, datetime):
            creation = datetime(creation.year, creation.month, creation.day, tzinfo=timezone.utc)
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        return {"domain": domain, "age_days": age_days, "risk_score": _age_to_risk(age_days)}
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {"domain": domain, "age_days": None, "risk_score": 25.0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Optional Redis cache
# ---------------------------------------------------------------------------
try:
    import redis.asyncio as aioredis
    _redis_client = aioredis.from_url("redis://localhost:6379", decode_responses=True)
    _redis_available = True
except Exception:
    _redis_client = None
    _redis_available = False

CACHE_TTL = 86400  # 1 day


_TIMEOUT = 5.0  # seconds per WHOIS lookup

async def _timed_lookup(domain: str) -> dict:
    """Run _whois_lookup with a hard async timeout."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(_whois_lookup, domain), timeout=_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for %s", domain)
        return {"domain": domain, "age_days": None, "risk_score": 25.0, "error": "timeout"}


async def _cached_lookup(domain: str) -> dict:
    """Return cached result or run a fresh WHOIS lookup."""
    if _redis_available and _redis_client:
        try:
            import json
            key = f"whois:{domain}"
            cached = await _redis_client.get(key)
            if cached:
                return json.loads(cached)
            result = await _timed_lookup(domain)
            await _redis_client.setex(key, CACHE_TTL, json.dumps(result))
            return result
        except Exception as exc:
            logger.warning("Redis cache error for %s: %s", domain, exc)
    # Fallback: no cache
    return await _timed_lookup(domain)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_domain_age(
    email_address: str = None,
    urls: list = None,
) -> dict:
    """
    Check WHOIS age for domains extracted from an email address and/or URLs.

    Returns:
        {
            "domains_checked": [...],
            "youngest_domain": "...",
            "youngest_age_days": int | None,
            "risk_score": float,
            "details": [{"domain": ..., "age_days": ..., "risk_score": ...}, ...]
        }
    """
    raw_sources = []
    if email_address:
        raw_sources.append(email_address)
    if urls:
        raw_sources.extend(urls)

    # Deduplicate domains, skip safe ones
    domains = []
    seen = set()
    for src in raw_sources:
        d = _extract_domain(src)
        if d and d not in seen and d not in SAFE_DOMAINS:
            seen.add(d)
            domains.append(d)

    if not domains:
        return {
            "domains_checked": [],
            "youngest_domain": None,
            "youngest_age_days": None,
            "risk_score": 0.0,
            "details": [],
        }

    # Run all lookups concurrently
    results = await asyncio.gather(*[_cached_lookup(d) for d in domains])

    # Find the youngest (highest risk) domain
    youngest = max(results, key=lambda r: r["risk_score"])

    return {
        "domains_checked": domains,
        "youngest_domain": youngest["domain"],
        "youngest_age_days": youngest.get("age_days"),
        "risk_score": youngest["risk_score"],
        "details": list(results),
    }
