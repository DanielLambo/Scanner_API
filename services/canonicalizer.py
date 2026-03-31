"""
URL canonicalization service.
- Strips zero-width / soft-hyphen characters
- NFKC-normalizes Unicode
- Decodes Punycode (IDN) hostnames
- Follows HTTP redirects up to 5 hops
- Tracks the full redirect chain and whether the URL was a known shortener
- Caches results in Redis (TTL 3600s) when available
"""
import asyncio
import json
import unicodedata
import logging
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)

# Zero-width + soft-hyphen code points to strip
_STRIP_CHARS = "\u200b\ufeff\u200c\u200d\u00ad"

MAX_HOPS = 5
HOP_TIMEOUT = 3.0  # seconds per hop
REDIS_TTL = 3600

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "short.io", "cutt.ly", "tiny.cc", "is.gd",
}


# ---------------------------------------------------------------------------
# Redis helpers (optional – gracefully degrade if unavailable)
# ---------------------------------------------------------------------------

_redis_client = None
_redis_checked = False


async def _get_redis():
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client
    _redis_checked = True
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url("redis://localhost:6379", decode_responses=True)
        await client.ping()
        _redis_client = client
        logger.debug("Canonicalizer: Redis available")
    except Exception:
        _redis_client = None
        logger.debug("Canonicalizer: Redis unavailable, skipping cache")
    return _redis_client


async def _cache_get(key: str) -> Optional[str]:
    try:
        redis = await _get_redis()
        if redis:
            return await redis.get(key)
    except Exception as exc:
        logger.debug("Canonicalizer cache read error: %s", exc)
    return None


async def _cache_set(key: str, value: str) -> None:
    try:
        redis = await _get_redis()
        if redis:
            await redis.setex(key, REDIS_TTL, value)
    except Exception as exc:
        logger.debug("Canonicalizer cache write error: %s", exc)


# ---------------------------------------------------------------------------
# Core canonicalization
# ---------------------------------------------------------------------------

def _clean_url(url: str) -> str:
    """Strip zero-width chars and NFKC-normalize."""
    url = url.strip(_STRIP_CHARS)
    for ch in _STRIP_CHARS:
        url = url.replace(ch, "")
    return unicodedata.normalize("NFKC", url)


def _decode_punycode(url: str) -> str:
    """Decode xn-- Punycode hostname to Unicode."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if "xn--" in hostname:
            decoded = hostname.encode("ascii").decode("idna")
            # Rebuild netloc preserving port and userinfo
            netloc = parsed.netloc
            netloc = netloc.replace(hostname, decoded)
            parsed = parsed._replace(netloc=netloc)
            return urlunparse(parsed)
    except Exception:
        pass
    return url


async def canonicalize_url(url: str) -> dict:
    """
    Return a dict describing the canonicalized URL:
      {
        "canonical_url": str,
        "was_shortened": bool,
        "redirect_chain": [str, ...]   # all URLs visited including start and final
      }

    Steps:
      1. Strip zero-width characters
      2. NFKC Unicode normalization
      3. Punycode decoding
      4. Follow up to MAX_HOPS HTTP redirects (3 s timeout each)

    Results are cached in Redis with TTL=3600 s when Redis is available.
    """
    cache_key = f"canon2:{url}"
    cached_raw = await _cache_get(cache_key)
    if cached_raw:
        try:
            return json.loads(cached_raw)
        except Exception:
            pass

    # Determine if the original URL's domain is a known shortener
    original_domain = (urlparse(url).hostname or "").lower()
    was_shortened = original_domain in SHORTENERS

    # Clean the URL
    current = _clean_url(url)
    current = _decode_punycode(current)

    # redirect_chain starts with the initial (cleaned) URL
    redirect_chain: list = [current]

    # Follow redirects manually so we control hop count
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=HOP_TIMEOUT) as client:
            for _ in range(MAX_HOPS):
                try:
                    resp = await client.get(current)
                    if resp.is_redirect:
                        location = resp.headers.get("location", "")
                        if not location:
                            break
                        # Resolve relative redirects
                        if location.startswith("/"):
                            parsed = urlparse(current)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        current = location
                        redirect_chain.append(current)
                    else:
                        # Final destination reached
                        break
                except httpx.TimeoutException:
                    logger.debug("Canonicalizer: timeout on hop for %s", current)
                    break
                except Exception as exc:
                    logger.debug("Canonicalizer: hop error for %s: %s", current, exc)
                    break
    except Exception as exc:
        logger.debug("Canonicalizer: client error for %s: %s", url, exc)

    result = {
        "canonical_url": current,
        "was_shortened": was_shortened,
        "redirect_chain": redirect_chain,
    }

    await _cache_set(cache_key, json.dumps(result))
    return result


async def canonicalize_urls(urls: list) -> dict:
    """
    Canonicalize a list of URLs concurrently.

    Returns:
        dict mapping original_url -> result dict
        (each result dict has canonical_url, was_shortened, redirect_chain)
    """
    results = await asyncio.gather(*[canonicalize_url(u) for u in urls])
    return dict(zip(urls, results))
