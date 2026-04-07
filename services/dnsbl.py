"""
DNSBL (DNS blocklist) checking service.
Queries multiple blocklists concurrently to flag known spam/phishing domains.
"""
import asyncio
import logging

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

BLOCKLISTS: dict[str, str] = {
    "zen.spamhaus.org": "Spamhaus",
    "dbl.spamhaus.org": "Spamhaus DBL",
    "multi.surbl.org": "SURBL",
    "multi.uribl.com": "URIBL",
}

SAFE_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "gitlab.com", "stackoverflow.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
    "youtube.com", "netflix.com", "dropbox.com",
    "slack.com", "zoom.us", "notion.so", "figma.com",
    "vercel.com", "netlify.com", "cloudflare.com", "render.com",
}

_TIMEOUT = 2.0  # seconds per DNS query


def _query(lookup_host: str) -> bool:
    """Blocking DNS A-record query. Returns True if the host resolves (= listed)."""
    try:
        dns.resolver.resolve(lookup_host, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except Exception as exc:
        logger.debug("DNS query error for %s: %s", lookup_host, exc)
        return False


async def _check_one(domain: str, zone: str, label: str) -> tuple[str, bool]:
    """Check a single domain against a single DNSBL zone. Returns (label, listed)."""
    lookup = f"{domain}.{zone}"
    try:
        listed = await asyncio.wait_for(
            asyncio.to_thread(_query, lookup),
            timeout=_TIMEOUT,
        )
        return label, listed
    except asyncio.TimeoutError:
        logger.warning("DNSBL query timed out: %s", lookup)
        return label, False


async def check_domains(domains: list[str]) -> dict:
    """
    Check a list of domains against all configured DNSBLs concurrently.

    Returns:
        {
            "domains_checked": [...],
            "flagged_domains": [...],
            "blocklist_hits": {"evil.com": ["Spamhaus", "SURBL"]},
            "risk_score": 100.0 | 0.0,
        }
    """
    # Filter out safe domains
    to_check = [d for d in domains if d and d not in SAFE_DOMAINS]

    if not to_check:
        return {
            "domains_checked": domains,
            "flagged_domains": [],
            "blocklist_hits": {},
            "risk_score": 0.0,
        }

    # Build all (domain, zone, label) tasks and run concurrently
    tasks = [
        (domain, zone, label)
        for domain in to_check
        for zone, label in BLOCKLISTS.items()
    ]

    results = await asyncio.gather(
        *[_check_one(domain, zone, label) for domain, zone, label in tasks]
    )

    # Map results back to domains
    blocklist_hits: dict[str, list[str]] = {}
    for (domain, _, _), (label, listed) in zip(tasks, results):
        if listed:
            blocklist_hits.setdefault(domain, []).append(label)

    flagged = list(blocklist_hits.keys())

    return {
        "domains_checked": to_check,
        "flagged_domains": flagged,
        "blocklist_hits": blocklist_hits,
        "risk_score": 100.0 if flagged else 0.0,
    }
