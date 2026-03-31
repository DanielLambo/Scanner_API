"""
Numeric feature scoring for URLs.
Computes a risk_score (0–100) based on structural/statistical signals.
"""
import re
import math
from urllib.parse import urlparse

SAFE_TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "uk", "ca", "au", "de", "fr"}
RISKY_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "top", "click", "loan",
    "work", "party", "download", "win", "racing", "date", "trade",
}

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _char_entropy(s: str) -> float:
    """Shannon entropy of character frequencies in *s*."""
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def score_url(url: str) -> dict:
    """
    Return a dict of URL signals and an aggregate risk_score (0–100).
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    signals_fired: list = []
    risk = 0.0

    # ------------------------------------------------------------------
    # A) Domain character entropy
    # ------------------------------------------------------------------
    entropy = _char_entropy(hostname)
    entropy_contrib = min((entropy / 4.0) * 40, 40)
    risk += entropy_contrib
    if entropy > 3.5:
        signals_fired.append("HIGH_ENTROPY")

    # ------------------------------------------------------------------
    # B) Subdomain depth
    # ------------------------------------------------------------------
    dot_count = hostname.count(".")
    subdomain_depth = max(dot_count - 1, 0)
    if subdomain_depth > 3:
        risk += 25
        signals_fired.append("DEEP_SUBDOMAIN")
    elif subdomain_depth >= 2:
        risk += 10
        signals_fired.append("MODERATE_SUBDOMAIN")

    # ------------------------------------------------------------------
    # C) TLD rarity
    # ------------------------------------------------------------------
    parts = hostname.rsplit(".", 1)
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in RISKY_TLDS:
        tld_risk = "risky"
        risk += 35
        signals_fired.append("RISKY_TLD")
    elif tld not in SAFE_TLDS:
        tld_risk = "unknown"
        risk += 15
        signals_fired.append("UNKNOWN_TLD")
    else:
        tld_risk = "safe"

    # ------------------------------------------------------------------
    # D) Digit ratio in hostname
    # ------------------------------------------------------------------
    digit_count = sum(1 for ch in hostname if ch.isdigit())
    digit_ratio = digit_count / len(hostname) if hostname else 0.0
    if digit_ratio > 0.5:
        risk += 55   # 20 (>0.3 tier) + 35 (>0.5 tier) additive
        signals_fired.append("HIGH_DIGIT_RATIO")
        signals_fired.append("MODERATE_DIGIT_RATIO")
    elif digit_ratio > 0.3:
        risk += 20
        signals_fired.append("MODERATE_DIGIT_RATIO")

    # ------------------------------------------------------------------
    # E) Special char count in path
    # ------------------------------------------------------------------
    special_chars_in_path = sum(path.count(c) for c in "@!%~=")
    if special_chars_in_path > 3:
        risk += 15
        signals_fired.append("SUSPICIOUS_PATH_CHARS")

    # ------------------------------------------------------------------
    # F) Query parameter count
    # ------------------------------------------------------------------
    if query:
        query_param_count = query.count("&") + 1
    else:
        query_param_count = 0

    if query_param_count > 10:
        risk += 25
        signals_fired.append("EXCESSIVE_QUERY_PARAMS")
        signals_fired.append("MANY_QUERY_PARAMS")
    elif query_param_count > 5:
        risk += 15
        signals_fired.append("MANY_QUERY_PARAMS")

    # ------------------------------------------------------------------
    # G) Total URL length
    # ------------------------------------------------------------------
    url_length = len(url)
    if url_length > 150:
        risk += 30
        signals_fired.append("EXTREMELY_LONG_URL")
        signals_fired.append("VERY_LONG_URL")
        signals_fired.append("LONG_URL")
    elif url_length > 100:
        risk += 20
        signals_fired.append("VERY_LONG_URL")
        signals_fired.append("LONG_URL")
    elif url_length > 75:
        risk += 10
        signals_fired.append("LONG_URL")

    # ------------------------------------------------------------------
    # H) IP address as hostname
    # ------------------------------------------------------------------
    is_ip_host = bool(_IPV4_RE.match(hostname))
    if is_ip_host:
        risk += 50
        signals_fired.append("IP_HOST")

    return {
        "url": url,
        "entropy": round(entropy, 4),
        "subdomain_depth": subdomain_depth,
        "tld": tld,
        "tld_risk": tld_risk,
        "digit_ratio": round(digit_ratio, 4),
        "url_length": url_length,
        "query_param_count": query_param_count,
        "is_ip_host": is_ip_host,
        "risk_score": round(min(risk, 100.0), 2),
        "signals_fired": signals_fired,
    }
