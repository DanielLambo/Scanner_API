"""
Homoglyph / lookalike domain detection.
Uses a confusables map + Levenshtein distance to flag domains that
impersonate well-known brands.
"""
import Levenshtein

TOP_DOMAINS = [
    "paypal.com", "amazon.com", "apple.com", "microsoft.com",
    "google.com", "facebook.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "dropbox.com", "github.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "irs.gov", "usps.com", "fedex.com", "ups.com"
]

# Single-character and multi-character confusables
CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'і': 'i', 'ı': 'i', '0': 'o',
    '1': 'l', 'l': '1', 'rn': 'm', 'vv': 'w', 'ν': 'v',
    'ρ': 'p', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ℯ': 'e'
}

# Separate single-char and multi-char entries for ordered application
_SINGLE_CHAR = {k: v for k, v in CONFUSABLES.items() if len(k) == 1}
_MULTI_CHAR = {k: v for k, v in CONFUSABLES.items() if len(k) > 1}


def normalize_domain(domain: str) -> str:
    """
    Apply confusables map then lowercase and strip www. prefix.

    Single-character substitutions are applied character-by-character,
    then multi-character substitutions ('rn'->'m', 'vv'->'w') are applied
    on the resulting string.
    """
    # Strip www. and lowercase
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    # Apply single-char substitutions
    normalized = ""
    for ch in domain:
        normalized += _SINGLE_CHAR.get(ch, ch)

    # Apply multi-char substitutions
    for seq, replacement in _MULTI_CHAR.items():
        normalized = normalized.replace(seq, replacement)

    return normalized


def check_domain(domain: str) -> dict:
    """
    Check whether *domain* is a homoglyph of any TOP_DOMAIN.

    Returns:
        {
            "is_homoglyph": bool,
            "matched_domain": str | None,
            "original": str,
            "normalized": str,
            "match_type": "confusable" | "levenshtein" | None,
            "risk_score": float   # 95.0 if homoglyph else 0.0
        }
    """
    norm_input = normalize_domain(domain)

    best_confusable = None
    best_levenshtein = None
    best_lev_dist = None

    for top in TOP_DOMAINS:
        # Skip exact-same original (no impersonation)
        stripped = domain.lower()
        if stripped.startswith("www."):
            stripped = stripped[4:]
        if stripped == top.lower():
            continue

        norm_top = normalize_domain(top)

        # Confusable check: normalized forms are identical but originals differ
        if norm_input == norm_top:
            best_confusable = top
            break  # confusable has highest priority, stop searching

        # Levenshtein check on normalized forms
        dist = Levenshtein.distance(norm_input, norm_top)
        if dist <= 2 and dist > 0:
            if best_lev_dist is None or dist < best_lev_dist:
                best_lev_dist = dist
                best_levenshtein = top

    if best_confusable:
        return {
            "is_homoglyph": True,
            "matched_domain": best_confusable,
            "original": domain,
            "normalized": norm_input,
            "match_type": "confusable",
            "risk_score": 95.0,
        }

    if best_levenshtein:
        return {
            "is_homoglyph": True,
            "matched_domain": best_levenshtein,
            "original": domain,
            "normalized": norm_input,
            "match_type": "levenshtein",
            "risk_score": 95.0,
        }

    return {
        "is_homoglyph": False,
        "matched_domain": None,
        "original": domain,
        "normalized": norm_input,
        "match_type": None,
        "risk_score": 0.0,
    }


def check_domains(domains: list) -> dict:
    """
    Run check_domain on each domain and return the result with the highest
    risk_score (first one wins on ties).

    Also includes an "all_results" key with all individual results.
    """
    all_results = [check_domain(d) for d in domains]

    best = None
    for result in all_results:
        if best is None or result["risk_score"] > best["risk_score"]:
            best = result

    if best is None:
        best = {
            "is_homoglyph": False,
            "matched_domain": None,
            "original": "",
            "normalized": "",
            "match_type": None,
            "risk_score": 0.0,
        }

    return {**best, "all_results": all_results}
