"""
Header analyzer - parses raw email headers to detect authentication failures,
reply-to mismatches, display name spoofing, and relay anomalies.
"""
import re
import email.parser
import email.utils
from typing import Optional


# Known brand → canonical domain fragments
_BRAND_DOMAINS = {
    "paypal":     "paypal.com",
    "amazon":     "amazon.com",
    "apple":      "apple.com",
    "microsoft":  "microsoft.com",
    "google":     "google.com",
    "netflix":    "netflix.com",
    "chase":      "chase.com",
    "irs":        "irs.gov",
}

# Display-name keywords (lowercase) → brand key
_BRAND_KEYWORDS = {
    "paypal":    "paypal",
    "amazon":    "amazon",
    "apple":     "apple",
    "microsoft": "microsoft",
    "google":    "google",
    "netflix":   "netflix",
    "chase":     "chase",
    "irs":       "irs",
}

_FREE_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}

# Private / RFC-1918 address ranges
_PRIVATE_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# IP anywhere inside brackets or bare
_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)")


def _extract_domain(address: str) -> Optional[str]:
    """Return the domain part of an e-mail address (lowercase), or None."""
    if not address:
        return None
    address = address.strip()
    if "@" in address:
        return address.split("@")[-1].strip().rstrip(">").lower()
    return None


def _parse_auth_results(value: str) -> dict:
    """
    Parse an Authentication-Results header value and return
    {"spf": ..., "dkim": ..., "dmarc": ..., "dmarc_policy": ...}.
    """
    result = {
        "spf": "missing",
        "dkim": "missing",
        "dmarc": "missing",
        "dmarc_policy": "missing",
    }

    # SPF
    spf_m = re.search(r"\bspf=(pass|fail|softfail|neutral|none)\b", value, re.I)
    result["spf"] = spf_m.group(1).lower() if spf_m else "missing"

    # DKIM
    dkim_m = re.search(r"\bdkim=(pass|fail|none)\b", value, re.I)
    result["dkim"] = dkim_m.group(1).lower() if dkim_m else "missing"

    # DMARC result
    dmarc_m = re.search(r"\bdmarc=(pass|fail|none)\b", value, re.I)
    result["dmarc"] = dmarc_m.group(1).lower() if dmarc_m else "missing"

    # DMARC policy  (p=reject / p=quarantine / p=none)
    policy_m = re.search(r"\bp=(reject|quarantine|none)\b", value, re.I)
    result["dmarc_policy"] = policy_m.group(1).lower() if policy_m else "missing"

    return result


def analyze_headers(raw_headers: str) -> dict:
    """
    Analyze raw email headers for authentication failures, spoofing
    indicators, and relay anomalies.

    Parameters
    ----------
    raw_headers : str
        The raw header block of an email (everything before the body).

    Returns
    -------
    dict
        See module docstring for the full schema.
    """
    # ------------------------------------------------------------------ #
    # 0. Parse with the stdlib email parser                                #
    # ------------------------------------------------------------------ #
    # email.parser expects headers followed by a blank line before body;
    # we add the blank line so it does not absorb our text as body.
    parser = email.parser.HeaderParser()
    msg = parser.parsestr(raw_headers + "\r\n\r\n")

    risk_score: float = 0.0
    flags: list[str] = []

    # ------------------------------------------------------------------ #
    # A. SPF / DKIM / DMARC                                               #
    # ------------------------------------------------------------------ #
    auth_header = msg.get("Authentication-Results", "")
    auth = _parse_auth_results(auth_header)

    spf         = auth["spf"]
    dkim        = auth["dkim"]
    dmarc       = auth["dmarc"]
    dmarc_policy = auth["dmarc_policy"]

    # Base score from DMARC
    if dmarc == "fail":
        flags.append("DMARC_FAIL")
        if dmarc_policy == "reject":
            risk_score += 90
        elif dmarc_policy == "quarantine":
            risk_score += 70
        else:
            # none or missing
            risk_score += 40

    # Additive penalties
    if dkim == "fail":
        risk_score += 30
    if spf == "fail":
        risk_score += 20
    elif spf == "softfail":
        risk_score += 10

    risk_score = min(risk_score, 100.0)

    # ------------------------------------------------------------------ #
    # B. Reply-To mismatch / display-name spoof                          #
    # ------------------------------------------------------------------ #
    from_header    = msg.get("From", "")
    reply_to_header = msg.get("Reply-To", "")

    # Parse From
    from_display, from_addr = email.utils.parseaddr(from_header)
    from_domain = _extract_domain(from_addr)

    # Parse Reply-To
    _, reply_to_addr = email.utils.parseaddr(reply_to_header)
    reply_to_domain = _extract_domain(reply_to_addr) if reply_to_addr else None

    reply_to_mismatch = False
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        reply_to_mismatch = True
        risk_score = min(risk_score + 60, 100.0)
        flags.append("REPLY_TO_MISMATCH")

        # Extra penalty when reply-to is a free provider
        if reply_to_domain in _FREE_PROVIDERS:
            risk_score = min(risk_score + 20, 100.0)

    # Display-name brand spoof
    display_name_spoof = False
    spoofed_brand: Optional[str] = None

    if from_display:
        dn_lower = from_display.lower()
        for keyword, brand_key in _BRAND_KEYWORDS.items():
            if keyword in dn_lower:
                canonical = _BRAND_DOMAINS[brand_key]
                # Check that from_domain actually ends with the canonical domain
                if from_domain and not from_domain.endswith(canonical):
                    display_name_spoof = True
                    spoofed_brand = from_display  # keep original casing for message
                    risk_score = min(risk_score + 40, 100.0)
                    flags.append("DISPLAY_NAME_SPOOF")
                break  # one match is enough

    # ------------------------------------------------------------------ #
    # C. Received-header hop analysis                                      #
    # ------------------------------------------------------------------ #
    received_headers: list[str] = msg.get_all("Received") or []
    hop_count = len(received_headers)

    if hop_count > 8:
        risk_score = min(risk_score + 20, 100.0)

    relay_mismatch = False
    internal_relay = False

    # The *first* Received header is the one appended by the final MTA
    # (closest to origin when the headers are in standard order top→bottom
    # newest→oldest).  Some implementations want last; we follow the spec:
    # the topmost Received header is added last (by the receiving server
    # closest to the recipient), so the BOTTOM-most is closest to origin.
    origin_received = received_headers[-1] if received_headers else ""

    # Relay mismatch: from_domain should appear somewhere in origin header
    if from_domain and origin_received:
        if from_domain.lower() not in origin_received.lower():
            relay_mismatch = True
            risk_score = min(risk_score + 25, 100.0)
            if "RELAY_MISMATCH" not in flags:
                flags.append("RELAY_MISMATCH")

    # Internal relay: private IP in ANY Received header
    all_received_text = "\n".join(received_headers)
    if _PRIVATE_RE.search(all_received_text):
        internal_relay = True
        risk_score = min(risk_score + 15, 100.0)
        if "INTERNAL_RELAY" not in flags:
            flags.append("INTERNAL_RELAY")

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "dmarc_policy": dmarc_policy,
        "reply_to_mismatch": reply_to_mismatch,
        "reply_to_domain": reply_to_domain,
        "from_domain": from_domain,
        "display_name_spoof": display_name_spoof,
        "spoofed_brand": spoofed_brand,
        "hop_count": hop_count,
        "relay_mismatch": relay_mismatch,
        "internal_relay": internal_relay,
        "risk_score": round(min(risk_score, 100.0), 2),
        "flags": flags,
    }
