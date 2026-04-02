"""
Unit tests for individual service modules.
"""
import base64
import pytest
import pytest_asyncio
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# URL Extractor
# ---------------------------------------------------------------------------

def test_url_extractor_basic():
    from utils.url_extractor import extract_urls
    result = extract_urls("Check http://example.com now")
    assert result == ["http://example.com"]


def test_url_extractor_dedup():
    from utils.url_extractor import extract_urls
    result = extract_urls("http://example.com and again http://example.com")
    assert result.count("http://example.com") == 1


def test_url_extractor_empty():
    from utils.url_extractor import extract_urls
    result = extract_urls("No URLs here, just text.")
    assert result == []


# ---------------------------------------------------------------------------
# URL Signals
# ---------------------------------------------------------------------------

def test_url_signals_high_entropy():
    from services.url_signals import score_url
    result = score_url("http://xkqzjwmvpb.com/path")
    assert "HIGH_ENTROPY" in result["signals_fired"]


def test_url_signals_risky_tld():
    from services.url_signals import score_url
    result = score_url("http://example.xyz")
    assert "RISKY_TLD" in result["signals_fired"]


def test_url_signals_ip_host():
    from services.url_signals import score_url
    result = score_url("http://192.168.1.1/login")
    assert "IP_HOST" in result["signals_fired"]
    assert result["is_ip_host"] is True


def test_url_signals_long_url():
    from services.url_signals import score_url
    long_path = "a" * 100
    result = score_url(f"http://example.com/{long_path}")
    fired = result["signals_fired"]
    assert "LONG_URL" in fired or "VERY_LONG_URL" in fired


def test_url_signals_safe_domain():
    from services.url_signals import score_url
    result = score_url("https://github.com")
    assert result["risk_score"] < 50


# ---------------------------------------------------------------------------
# Homoglyph
# ---------------------------------------------------------------------------

def test_homoglyph_paypal():
    from services.homoglyph import check_domain
    result = check_domain("paypa1.com")
    # paypa1.com - '1' is not in CONFUSABLES (removed to prevent FP),
    # but Levenshtein distance from paypal.com is 1 char so should match
    assert result["is_homoglyph"] is True
    assert result["matched_domain"] == "paypal.com"


def test_homoglyph_amazon():
    from services.homoglyph import check_domain
    result = check_domain("arnazon.com")
    assert result["is_homoglyph"] is True
    assert result["matched_domain"] == "amazon.com"


def test_homoglyph_gmail_no_fp():
    from services.homoglyph import check_domain
    result = check_domain("gmail.com")
    assert result["is_homoglyph"] is False


def test_homoglyph_google_no_fp():
    from services.homoglyph import check_domain
    result = check_domain("google.com")
    assert result["is_homoglyph"] is False


# ---------------------------------------------------------------------------
# Header Analyzer
# ---------------------------------------------------------------------------

def test_header_analyzer_dmarc_fail():
    from services.header_analyzer import analyze_headers
    raw = "Authentication-Results: mx.google.com; dmarc=fail (p=REJECT)"
    result = analyze_headers(raw)
    assert "DMARC_FAIL" in result["flags"]
    assert result["risk_score"] > 50


def test_header_analyzer_reply_to_mismatch():
    from services.header_analyzer import analyze_headers
    raw = (
        "From: user@company.com\r\n"
        "Reply-To: attacker@gmail.com\r\n"
        "To: victim@example.com"
    )
    result = analyze_headers(raw)
    assert "REPLY_TO_MISMATCH" in result["flags"]


def test_header_analyzer_display_name_spoof():
    from services.header_analyzer import analyze_headers
    raw = "From: PayPal Support <support@paypa1.com>\r\nTo: victim@example.com"
    result = analyze_headers(raw)
    assert "DISPLAY_NAME_SPOOF" in result["flags"]
    assert result["spoofed_brand"] is not None
    assert "PayPal" in result["spoofed_brand"]


def test_header_analyzer_clean():
    from services.header_analyzer import analyze_headers
    raw = "From: user@example.com\r\nTo: other@example.com"
    result = analyze_headers(raw)
    assert result["risk_score"] == 0.0
    assert result["flags"] == []


# ---------------------------------------------------------------------------
# Canonicalizer
# ---------------------------------------------------------------------------

async def test_canonicalizer_zero_width():
    from services.canonicalizer import canonicalize_url
    url_with_zwsp = "http://exa\u200bmple.com/page"
    result = await canonicalize_url(url_with_zwsp)
    assert "\u200b" not in result["canonical_url"]


async def test_canonicalizer_shortener():
    from services.canonicalizer import canonicalize_url
    result = await canonicalize_url("https://bit.ly/something")
    assert result["was_shortened"] is True


# ---------------------------------------------------------------------------
# Content Analyzer — evasion detection (preprocess_text)
# ---------------------------------------------------------------------------

def test_evasion_base64():
    from services.content_analyzer import preprocess_text
    encoded = base64.b64encode(b"verify your PayPal account immediately").decode()
    _, evasion_labels = preprocess_text(f"Check: {encoded}")
    assert "BASE64_ENCODED_BODY" in evasion_labels


def test_evasion_css_hidden():
    from services.content_analyzer import preprocess_text
    _, evasion_labels = preprocess_text('<div style="display:none">hidden phishing text</div>')
    assert "CSS_HIDDEN_TEXT" in evasion_labels


def test_evasion_html_comment():
    from services.content_analyzer import preprocess_text
    _, evasion_labels = preprocess_text("<!-- verify account: http://evil.com -->")
    assert "HTML_COMMENT_INJECTION" in evasion_labels


# ---------------------------------------------------------------------------
# EmailVerifier — Hunter.io integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_email_verifier_valid_response(monkeypatch):
    """Hunter.io returns a deliverable result — valid=True, score=90."""
    monkeypatch.setattr("config.settings.hunter_api_key", "fake-key-for-test")

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "result": "deliverable",
            "score": 90,
            "disposable": False,
            "gibberish": False,
            "accept_all": False,
            "webmail": True,
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_response):
        from services.email_verifier import EmailVerifier
        verifier = EmailVerifier()
        verifier.api_key = "fake-key-for-test"
        result = await verifier.verify_email("test@example.com")

    assert result is not None
    assert result.valid is True or result.score == 90


@pytest.mark.asyncio
async def test_email_verifier_disposable(monkeypatch):
    """Hunter.io returns a disposable/undeliverable result — risk_score > 50."""
    monkeypatch.setattr("config.settings.hunter_api_key", "fake-key-for-test")

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "result": "undeliverable",
            "score": 10,
            "disposable": True,
            "gibberish": True,
            "accept_all": False,
            "webmail": False,
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("requests.get", return_value=mock_response):
        from services.email_verifier import EmailVerifier
        verifier = EmailVerifier()
        verifier.api_key = "fake-key-for-test"
        result = await verifier.verify_email("disposable@throwaway.com")

    assert result.disposable is True or result.risk_score > 50


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gsb_detects_malicious(mock_gsb, monkeypatch):
    """GSB mock returns a match — flagged_urls should contain the evil URL."""
    from services.google_safe_browsing import GoogleSafeBrowsingService
    svc = GoogleSafeBrowsingService()
    svc.api_key = "fake-gsb-key"
    svc._redis_checked = True
    svc._redis = None

    result = await svc.check_urls(["http://evil.com"])

    assert "http://evil.com" in result["flagged_urls"]
    assert result["risk_score"] == 100


@pytest.mark.asyncio
async def test_gsb_clean_url(mock_gsb_clean, monkeypatch):
    """GSB mock returns no matches — flagged_urls should be empty."""
    from services.google_safe_browsing import GoogleSafeBrowsingService
    svc = GoogleSafeBrowsingService()
    svc.api_key = "fake-gsb-key"
    svc._redis_checked = True
    svc._redis = None

    result = await svc.check_urls(["http://safe.com"])

    assert result["flagged_urls"] == []
    assert result["risk_score"] == 0


# ---------------------------------------------------------------------------
# Canonicalizer — redirect following
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_canonicalizer_follows_redirect(mock_redirect):
    """bit.ly/test123 redirects to phishing-destination.com via mock."""
    from services.canonicalizer import canonicalize_url
    result = await canonicalize_url("https://bit.ly/test123")
    assert result["canonical_url"] == "http://phishing-destination.com"
    assert result["was_shortened"] is True


# ---------------------------------------------------------------------------
# Canonicalizer — new tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multi_hop_redirect_followed(mock_multi_hop_redirect):
    """bit.ly/abc -> tinyurl.com/xyz -> final-phishing-destination.com"""
    from services.canonicalizer import canonicalize_url
    result = await canonicalize_url("https://bit.ly/abc")
    assert result["canonical_url"] == "http://final-phishing-destination.com"
    assert len(result["redirect_chain"]) >= 2
    assert result["was_shortened"] is True


@pytest.mark.asyncio
async def test_redirect_timeout_handled(mock_redirect_timeout):
    """Timeout on hop should not raise, should return a result."""
    from services.canonicalizer import canonicalize_url
    result = await canonicalize_url("https://slow-redirect.com")
    assert result is not None
    assert result["canonical_url"] is not None


@pytest.mark.asyncio
async def test_zero_width_chars_stripped():
    """Zero-width char at end of path should be stripped from canonical_url."""
    from services.canonicalizer import canonicalize_url
    url = "https://evil.com/path\u200b"
    result = await canonicalize_url(url)
    assert "\u200b" not in result["canonical_url"]


@pytest.mark.asyncio
async def test_max_hops_respected():
    """Should stop following redirects after MAX_HOPS and not infinite loop."""
    import respx
    import httpx
    from services.canonicalizer import canonicalize_url

    hops = [f"https://hop{i}.com" for i in range(1, 8)]
    with respx.mock:
        for i in range(len(hops) - 1):
            respx.get(hops[i]).mock(
                return_value=httpx.Response(301, headers={"location": hops[i + 1]})
            )
        respx.get(hops[-1]).mock(return_value=httpx.Response(200))
        result = await canonicalize_url(hops[0])

    assert len(result["redirect_chain"]) <= 6
    # No infinite loop — just checking it returns
    assert result["canonical_url"] is not None


# ---------------------------------------------------------------------------
# OpenPhish tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_openphish_initialize(mock_openphish_feed):
    """After initialize, feed should contain 3 URLs and status should be ready."""
    from services.openphish import DumpManager
    svc = DumpManager()
    await svc._fetch_feed()
    assert svc.url_count == 3
    assert svc.status == "ready"


@pytest.mark.asyncio
async def test_openphish_detects_known_url(mock_openphish_feed):
    """After initialize, check_urls should flag a known phishing URL."""
    from services.openphish import DumpManager
    svc = DumpManager()
    await svc._fetch_feed()
    result = svc.check_urls(["http://evil1.com"])
    assert "http://evil1.com" in result["flagged_urls"]
    assert result["risk_score"] == 100


@pytest.mark.asyncio
async def test_openphish_clean_url(mock_openphish_feed):
    """GitHub should not be in the phishing feed."""
    from services.openphish import DumpManager
    svc = DumpManager()
    await svc._fetch_feed()
    result = svc.check_urls(["https://github.com"])
    assert result["risk_score"] == 0


@pytest.mark.asyncio
async def test_openphish_feed_failure_graceful(mock_openphish_error):
    """500 error from feed should not raise; service should be in empty state."""
    from services.openphish import DumpManager
    svc = DumpManager()
    await svc._fetch_feed()
    assert svc.url_count == 0
    assert svc.status == "empty"


# ---------------------------------------------------------------------------
# Google Safe Browsing — new tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gsb_multiple_matches(mock_gsb_full, monkeypatch):
    """GSB returns 2 matches — flagged_urls >= 1 and risk_score > 0."""
    monkeypatch.setattr("config.settings.google_safe_browsing_key", "fake-key")
    from services.google_safe_browsing import GoogleSafeBrowsingService
    svc = GoogleSafeBrowsingService()
    svc.api_key = "fake-key"
    svc._redis_checked = True
    svc._redis = None

    result = await svc.check_urls(["http://evil.com", "http://malware.com", "http://clean.com"])
    assert len(result["flagged_urls"]) >= 1
    assert result["risk_score"] > 0


@pytest.mark.asyncio
async def test_gsb_network_error_graceful(mock_gsb_network_error, monkeypatch):
    """Network error from GSB should not raise; returns risk_score=0."""
    monkeypatch.setattr("config.settings.google_safe_browsing_key", "fake-key")
    from services.google_safe_browsing import GoogleSafeBrowsingService
    svc = GoogleSafeBrowsingService()
    svc.api_key = "fake-key"
    svc._redis_checked = True
    svc._redis = None

    result = await svc.check_urls(["http://evil.com"])
    assert result["risk_score"] == 0


# ---------------------------------------------------------------------------
# URL Scanner tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_url_scanner_empty_text():
    """Email with no URLs returns empty urls_found and risk_score 0."""
    from services.url_scanner import url_scanner
    result = await url_scanner.scan_urls("Hello, see you at the meeting tomorrow.")
    assert result.urls_found == []
    assert result.risk_score == 0


@pytest.mark.asyncio
async def test_url_scanner_ip_address_url():
    """IP-based URL triggers IP_HOST signal and risk_score > 0."""
    from unittest.mock import patch, AsyncMock
    from services.url_scanner import url_scanner

    async def mock_canonicalize_urls(urls):
        return {u: {"canonical_url": u, "was_shortened": False, "redirect_chain": [u]} for u in urls}

    with patch("services.url_scanner.canonicalize_urls", side_effect=mock_canonicalize_urls), \
         patch("services.url_scanner.gsb_service.check_urls", new_callable=AsyncMock,
               return_value={"flagged_urls": [], "clean_urls": [], "risk_score": 0}), \
         patch("services.url_scanner.openphish.check_urls",
               return_value={"flagged_urls": [], "clean_urls": [], "risk_score": 0}), \
         patch.object(url_scanner, "_scan_urls_vt",
                      return_value={"malicious_count": 0, "suspicious_count": 0,
                                    "risk_score": 0.0, "details": []}):
        result = await url_scanner.scan_urls("Visit http://192.168.1.100/login now")

    assert any("192.168.1.100" in u for u in result.urls_found)
    signals_fired = []
    if result.url_signals:
        for sig in result.url_signals:
            signals_fired.extend(sig.get("signals_fired", []))
    assert "IP_HOST" in signals_fired
    assert result.risk_score > 0


@pytest.mark.asyncio
async def test_url_scanner_deduplication():
    """Same URL 3 times should appear only once in urls_found."""
    from unittest.mock import patch, AsyncMock
    from services.url_scanner import url_scanner

    async def mock_canonicalize_urls(urls):
        return {u: {"canonical_url": u, "was_shortened": False, "redirect_chain": [u]} for u in urls}

    with patch("services.url_scanner.canonicalize_urls", side_effect=mock_canonicalize_urls), \
         patch("services.url_scanner.gsb_service.check_urls", new_callable=AsyncMock,
               return_value={"flagged_urls": [], "clean_urls": [], "risk_score": 0}), \
         patch("services.url_scanner.openphish.check_urls",
               return_value={"flagged_urls": [], "clean_urls": [], "risk_score": 0}), \
         patch.object(url_scanner, "_scan_urls_vt",
                      return_value={"malicious_count": 0, "suspicious_count": 0,
                                    "risk_score": 0.0, "details": []}):
        result = await url_scanner.scan_urls(
            "Click http://example.xyz http://example.xyz http://example.xyz"
        )

    assert result.urls_found.count("http://example.xyz") == 1
