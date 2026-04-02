"""
URL extraction utility
Extracts URLs from email text using regex
"""
import re
from typing import List, Tuple
from urllib.parse import urlparse, unquote


def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from text

    Args:
        text: Text to extract URLs from

    Returns:
        List of unique URLs found
    """
    if not text:
        return []

    # Regex pattern for URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    urls = re.findall(url_pattern, text)

    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    return unique_urls


def extract_urls_with_evasion(text: str) -> Tuple[List[str], List[str]]:
    """
    Extract all URLs from text, also detecting URL fragment tricks and data: URIs.

    Attack 4 detection:
    - "#http" fragment trick: extracts the fragment URL as an additional URL to scan
    - data: URIs (data:text/html or data:application/javascript): flagged immediately

    Args:
        text: Text to extract URLs from

    Returns:
        (urls, evasion_labels) where urls includes fragment-extracted URLs,
        and evasion_labels contains "URL_FRAGMENT_TRICK" and/or "DATA_URI_DETECTED"
    """
    if not text:
        return [], []

    evasion_labels: List[str] = []

    # Base URL extraction
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    raw_urls = re.findall(url_pattern, text)

    # Also detect data: URIs in text
    data_uri_pattern = r'data:(?:text/html|application/javascript)[^"\'>\s]*'
    data_uris = re.findall(data_uri_pattern, text, re.IGNORECASE)
    if data_uris:
        evasion_labels.append("DATA_URI_DETECTED")

    seen = set()
    unique_urls = []

    for url in raw_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

        # Check for "#http" fragment trick
        # The regex may already include the fragment in the URL if # is matched,
        # but the standard URL regex stops at # since # is not in the character class.
        # We need to check the original text for URLs followed by #http...

    # Re-scan the text specifically for fragment trick: URLs containing #http
    fragment_trick_pattern = r'(https?://[^\s"\'<>]+?)(#https?://[^\s"\'<>]+)'
    fragment_matches = re.findall(fragment_trick_pattern, text)
    for base_url, fragment in fragment_matches:
        fragment_url = fragment[1:]  # strip the leading '#'
        if "URL_FRAGMENT_TRICK" not in evasion_labels:
            evasion_labels.append("URL_FRAGMENT_TRICK")
        # Add the fragment URL as an additional URL to scan
        if fragment_url not in seen:
            seen.add(fragment_url)
            unique_urls.append(fragment_url)
        # Also ensure the base URL (with fragment stripped) is present
        if base_url not in seen:
            seen.add(base_url)
            unique_urls.append(base_url)

    return unique_urls, evasion_labels
