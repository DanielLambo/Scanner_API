"""
URL extraction utility
Extracts URLs from email text using regex
"""
import re
from typing import List


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
