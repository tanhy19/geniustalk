# utils/link_verifier.py
# QR and Link Verifier Module
# Handles: URL extraction, link expansion, lexical URL analysis

import re
import requests
from urllib.parse import urlparse


SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl", "goo.gl"]
SUSPICIOUS_TLDS    = [".xyz", ".top", ".ru", ".click", ".loan", ".win", ".tk", ".ml"]
PHISHING_WORDS     = [
    "login", "verify", "secure", "update", "bank",
    "reward", "gift", "free", "claim", "prize",
    "winner", "account", "confirm", "password"
]


def extract_urls(text):
    """Extracts all URLs including shortened ones."""
    pattern = r'(https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+|goo\.gl/\S+)'
    urls = re.findall(pattern, text)
    normalized = []
    for url in urls:
        if not url.startswith('http'):
            url = 'https://' + url
        normalized.append(url)
    return normalized


def expand_url(url):
    """Follows redirects to find real destination of shortened URL."""
    try:
        session  = requests.Session()
        response = session.get(url, allow_redirects=True, timeout=10)
        final_url = response.url
        if "bit.ly" in final_url or "tinyurl" in final_url:
            response  = session.get(url, stream=True, timeout=10)
            final_url = response.url
        return final_url
    except Exception:
        return url


def analyze_url(url):
    """
    Analyzes a URL for suspicious indicators.
    Returns risk score and list of flags.
    """
    score  = 0
    flags  = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    for s in SUSPICIOUS_DOMAINS:
        if s in domain:
            score += 20
            flags.append("Shortened URL detected")

    for t in SUSPICIOUS_TLDS:
        if domain.endswith(t) or t in domain:
            score += 25
            flags.append(f"Suspicious domain extension: {t}")

    for word in PHISHING_WORDS:
        if word in url.lower():
            score += 15
            flags.append(f"Phishing keyword in URL: {word}")

    if domain.count("-") >= 3:
        score += 10
        flags.append("Too many hyphens in domain")

    if len(domain) > 25:
        score += 10
        flags.append("Unusually long domain name")

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 30
        flags.append("IP address used instead of domain name")

    return score, flags


def verify_links(text):
    """
    Main function — extracts, expands, and analyzes all URLs in text.
    Returns total_score, urls found, and all flags.
    """
    urls = extract_urls(text)
    if not urls:
        return 0, [], []

    total_score = 0
    all_flags   = []

    for url in urls:
        expanded     = expand_url(url)
        score, flags = analyze_url(expanded)
        total_score  += score
        all_flags.extend(flags)

    return total_score, urls, all_flags