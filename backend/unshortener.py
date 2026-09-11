import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests

try:
    from .heuristics import is_url_suspicious
except ImportError:  # supports `uvicorn main:app` from inside backend/
    from heuristics import is_url_suspicious


URL_PATTERN = re.compile(r"https?://[^\s<>\"'\]\[()]+", re.IGNORECASE)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
MAX_REDIRECTS = 5
MAX_URLS = 20


def extract_urls(text: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:MAX_URLS]


def _assert_public_destination(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs can be checked")
    if parsed.username or parsed.password:
        raise ValueError("Credential-bearing URLs are not allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("Host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("Private or reserved destinations are blocked")


def resolve_url(url: str) -> str:
    current = url
    session = requests.Session()
    session.trust_env = False
    session.headers["User-Agent"] = "PhishGuard-LinkScanner/1.0"
    for _ in range(MAX_REDIRECTS + 1):
        _assert_public_destination(current)
        response = session.get(current, allow_redirects=False, timeout=(3.05, 5), stream=True)
        try:
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                if not location:
                    return current
                current = urljoin(current, location)
                continue
            return current
        finally:
            response.close()
    raise ValueError("Too many redirects")


def analyze_urls(text: str, claimed_brand: str | None = None) -> tuple[list[dict], list[dict[str, str]]]:
    results: list[dict] = []
    issues: list[dict[str, str]] = []
    for original in extract_urls(text):
        host = (urlparse(original).hostname or "").lower()
        final = original
        if host in SHORTENERS or any(host.endswith(f".{item}") for item in SHORTENERS):
            try:
                final = resolve_url(original)
            except (requests.RequestException, ValueError, OSError) as exc:
                issues.append({
                    "category": "Link inspection",
                    "severity": "Warning",
                    "description": f"Could not safely resolve {original}: {exc}",
                })
        suspicious = is_url_suspicious(final, claimed_brand)
        results.append({"original_url": original, "final_url": final, "is_suspicious": suspicious})
        if suspicious:
            issues.append({
                "category": "Suspicious link",
                "severity": "Critical",
                "description": f"The link points to {urlparse(final).hostname or final}, which is insecure or does not match the claimed brand.",
            })
    return results, issues
