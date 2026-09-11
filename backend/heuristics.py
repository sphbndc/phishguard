import re
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup


URGENCY_PATTERNS = {
    "account suspended": 10,
    "immediate action required": 10,
    "verify now": 10,
    "act now": 10,
    "urgent": 10,
    "within 24 hours": 10,
    "final warning": 10,
    "unusual activity": 10,
    "limited time": 10,
}

TRANSACTIONAL_PATTERNS = ("reset password", "log in", "login", "unsubscribe", "manage preferences")

DATA_PATTERNS = {
    r"\b(?:send|share|confirm|enter|provide|reply with)\b.{0,35}\bpassword\b": "password",
    r"\b(?:send|share|confirm|enter|provide)\b.{0,35}\b(?:ssn|social security number)\b": "Social Security number",
    r"\b(?:send|share|confirm|enter|provide)\b.{0,35}\b(?:pin|passcode|one[- ]time (?:code|password)|otp)\b": "PIN or verification code",
    r"\b(?:send|share|confirm|enter|provide)\b.{0,35}\b(?:credit card|card number|cvv)\b": "payment-card details",
    r"\b(?:seed phrase|recovery phrase|private key)\b": "wallet recovery secret",
}

PAYMENT_REQUEST_PATTERN = re.compile(
    r"\b(?:give|send|transfer|pay|wire|deposit|refund)\b.{0,45}\b(?:money|cash|funds|payment|dollars?|€|£|₱)\b",
    re.IGNORECASE,
)
LINK_ACTION_PATTERN = re.compile(
    r"\b(?:send|click|open|follow|use)\b.{0,35}\b(?:this|the)\s+link\b",
    re.IGNORECASE,
)

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


@dataclass
class HeuristicResult:
    score: int
    issues: list[dict[str, str]]
    sender_domain: str
    claimed_brand: str | None


def _registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_left != char_right)))
        previous = current
    return previous[-1]


def extract_sender_domain(sender: str) -> str:
    address = parseaddr(sender)[1] or sender.strip()
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[1].lower().strip().strip(">")
    return domain if re.fullmatch(r"[a-z0-9._-]+", domain) else ""


def identify_claimed_brand(sender: str, body: str) -> str | None:
    haystack = f"{sender} {body}".lower()
    for brand in BRAND_DOMAINS:
        if re.search(rf"\b{re.escape(brand)}\b", haystack):
            return brand
    return None


def suspicious_domain(domain: str, claimed_brand: str | None = None) -> tuple[bool, str]:
    if not domain:
        return False, ""
    registered = _registered_domain(domain)
    domain_label = registered.split(".")[0]
    candidates = [claimed_brand] if claimed_brand else list(BRAND_DOMAINS)
    for brand in filter(None, candidates):
        official = BRAND_DOMAINS[brand]
        if registered in official or any(domain.endswith(f".{item}") for item in official):
            return False, ""
        normalized = domain_label.translate(SUBSTITUTIONS).replace("-", "")
        if brand in domain_label or brand in normalized or _distance(normalized, brand) <= 1:
            return True, f"The domain {domain} resembles {brand} but is not one of its known official domains."
        if claimed_brand == brand:
            return True, f"The message appears to represent {brand}, but {domain} is not one of its known official domains."
    if domain.startswith("xn--") or ".xn--" in domain:
        return True, f"The sender domain {domain} uses internationalized-domain encoding, which can conceal lookalike characters."
    return False, ""


def analyze_heuristics(sender: str, body: str) -> HeuristicResult:
    soup = BeautifulSoup(body, "html.parser")
    for node in soup(["style", "script", "noscript", "template", "head"]):
        node.decompose()
    for node in soup.find_all(True):
        node.attrs.pop("style", None)
    lowered = re.sub(r"\s+", " ", soup.get_text(" ").lower()).strip()
    issues: list[dict[str, str]] = []
    score = 0

    urgency = [phrase for phrase in URGENCY_PATTERNS if phrase in lowered]
    if urgency:
        points = min(10, sum(URGENCY_PATTERNS[item] for item in urgency))
        score += points
        issues.append({
            "category": "High-pressure language",
            "severity": "Warning",
            "description": f"Uses urgency cues: {', '.join(urgency[:4])}. Pressure is commonly used to suppress careful verification.",
        })

    routine = [phrase for phrase in TRANSACTIONAL_PATTERNS if phrase in lowered]
    if routine:
        issues.append({
            "category": "Routine transactional language",
            "severity": "Informational",
            "description": f"Contains ordinary account language ({', '.join(routine[:3])}); this is not a phishing signal by itself.",
        })

    requested = [label for pattern, label in DATA_PATTERNS.items() if re.search(pattern, lowered, re.IGNORECASE)]
    if requested:
        score += min(35, 18 + 7 * len(requested))
        issues.append({
            "category": "Sensitive-data request",
            "severity": "Critical",
            "description": f"Asks the recipient to disclose {', '.join(requested)}. Legitimate organizations do not request secrets by email.",
        })

    sender_domain = extract_sender_domain(sender)
    brand = identify_claimed_brand(sender, body)
    is_lookalike, reason = suspicious_domain(sender_domain, brand)
    if is_lookalike:
        score += 50
        issues.append({"category": "Sender impersonation", "severity": "Critical", "description": reason})
    elif not sender_domain:
        score += 8
        issues.append({
            "category": "Sender identity",
            "severity": "Warning",
            "description": "The sender value is not a valid email address, so its domain cannot be verified.",
        })

    if re.search(r"\b(?:wire transfer|gift cards?|cryptocurrency|bitcoin)\b", lowered):
        score += 18
        issues.append({
            "category": "Unusual payment request",
            "severity": "Critical",
            "description": "Requests a hard-to-reverse payment method often used in social-engineering scams.",
        })

    if PAYMENT_REQUEST_PATTERN.search(lowered):
        # A financial demand is concerning, but without corroborating evidence
        # (spoofed identity, suspicious URL, credentials, or attachment) it is
        # a warning rather than proof of phishing.
        score += 15
        issues.append({
            "category": "Direct money request",
            "severity": "Warning",
            "description": "Demands or solicits money through the message. Verify unexpected payment requests through an independent, trusted channel.",
        })

    if LINK_ACTION_PATTERN.search(lowered) and not re.search(r"https?://|www\.", lowered):
        score += 12
        issues.append({
            "category": "Unspecified link action",
            "severity": "Warning",
            "description": "Directs the recipient to use an unspecified link without providing a verifiable destination.",
        })

    return HeuristicResult(min(score, 100), issues, sender_domain, brand)


def is_url_suspicious(url: str, claimed_brand: str | None = None) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host:
            return True
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or "@" in parsed.netloc:
            return True
        return suspicious_domain(host, claimed_brand)[0]
    except ValueError:
        return True
