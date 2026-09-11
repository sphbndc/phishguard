import re
from email import policy
from email.parser import BytesParser, Parser

import dns.resolver
import dkim


AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)


def _organizational_domain(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def _aligned(auth_domain: str, from_domain: str) -> bool:
    return bool(auth_domain and from_domain) and _organizational_domain(auth_domain) == _organizational_domain(from_domain)


def _dns_txt(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    answers = resolver.resolve(name, "TXT")
    return [b"".join(record.strings).decode("utf-8", errors="replace") for record in answers]


def analyze_headers(raw_header: str, body: str, sender_domain: str) -> tuple[int, list[dict[str, str]], bool]:
    if not raw_header.strip():
        return 0, [{
            "category": "Email authentication",
            "severity": "Informational",
            "description": "No raw headers were supplied, so SPF, DKIM, and DMARC could not be assessed.",
        }], False

    message = Parser(policy=policy.default).parsestr(raw_header)
    received_spf = message.get_all("Received-SPF", [])
    auth_text = " ".join(message.get_all("Authentication-Results", []) + received_spf)
    auth = {mechanism.lower(): result.lower() for mechanism, result in AUTH_RESULT_RE.findall(auth_text)}
    if "spf" not in auth:
        for value in received_spf:
            verdict = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", value, re.I)
            if verdict:
                auth["spf"] = verdict.group(1).lower()
                break
    issues: list[dict[str, str]] = []
    score = 0

    for mechanism in ("spf", "dkim", "dmarc"):
        result = auth.get(mechanism)
        if result in {"fail", "softfail", "permerror"}:
            points = 18 if mechanism == "dmarc" else 12
            score += points
            issues.append({
                "category": f"{mechanism.upper()} authentication",
                "severity": "Critical" if result == "fail" else "Warning",
                "description": f"The receiving server reported {mechanism.upper()}={result}.",
            })
        elif result == "pass":
            issues.append({
                "category": f"{mechanism.upper()} authentication",
                "severity": "Informational",
                "description": f"The supplied Authentication-Results reports {mechanism.upper()}=pass.",
            })
        elif result in {"none", "neutral", "temperror"}:
            score += 5
            issues.append({
                "category": f"{mechanism.upper()} authentication",
                "severity": "Warning",
                "description": f"The supplied headers report {mechanism.upper()}={result}; authentication is inconclusive.",
            })

    dkim_domain_match = re.search(r"\bheader\.d=([^;\s]+)", auth_text, re.I)
    spf_domain_match = re.search(r"\bsmtp\.mailfrom=([^;\s@]+@)?([^;\s]+)", auth_text, re.I)
    header_from_match = re.search(r"\bheader\.from=([^;\s]+)", auth_text, re.I)
    dkim_aligned = not dkim_domain_match or _aligned(dkim_domain_match.group(1), sender_domain)
    spf_aligned = not spf_domain_match or _aligned(spf_domain_match.group(2), sender_domain)
    from_aligned = not header_from_match or _aligned(header_from_match.group(1), sender_domain)
    authentication_override = (
        all(auth.get(mechanism) == "pass" for mechanism in ("spf", "dkim", "dmarc"))
        and bool(sender_domain)
        and dkim_aligned
        and spf_aligned
        and from_aligned
    )
    if authentication_override:
        issues.append({
            "category": "Verified authentication",
            "severity": "Informational",
            "description": "SPF, DKIM, and DMARC all pass and align with the visible sender domain; routine account language is not treated as phishing evidence.",
        })
    if auth.get("dkim") == "pass" and dkim_domain_match and not _aligned(dkim_domain_match.group(1), sender_domain):
        score += 12
        issues.append({
            "category": "DKIM alignment",
            "severity": "Warning",
            "description": "DKIM passed for a domain that is not aligned with the visible sender domain.",
        })
    if auth.get("spf") == "pass" and spf_domain_match and not _aligned(spf_domain_match.group(2), sender_domain):
        score += 10
        issues.append({
            "category": "SPF alignment",
            "severity": "Warning",
            "description": "SPF passed for a return-path domain that is not aligned with the visible sender domain.",
        })

    if "dkim-signature" in raw_header.lower():
        try:
            full_message = raw_header.rstrip("\r\n").encode() + b"\r\n\r\n" + body.encode()
            parsed = BytesParser(policy=policy.SMTP).parsebytes(full_message)
            serialized = parsed.as_bytes(policy=policy.SMTP)
            if not dkim.verify(serialized):
                score += 12
                issues.append({
                    "category": "DKIM signature",
                    "severity": "Warning",
                    "description": "A direct DKIM verification attempt did not validate. Body canonicalization or copied headers may affect this check.",
                })
        except Exception:  # malformed copied messages and DNS backends raise varied errors
            issues.append({
                "category": "DKIM signature",
                "severity": "Informational",
                "description": "The DKIM signature could not be independently verified from the pasted message data.",
            })

    if sender_domain and "dmarc" not in auth:
        try:
            records = [record for record in _dns_txt(f"_dmarc.{sender_domain}") if record.lower().startswith("v=dmarc1")]
            if not records:
                score += 5
                issues.append({
                    "category": "DMARC policy",
                    "severity": "Warning",
                    "description": f"No DMARC policy was found for {sender_domain}.",
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            score += 5
            issues.append({
                "category": "DMARC policy",
                "severity": "Warning",
                "description": f"No retrievable DMARC policy was found for {sender_domain}.",
            })

    if sender_domain and "spf" not in auth:
        try:
            spf_records = [record for record in _dns_txt(sender_domain) if record.lower().startswith("v=spf1")]
            if spf_records:
                issues.append({
                    "category": "SPF policy",
                    "severity": "Informational",
                    "description": f"An SPF policy exists for {sender_domain}, but pass/fail cannot be determined without the sending server IP.",
                })
            else:
                score += 5
                issues.append({
                    "category": "SPF policy",
                    "severity": "Warning",
                    "description": f"No SPF policy was found for {sender_domain}.",
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            score += 5
            issues.append({
                "category": "SPF policy",
                "severity": "Warning",
                "description": f"No retrievable SPF policy was found for {sender_domain}.",
            })

    if not auth:
        score += 5
        issues.append({
            "category": "Email authentication",
            "severity": "Warning",
            "description": "No recognizable SPF, DKIM, or DMARC verdicts were found in the supplied headers.",
        })
    return min(score, 45), issues, authentication_override
