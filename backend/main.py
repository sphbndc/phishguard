import logging
import os
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    from .header_parser import analyze_headers
    from .heuristics import BRAND_DOMAINS, analyze_heuristics
    from .nlp_engine import clean_email_text, phishing_probability
    from .schemas import AnalyzeRequest, AnalyzeResponse
    from .unshortener import analyze_urls
except ImportError:  # supports `uvicorn main:app` from inside backend/
    from header_parser import analyze_headers
    from heuristics import BRAND_DOMAINS, analyze_heuristics
    from nlp_engine import clean_email_text, phishing_probability
    from schemas import AnalyzeRequest, AnalyzeResponse
    from unshortener import analyze_urls

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="PhishGuard API",
    version="1.0.0",
    description="Local-first phishing analysis API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://phishguard-drab-five.vercel.app",
        *[origin.strip() for origin in os.getenv("PHISHGUARD_FRONTEND_ORIGIN", "").split(",") if origin.strip()],
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(Exception)
async def unexpected_error_handler(_, exc: Exception):
    logging.getLogger(__name__).exception("Unhandled API error", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Analysis failed unexpectedly"})


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, str]:
    """Human-friendly service status for hosting-platform probes and visitors."""
    return {"service": "PhishGuard API", "status": "ok", "docs": "/docs"}


def _educational_advice(brand: str | None, issues: list[dict[str, str]], score: int) -> str:
    if brand:
        domains = ", ".join(sorted(BRAND_DOMAINS[brand]))
        identity = f"A legitimate {brand.title()} message should use an official domain such as {domains}"
    else:
        identity = "A legitimate message should come from a domain you already know and can verify independently"
    categories = {issue["category"] for issue in issues if issue["severity"] != "Informational"}
    reasons = ", ".join(sorted(categories)[:4])
    if score >= 65:
        action = "Do not click links, download attachments, reply, or provide information. Contact the organization through its official app or a bookmarked website."
    elif score >= 30:
        action = "Verify the request using a trusted phone number or official website before interacting with the message."
    else:
        action = "No strong phishing pattern was found, but independently verify unexpected requests and never share passwords or one-time codes."
    detail = f" The scan was influenced by: {reasons}." if reasons else ""
    return f"{identity}, address you by expected details, and avoid asking for secrets by email.{detail} {action}"


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    # Gatekeeper check is deliberately independent of model and heuristic output.
    def unambiguous_pass(mechanism: str) -> bool:
        verdicts = re.findall(
            rf"\b{mechanism}\s*=\s*(pass|fail|softfail|permerror|neutral|none|temperror)\b",
            payload.header,
            re.IGNORECASE,
        )
        return bool(verdicts) and all(verdict.lower() == "pass" for verdict in verdicts)

    explicit_auth_pass = all(unambiguous_pass(mechanism) for mechanism in ("dmarc", "spf", "dkim"))
    clean_body = clean_email_text(payload.body)
    heuristic = analyze_heuristics(payload.sender, clean_body)
    # Keep original href targets for link inspection; HTML is never passed to NLP or keyword rules.
    urls, url_issues = analyze_urls(payload.body, heuristic.claimed_brand)
    header_score, header_issues, authentication_override = analyze_headers(payload.header, payload.body, heuristic.sender_domain)
    # Authentication is a hard safety gate only when the parser also confirms
    # that the authenticated domains align with the visible sender domain. A
    # confirmed malicious destination remains a higher-priority safety signal:
    # SPF/DKIM/DMARC cannot make a spoofed outbound link safe.
    critical_link_evidence = any(
        issue["severity"] == "Critical"
        and issue["category"] in {"Suspicious link", "Anchor text mismatch"}
        for issue in url_issues
    )
    authentication_gate = explicit_auth_pass and authentication_override and not critical_link_evidence
    ml_score, _ml_error = phishing_probability(f"From: {payload.sender}\n\n{clean_body}")

    issues = heuristic.issues + url_issues + header_issues
    url_score = min(24, sum(12 for url in urls if url["is_suspicious"]))
    # A complete aligned authentication pass is a safety bonus, not merely a neutral signal.
    rule_score = max(0, min(100, heuristic.score + header_score + url_score - (40 if authentication_override else 0)))
    if ml_score is None:
        issues.append({
            "category": "Local AI classifier",
            "severity": "Informational",
            "description": "The local model was unavailable, so the score uses deterministic security checks only.",
        })
        overall = rule_score
    else:
        # Independent controls retain influence even when the statistical model is uncertain.
        weighted_score = round(ml_score * 0.55 + rule_score * 0.45)
        deterministic_floor = min(90, round(rule_score * 0.8))
        overall = min(100, max(weighted_score, deterministic_floor))
        if ml_score >= 65:
            issues.append({
                "category": "Language model signal",
                "severity": "Warning" if ml_score < 80 else "Critical",
                "description": f"The local phishing classifier assigned a {ml_score}% phishing probability.",
            })

    # The local classifier can be overconfident on benign retail support messages
    # (apologies, orders, dispatch and tracking updates). Treat that language as
    # contextual evidence only when every deterministic control is clean. This
    # prevents a routine order update from becoming a high-risk verdict solely
    # because of a statistical false positive.
    commerce_context = re.search(
        r"\b(?:order|shipment|shipped|dispatch(?:ed)?|tracking|delivery|production|loafers?|patience|understanding|support|apolog(?:y|ize|ise)|notify)\b",
        clean_body,
        re.IGNORECASE,
    )
    deterministic_issues = [
        issue for issue in issues
        if issue["severity"] in {"Critical", "Warning"}
        and issue["category"] != "Language model signal"
    ]
    if commerce_context and rule_score == 0 and not deterministic_issues:
        if overall > 18:
            overall = 18
        for issue in issues:
            if issue["category"] == "Language model signal":
                issue["severity"] = "Informational"
                issue["description"] = "The local classifier produced a strong signal, but routine commerce language and clean deterministic checks indicate no corroborating phishing evidence. The signal was conservatively reduced."
        issues.append({
            "category": "Routine commerce context",
            "severity": "Informational",
            "description": "The message uses ordinary order, delivery, or customer-support language without a deterministic phishing signal; the statistical score was conservatively reduced.",
        })

    # Do not let an isolated, overconfident classifier result make a clean
    # message Moderate Risk. For model-only evidence, deterministic controls
    # remain the source of escalation and the statistical signal is advisory.
    if rule_score == 0 and not deterministic_issues and not commerce_context and not any(url["is_suspicious"] for url in urls) and overall > 28:
        overall = 28
        for issue in issues:
            if issue["category"] == "Language model signal":
                issue["severity"] = "Informational"
                issue["description"] = "The local classifier produced a strong signal, but no independent phishing indicators supported it, so the signal was conservatively reduced."
        issues.append({
            "category": "Low-signal message",
            "severity": "Informational",
            "description": "No links, authentication failures, impersonation, urgency, or sensitive-data requests were detected; the model-only result is treated conservatively.",
        })

    # A standalone financial demand should prompt verification, not be treated
    # as confirmed phishing. Escalation remains available when a critical
    # corroborating signal or suspicious destination is present.
    has_money_request = any(issue["category"] == "Direct money request" for issue in issues)
    has_critical_evidence = any(
        issue["severity"] == "Critical" and issue["category"] != "Language model signal"
        for issue in issues
    )
    has_suspicious_url = any(url["is_suspicious"] for url in urls)
    if has_money_request and not has_critical_evidence and not has_suspicious_url and overall > 55:
        overall = 55

    if authentication_gate:
        overall = min(overall, 12)
        print("[AUTH OVERRIDE] DMARC/SPF Passed. Capping risk score to 12%", flush=True)

    # A destination that is confirmed suspicious or mismatched with its
    # visible anchor text is decisive evidence. Keep the verdict Dangerous
    # rather than allowing model weighting to dilute a critical link finding.
    if critical_link_evidence:
        overall = max(overall, 70)

    if overall >= 65:
        risk = "Dangerous Phishing"
    elif overall >= 30:
        risk = "Moderate Risk"
    else:
        risk = "Safe"

    return AnalyzeResponse(
        overall_score=overall,
        risk_level=risk,
        flagged_issues=issues,
        uncloaked_urls=urls,
        educational_advice=_educational_advice(heuristic.claimed_brand, issues, overall),
    )
