"""PhishGuard API.

This backend intentionally performs explainable, local heuristic analysis.
It does not fetch submitted URLs, execute attachments, or expose third-party
API keys. Those integrations belong behind a hardened worker/sandbox in a
production deployment.
"""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.parser import Parser
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


app = FastAPI(
    title="PhishGuard API",
    description="Explainable phishing link and email analysis API.",
    version="1.0.0",
)

# Safe for local development and GitHub Pages-to-localhost testing.
# Restrict this list to the real frontend origin in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^https://[A-Za-z0-9-]+\.github\.io$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

MAX_EMAIL_CHARS = 100_000
MAX_URL_CHARS = 4_096

KNOWN_SAFE_DOMAINS = {
    "google.com",
    "microsoft.com",
    "github.com",
    "apple.com",
    "openai.com",
    "paypal.com",
}
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".cc", ".click", ".zip", ".buzz", ".fit"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly"}
BRAND_WORDS = {"paypal", "microsoft", "google", "apple", "bank", "secure", "verify", "login"}
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".iso", ".apk", ".msi"}


class URLScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_CHARS)


class EmailScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_EMAIL_CHARS)


def finding(kind: str, title: str, body: str) -> dict[str, str]:
    return {"type": kind, "title": title, "body": body}


def result(score: int, target: str, findings: list[dict[str, str]], scan_type: str) -> dict[str, Any]:
    score = max(0, min(99, int(score)))
    if score >= 70:
        label = "High risk"
        summary = "Multiple phishing indicators detected"
        recommendation = "Do not open the link, download files, or enter information. Report the message if possible."
    elif score >= 35:
        label = "Suspicious"
        summary = "Review the evidence before continuing"
        recommendation = "Do not continue until the sender and destination are independently verified."
    else:
        label = "Safe"
        summary = "Low-risk signals detected"
        recommendation = "No obvious phishing indicators were found, but stay cautious with unexpected messages."

    return {
        "score": score,
        "label": label,
        "summary": summary,
        "target": target,
        "scan_type": scan_type,
        "findings": findings,
        "recommendation": recommendation,
        "threat_intelligence": {
            "mode": "simulated",
            "message": "Connect Safe Browsing, VirusTotal, OpenPhish, WHOIS, and URLScan through a secure backend worker for production.",
        },
    }


def normalise_url(raw: str) -> tuple[str, Any] | tuple[None, None]:
    value = raw.strip()
    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, None
    return value, parsed


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_known_safe(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in KNOWN_SAFE_DOMAINS)


def scan_url(raw: str) -> dict[str, Any]:
    value, parsed = normalise_url(raw)
    if not parsed:
        return result(
            88,
            raw.strip(),
            [finding("bad", "Invalid URL format", "Check the address before opening it.")],
            "url",
        )

    host = (parsed.hostname or "").lower()
    full = value.lower()
    findings: list[dict[str, str]] = []
    score = 8
    path_and_query = f"{parsed.path}?{parsed.query}"
    query_values = parse_qs(parsed.query)
    safe_brand = is_known_safe(host)
    has_ip = is_ip_host(host)
    has_at = "@" in raw
    subdomains = max(0, len(host.split(".")) - 2)
    suspicious_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
    shortener = host in URL_SHORTENERS
    brand_imitation = any(word in host and not safe_brand for word in BRAND_WORDS)
    long_url = len(raw) > 90
    query_risk = bool(re.search(r"password|verify|credential|wallet|payment|unlock|urgent", full, re.I))
    unicode_risk = any(ord(char) > 127 for char in host)
    many_hyphens = host.count("-") >= 2

    if parsed.scheme != "https":
        score += 20
        findings.append(finding("warn", "No secure HTTPS connection", "The link does not use encrypted transport."))
    else:
        findings.append(finding("good", "HTTPS is enabled", "The connection is encrypted, but this alone does not prove the site is legitimate."))
    if has_ip:
        score += 30
        findings.append(finding("bad", "IP address used instead of a domain", "Phishing pages often hide behind raw server addresses."))
    if has_at:
        score += 28
        findings.append(finding("bad", "Deceptive @ symbol detected", "Text before @ can disguise the real destination host."))
    if suspicious_tld:
        score += 17
        findings.append(finding("warn", "Higher-risk domain ending", "This TLD has a higher concentration of abuse in the demo dataset."))
    if shortener:
        score += 16
        findings.append(finding("warn", "URL shortener detected", "The final destination is hidden and should be expanded safely."))
    if brand_imitation:
        score += 27
        findings.append(finding("bad", "Possible brand impersonation", "The hostname uses trusted-brand language without matching its official domain."))
    if unicode_risk:
        score += 25
        findings.append(finding("bad", "Non-standard characters in hostname", "This can indicate a homograph or look-alike domain."))
    if long_url:
        score += 9
        findings.append(finding("warn", "Unusually long URL", "Long paths and parameters can conceal a malicious destination."))
    if query_risk:
        score += 12
        findings.append(finding("warn", "Sensitive action keywords found", "The link appears to request verification, payment, or account access."))
    if many_hyphens:
        score += 7
        findings.append(finding("warn", "Multiple hyphens in hostname", "This is a weak signal often seen in look-alike domains."))
    if subdomains > 2:
        score += 10
        findings.append(finding("warn", "Many nested subdomains", "Extra subdomains can make the actual owner harder to recognize."))

    # Keep these variables visible as useful extension points for API adapters.
    _ = path_and_query, query_values

    if safe_brand and not any(item["type"] == "bad" for item in findings):
        score = min(score, 14)
        findings.append(finding("good", "Recognized domain pattern", "The hostname matches a known safe example in this demo."))
    if not any(item["type"] in {"bad", "warn"} for item in findings):
        findings.append(finding("good", "No obvious heuristic issues", "No high-risk URL patterns were found in this local check."))

    return result(score, value, findings, "url")


def header_domain(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)", value)
    return match.group(1).lower().strip(" >") if match else ""


def scan_email(content: str) -> dict[str, Any]:
    parser = Parser(policy=policy.default)
    message = parser.parsestr(content)
    text = content.strip()
    lower = text.lower()
    findings: list[dict[str, str]] = []
    score = 8

    urgency = bool(re.search(r"urgent|immediately|within\s+\d+\s*(hour|minute)|account\s+(suspend|locked)|last\s+warning|action\s+required", text, re.I))
    credential = bool(re.search(r"password|login|sign in|verify your identity|one[- ]time password|otp|ssn|social security|credit card", text, re.I))
    money = bool(re.search(r"refund|prize|winner|invoice|payment|gift card|tax|bank transfer|crypto", text, re.I))
    links = re.findall(r"https?://[^\s>]+", text, flags=re.I)
    from_header = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    authentication = message.get("Authentication-Results", "")
    auth_fail = bool(re.search(r"(spf|dkim|dmarc)\s*=\s*(fail|softfail|none|neutral)", authentication or text, re.I))

    attachment_names: list[str] = []
    for part in message.walk():
        filename = part.get_filename()
        if filename:
            attachment_names.append(filename)
    dangerous_attachment = any(
        PurePosixPath(name.lower()).suffix in DANGEROUS_EXTENSIONS
        or bool(re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js)$", name, re.I))
        for name in attachment_names
    ) or bool(re.search(r"\b[^\s]+\.(exe|scr|vbs|js|bat|cmd|iso|apk|msi)(\b|$)", text, re.I))

    if urgency:
        score += 22
        findings.append(finding("warn", "Urgency or fear language", "The message pressures the recipient to act before thinking."))
    if credential:
        score += 24
        findings.append(finding("bad", "Sensitive information requested", "It mentions credentials, identity data, or payment details."))
    if money:
        score += 15
        findings.append(finding("warn", "Financial or reward lure", "Refund, prize, payment, or money-transfer language was found."))
    if dangerous_attachment:
        score += 28
        names = ", ".join(attachment_names[:3]) if attachment_names else "an executable-looking file"
        findings.append(finding("bad", "Dangerous attachment pattern", f"The message references {names}. Do not open it."))
    if auth_fail:
        score += 23
        findings.append(finding("bad", "Sender authentication failure", "SPF, DKIM, or DMARC reports a failure or missing authentication."))
    elif authentication:
        findings.append(finding("good", "Authentication headers found", "Authentication results are available for a deeper backend check."))
    if from_header and reply_to and header_domain(from_header) != header_domain(reply_to):
        score += 18
        findings.append(finding("bad", "Reply-To domain mismatch", "Replies would be sent to a different domain than the visible sender."))
    if links:
        score += min(12, len(links) * 4)
        findings.append(finding("warn", f"{len(links)} link{'s' if len(links) != 1 else ''} found in message", "Links should be scanned individually before opening."))
    if not findings:
        findings.append(finding("good", "No obvious phishing phrases", "This local check did not find common social-engineering indicators."))

    subject = message.get("Subject") or "Email message"
    return result(score, subject[:200], findings, "email")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "phishguard-api", "mode": "heuristic-demo"}


@app.post("/api/scan/url")
def scan_url_endpoint(payload: URLScanRequest) -> dict[str, Any]:
    return scan_url(payload.url)


@app.post("/api/scan/email")
def scan_email_endpoint(payload: EmailScanRequest) -> dict[str, Any]:
    return scan_email(payload.content)


@app.exception_handler(ValueError)
async def value_error_handler(_, exc: ValueError):
    raise HTTPException(status_code=400, detail=str(exc))
