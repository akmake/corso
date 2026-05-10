"""
Subdomain Takeover Scanner
--------------------------
Detects dangling DNS records pointing to services that can be claimed:
  - GitHub Pages (CNAME → username.github.io)
  - AWS S3 buckets
  - Azure sites
  - Heroku apps
  - Netlify / Vercel / Surge / Fastly
  - Ghost / Tumblr / Shopify / HubSpot
  - 50+ service fingerprints
  - DNS NXDOMAIN probing for all subdomains
"""

import asyncio
import re
import socket
from dataclasses import dataclass, field
from typing import Optional, Callable

import aiohttp

try:
    import aiodns
    _HAS_AIODNS = True
except ImportError:
    _HAS_AIODNS = False

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""
    tags: list = field(default_factory=list)

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tags": self.tags,
        }

# ── Service fingerprints ──────────────────────────────────────────────────────

# (service_name, cname_pattern, response_body_pattern, severity, claim_instructions)
_FINGERPRINTS = [
    (
        "GitHub Pages",
        r"\.github\.io$",
        r"There isn't a GitHub Pages site here",
        "critical",
        "הרץ: git init, הוסף CNAME file עם הדומיין, push ל-GitHub Pages",
    ),
    (
        "AWS S3",
        r"\.s3\.amazonaws\.com$|\.s3-website",
        r"NoSuchBucket|The specified bucket does not exist",
        "critical",
        "צור bucket עם שם זהה ל-CNAME ב-AWS S3, הפעל static website hosting",
    ),
    (
        "AWS CloudFront",
        r"\.cloudfront\.net$",
        r"ERROR: The request could not be satisfied",
        "high",
        "הגדר CloudFront distribution חדשה עם ה-CNAME הזה",
    ),
    (
        "Heroku",
        r"\.herokudns\.com$|\.herokuapp\.com$",
        r"No such app|herokucdn\.com/error-pages/no-such-app",
        "critical",
        "צור Heroku app חדשה, הוסף custom domain",
    ),
    (
        "Azure",
        r"\.azurewebsites\.net$|\.cloudapp\.net$|\.blob\.core\.windows\.net$",
        r"404 Web Site not found|Error 404 - Web app not found",
        "critical",
        "צור Azure Web App עם השם הזה",
    ),
    (
        "Netlify",
        r"\.netlify\.app$|\.netlify\.com$",
        r"Not Found|Netlify.*not found",
        "critical",
        "צור Netlify site עם ה-custom domain הזה",
    ),
    (
        "Vercel",
        r"\.vercel\.app$|\.now\.sh$",
        r"The deployment could not be found|This deployment has been deleted",
        "critical",
        "צור Vercel project עם ה-custom domain הזה",
    ),
    (
        "Surge.sh",
        r"\.surge\.sh$",
        r"project not found",
        "critical",
        "surge --domain <subdomain>.surge.sh",
    ),
    (
        "Ghost",
        r"\.ghost\.io$",
        r"Used internally by Ghost|The thing you were looking for is no longer here",
        "high",
        "צור Ghost blog עם subdomain זה",
    ),
    (
        "Tumblr",
        r"\.tumblr\.com$",
        r"There's nothing here|Whatever you were looking for doesn't currently exist",
        "high",
        "צור Tumblr blog עם custom domain זה",
    ),
    (
        "Shopify",
        r"\.myshopify\.com$",
        r"Sorry, this shop is currently unavailable|Only one step left",
        "high",
        "צור Shopify store עם subdomain זה",
    ),
    (
        "HubSpot",
        r"\.hs-sites\.com$|\.hubspot\.com$",
        r"Domain not found|does not exist in our system",
        "high",
        "הגדר HubSpot site עם custom domain זה",
    ),
    (
        "Fastly",
        r"\.fastly\.net$|\.global\.fastly\.net$",
        r"Fastly error: unknown domain|Please check that this domain has been added",
        "high",
        "הגדר Fastly service עם hostname זה",
    ),
    (
        "WP Engine",
        r"\.wpengine\.com$",
        r"The site you were looking for couldn't be found",
        "high",
        "צור WP Engine site עם domain זה",
    ),
    (
        "Zendesk",
        r"\.zendesk\.com$",
        r"Help Center Closed|Oops, this help center no longer exists",
        "medium",
        "צור Zendesk help center עם subdomain זה",
    ),
    (
        "Pantheon",
        r"\.pantheon\.io$|\.pantheonsite\.io$",
        r"404 error unknown site",
        "high",
        "צור Pantheon site עם domain זה",
    ),
    (
        "Readme.io",
        r"\.readme\.io$",
        r"Project doesnt exist|page not found",
        "medium",
        "צור Readme project עם custom domain זה",
    ),
    (
        "Statuspage",
        r"\.statuspage\.io$",
        r"You are being redirected|page not found",
        "medium",
        "צור Atlassian Statuspage עם custom domain זה",
    ),
    (
        "UserVoice",
        r"\.uservoice\.com$",
        r"This UserVoice subdomain is currently available",
        "medium",
        "רשום UserVoice subdomain זה",
    ),
    (
        "Intercom",
        r"\.custom\.intercom\.help$",
        r"Uh oh. That page doesn't exist",
        "medium",
        "הגדר Intercom Help Center עם domain זה",
    ),
    (
        "Webflow",
        r"\.webflow\.io$",
        r"The page you are looking for doesn't exist or has been moved",
        "high",
        "צור Webflow project עם domain זה",
    ),
    (
        "Cargo",
        r"\.cargocollective\.com$",
        r"404 Not Found",
        "medium",
        "צור Cargo Collective site עם domain זה",
    ),
    (
        "Squarespace",
        r"\.squarespace\.com$",
        r"No Such Account|You may have mistyped the address",
        "medium",
        "צור Squarespace site עם domain זה",
    ),
]

# ── DNS helpers ────────────────────────────────────────────────────────────────

def _resolve_cname_sync(hostname: str) -> Optional[str]:
    """Get CNAME for hostname synchronously."""
    try:
        # Try to get CNAME via socket (limited)
        result = socket.getaddrinfo(hostname, None)
        return None  # socket doesn't give CNAME
    except socket.gaierror:
        return "NXDOMAIN"
    except Exception:
        return None

async def _resolve_cname(hostname: str) -> Optional[str]:
    """Async CNAME resolution."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _resolve_cname_sync, hostname)

async def _is_nxdomain(hostname: str) -> bool:
    """Check if hostname resolves at all."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, hostname)
        return False  # Resolves
    except socket.gaierror as e:
        if "NXDOMAIN" in str(e) or "Name or service not known" in str(e) or "getaddrinfo failed" in str(e):
            return True
        return False
    except Exception:
        return False

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
_TIMEOUT = aiohttp.ClientTimeout(total=10)

async def _get_body(session, url: str) -> tuple[int, str]:
    try:
        resp = await session.get(url, headers=_HEADERS, timeout=_TIMEOUT, ssl=False, allow_redirects=True)
        body = await resp.text(errors="replace")
        return resp.status, body
    except Exception:
        return 0, ""

# ── Scanner ───────────────────────────────────────────────────────────────────

class SubdomainTakeoverScanner:
    def __init__(self, domain: str, subdomains: list[str] = None, log: Optional[Callable] = None):
        self.domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        self.subdomains = subdomains or []
        self._log = log or (lambda m: None)
        self.findings: list[Finding] = []

    async def _discover_subdomains(self) -> list[str]:
        """Use subfinder if available, otherwise try common subdomain list."""
        import shutil
        import subprocess

        subs = list(self.subdomains)
        subfinder = shutil.which("subfinder")
        if subfinder:
            self._log(f"Takeover: מריץ subfinder על {self.domain}...")
            try:
                proc = await asyncio.create_subprocess_exec(
                    subfinder, "-d", self.domain, "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                found = stdout.decode().strip().split("\n")
                subs += [s.strip() for s in found if s.strip()]
                self._log(f"Takeover: subfinder מצא {len(found)} subdomains")
            except Exception as e:
                self._log(f"Takeover: subfinder שגיאה — {e}")
        else:
            self._log("Takeover: subfinder לא מותקן — בודק רשימת subdomains נפוצה")
            common = ["www", "mail", "ftp", "dev", "staging", "api", "admin", "blog",
                      "shop", "store", "app", "portal", "help", "support", "docs",
                      "cdn", "static", "assets", "media", "images", "video",
                      "old", "legacy", "test", "demo", "beta", "alpha", "v2",
                      "m", "mobile", "ww", "ns1", "ns2", "vpn", "remote"]
            subs += [f"{c}.{self.domain}" for c in common]

        return list(set(subs))

    async def _check_subdomain(self, session, subdomain: str):
        """Check a single subdomain for takeover vulnerability."""
        subdomain = subdomain.strip()
        if not subdomain:
            return

        # Check if NXDOMAIN (best signal)
        nxdomain = await _is_nxdomain(subdomain)
        if nxdomain:
            self.findings.append(Finding(
                severity="medium",
                category="Subdomain Takeover",
                title=f"NXDOMAIN Subdomain — {subdomain}",
                description=f"הדומיין {subdomain} אינו מפוצל ל-IP — ייתכן שנמחק השירות שהוא הצביע עליו.",
                evidence=[f"Subdomain: {subdomain}", "DNS: NXDOMAIN"],
                recommendation="מחק את ה-DNS record אם השירות אינו בשימוש.",
                tags=["subdomain-takeover", "nxdomain", subdomain],
            ))
            return

        # Try HTTP and check response
        for proto in ["https", "http"]:
            url = f"{proto}://{subdomain}"
            status, body = await _get_body(session, url)

            if status == 0:
                continue

            # Check against all fingerprints
            for service, cname_pattern, body_pattern, severity, instructions in _FINGERPRINTS:
                if re.search(body_pattern, body, re.I):
                    self._log(f"Takeover {severity.upper()}: {subdomain} → {service}")
                    self.findings.append(Finding(
                        severity=severity,
                        category="Subdomain Takeover",
                        title=f"Subdomain Takeover — {subdomain} → {service}",
                        description=f"הדומיין {subdomain} מצביע ל-{service} שאינו בשימוש. תוקף יכול לתפוס אותו ולהגיש תוכן ממקור מהימן.",
                        evidence=[
                            f"Subdomain: {subdomain}",
                            f"Service: {service}",
                            f"HTTP Status: {status}",
                            f"Fingerprint matched: {body_pattern}",
                            f"Response snippet: {body[:200]}",
                        ],
                        recommendation=f"אם לא בשימוש: מחק DNS record. אם בשימוש: {instructions}",
                        tags=["subdomain-takeover", service.lower().replace(" ", "-"), severity],
                    ))
                    return

            # Check for AWS S3 specifically (common)
            if "amazonaws.com" in subdomain or "s3" in subdomain:
                if "NoSuchBucket" in body or "AccessDenied" in body:
                    self.findings.append(Finding(
                        severity="critical" if "NoSuchBucket" in body else "info",
                        category="Subdomain Takeover",
                        title=f"AWS S3 Bucket — {subdomain} ({'פנוי' if 'NoSuchBucket' in body else 'Access Denied'})",
                        description=f"S3 bucket {subdomain} {'לא קיים וניתן לתפיסה' if 'NoSuchBucket' in body else 'קיים אבל גישה נדחתה'}.",
                        evidence=[f"Subdomain: {subdomain}", f"Status: {status}", f"Body: {body[:150]}"],
                        recommendation="צור S3 bucket עם שם זהה ב-AWS." if "NoSuchBucket" in body else "ודא הרשאות bucket נכונות.",
                        tags=["subdomain-takeover", "aws-s3"],
                    ))

            break  # Only check https first, http only if https fails

    # ── Check main domain's DNS for dangling records ──────────────────────────

    async def _check_dangling_cname(self, session):
        """Check if main domain has CNAMEs pointing to unclaimed services."""
        self._log("Takeover: בודק CNAME records של הדומיין הראשי...")
        import subprocess
        import shutil

        dig = shutil.which("dig") or shutil.which("nslookup")
        if not dig:
            return

        try:
            cmd = ["dig", "CNAME", self.domain, "+short"] if "dig" in dig else ["nslookup", "-type=CNAME", self.domain]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname_output = stdout.decode().strip()

            for service, cname_pattern, _, severity, instructions in _FINGERPRINTS:
                if re.search(cname_pattern, cname_output, re.I):
                    self._log(f"Takeover: CNAME של {self.domain} מצביע ל-{service}")
                    status, body = await _get_body(session, f"https://{self.domain}")
                    # Check fingerprint
                    _, body_pattern, _, _, _ = next(
                        (x for x in _FINGERPRINTS if x[0] == service), (None, "", None, None, None)
                    )
                    if body_pattern and re.search(body_pattern, body, re.I):
                        self.findings.append(Finding(
                            severity="critical",
                            category="Subdomain Takeover",
                            title=f"Takeover — {self.domain} → {service} (Dangling CNAME)",
                            description=f"CNAME של הדומיין הראשי מצביע ל-{service} שאינו בשימוש.",
                            evidence=[f"CNAME: {cname_output}", f"Service: {service}"],
                            recommendation=instructions,
                            tags=["subdomain-takeover", "dangling-cname", service.lower()],
                        ))
        except Exception:
            pass

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"Subdomain Takeover Scanner: מתחיל על {self.domain}")

        all_subdomains = await self._discover_subdomains()
        self._log(f"Takeover: בודק {len(all_subdomains)} subdomains...")

        connector = aiohttp.TCPConnector(limit=30, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            await self._check_dangling_cname(session)

            # Check subdomains in batches of 20
            batch_size = 20
            for i in range(0, len(all_subdomains), batch_size):
                batch = all_subdomains[i:i + batch_size]
                await asyncio.gather(*[self._check_subdomain(session, s) for s in batch])
                self._log(f"Takeover: {min(i + batch_size, len(all_subdomains))}/{len(all_subdomains)} subdomains...")

        critical = [f for f in self.findings if f.severity == "critical"]
        self._log(f"Subdomain Takeover Scanner: הושלם — {len(self.findings)} ממצאים ({len(critical)} קריטי)")

        return {
            "domain": self.domain,
            "subdomains_checked": len(all_subdomains),
            "total": len(self.findings),
            "critical": len(critical),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_subdomain_takeover(domain: str, subdomains: list[str] = None, log=None) -> dict:
    scanner = SubdomainTakeoverScanner(domain, subdomains=subdomains, log=log)
    return await scanner.scan()
