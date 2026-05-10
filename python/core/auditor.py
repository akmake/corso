"""
Web Security Auditor
--------------------
Comprehensive security audit for web applications.

Checks:
  - Data leaks: emails, phones, credit cards, Israeli IDs, JWTs, API keys, passwords
  - Sensitive file exposure: .env, .git, backups, admin panels, API docs, DB dumps
  - Security headers: HSTS, CSP, X-Frame-Options, CORS, etc.
  - JavaScript secrets: hardcoded keys, passwords, tokens in JS files
  - Cookie security: Secure, HttpOnly, SameSite flags
  - Form security: HTTP submissions, hidden sensitive fields
  - Information disclosure: stack traces, error messages, server version
  - robots.txt mining: hidden sensitive paths
  - CORS misconfiguration
"""

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from core.advanced_auditor import run_advanced_checks, Finding as AdvFinding
from core.cms_scanner import scan_cms, Finding as CmsFinding
from core.tool_runner import is_available, run_tool

log = __import__("logging").getLogger(__name__)

# ── Finding ───────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    severity:       str   # critical | high | medium | low | info
    category:       str
    title:          str
    description:    str
    evidence:       list[str] = field(default_factory=list)
    recommendation: str = ""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Regex patterns ────────────────────────────────────────────────────────────
PAT = {
    "email":        re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]{2,}'),
    "phone_il":     re.compile(r'(?<!\d)(?:(?:\+972|0972|972)[-\s]?)?0?(?:5[0-9]|[234679])[-\s]?\d{3}[-\s]?\d{4}(?!\d)'),
    "credit_card":  re.compile(r'(?<!\d)(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12})(?!\d)'),
    "jwt":          re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "aws_key":      re.compile(r'AKIA[0-9A-Z]{16}'),
    "google_api":   re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "private_key":  re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "password":     re.compile(r'(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key|client_secret|db_pass|database_password)\s*[=:]\s*["\']([^"\']{4,120})["\']'),
    "internal_ip":  re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)'),
    "bitcoin":      re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "ethereum":     re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "html_comment": re.compile(r'<!--(.*?)-->', re.DOTALL),
}

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Env / Config
    ("/.env",                   "critical", "Environment variables"),
    ("/.env.local",             "critical", "Environment variables"),
    ("/.env.production",        "critical", "Environment variables"),
    ("/.env.backup",            "critical", "Environment variables"),
    ("/config.php",             "high",     "PHP config"),
    ("/config.json",            "high",     "Config file"),
    ("/config.yaml",            "high",     "Config file"),
    ("/configuration.php",      "high",     "PHP config"),
    ("/settings.py",            "high",     "Python settings"),
    ("/local_settings.py",      "high",     "Python settings"),
    ("/wp-config.php",          "critical", "WordPress config"),
    ("/web.config",             "high",     "ASP.NET config"),
    ("/application.properties", "high",     "Java config"),
    ("/application.yml",        "high",     "Java config"),
    # Git
    ("/.git/config",            "critical", "Git repository"),
    ("/.git/HEAD",              "critical", "Git repository"),
    ("/.gitignore",             "low",      "Git ignore file"),
    # DB / Backups
    ("/backup.sql",             "critical", "Database backup"),
    ("/dump.sql",               "critical", "Database dump"),
    ("/database.sql",           "critical", "Database file"),
    ("/db.sql",                 "critical", "Database file"),
    ("/backup.zip",             "critical", "Site backup"),
    ("/backup.tar.gz",          "critical", "Site backup"),
    ("/site.zip",               "critical", "Site archive"),
    ("/data.zip",               "critical", "Data archive"),
    # Admin
    ("/admin",                  "medium",   "Admin panel"),
    ("/admin/",                 "medium",   "Admin panel"),
    ("/wp-admin/",              "medium",   "WordPress admin"),
    ("/administrator/",         "medium",   "Admin panel"),
    ("/phpmyadmin/",            "high",     "phpMyAdmin"),
    ("/adminer.php",            "high",     "Adminer DB UI"),
    ("/cpanel",                 "medium",   "cPanel"),
    ("/manage",                 "medium",   "Management panel"),
    # PHP / Debug
    ("/phpinfo.php",            "high",     "PHP info page"),
    ("/info.php",               "high",     "PHP info page"),
    ("/test.php",               "medium",   "Test file"),
    ("/debug",                  "medium",   "Debug endpoint"),
    ("/debug/",                 "medium",   "Debug endpoint"),
    # Cloud credentials
    ("/.aws/credentials",       "critical", "AWS credentials"),
    ("/credentials.json",       "critical", "Credentials file"),
    ("/service-account.json",   "critical", "GCP service account"),
    # API docs
    ("/swagger.json",           "info",     "Swagger API docs"),
    ("/swagger-ui.html",        "info",     "Swagger UI"),
    ("/api-docs",               "info",     "API docs"),
    ("/api/docs",               "info",     "API docs"),
    ("/openapi.json",           "info",     "OpenAPI spec"),
    ("/redoc",                  "info",     "ReDoc API docs"),
    # Potential data endpoints
    ("/api/users",              "high",     "Users API"),
    ("/api/customers",          "high",     "Customers API"),
    ("/api/orders",             "high",     "Orders API"),
    ("/api/v1/users",           "high",     "Users API"),
    ("/api/v1/customers",       "high",     "Customers API"),
    ("/api/admin",              "high",     "Admin API"),
    # Logs
    ("/error.log",              "high",     "Error log"),
    ("/access.log",             "high",     "Access log"),
    ("/debug.log",              "high",     "Debug log"),
    ("/app.log",                "high",     "App log"),
    ("/logs/error.log",         "high",     "Error log"),
    # Server status
    ("/server-status",          "medium",   "Apache server-status"),
    ("/nginx_status",           "medium",   "Nginx status"),
    ("/actuator",               "high",     "Spring Boot Actuator"),
    ("/actuator/env",           "critical", "Spring Boot env"),
    ("/actuator/health",        "info",     "Spring Boot health"),
    # Dependencies (info disclosure)
    ("/composer.json",          "low",      "PHP dependencies"),
    ("/package.json",           "low",      "Node dependencies"),
    ("/requirements.txt",       "low",      "Python dependencies"),
    ("/Gemfile",                "low",      "Ruby dependencies"),
    # Other
    ("/.htaccess",              "low",      "Apache config"),
    ("/.DS_Store",              "low",      "Mac directory listing"),
    ("/crossdomain.xml",        "low",      "Flash crossdomain"),
    ("/sitemap.xml",            "info",     "Sitemap"),
    ("/robots.txt",             "info",     "Robots file"),
]

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "high",
        "rec": "הוסף: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": "medium",
        "rec": "הגדר Content-Security-Policy להגנה מפני XSS ו-injection attacks",
    },
    "x-frame-options": {
        "severity": "medium",
        "rec": "הוסף: X-Frame-Options: DENY (למניעת Clickjacking)",
    },
    "x-content-type-options": {
        "severity": "low",
        "rec": "הוסף: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "low",
        "rec": "הוסף: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "low",
        "rec": "הוסף Permissions-Policy להגבלת גישה ל-browser APIs",
    },
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
}


class WebAuditor:
    def __init__(self, url: str):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url  = url.rstrip("/")
        parsed    = urlparse(self.url)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.domain   = parsed.netloc
        self.findings: list[Finding] = []

    # ── Public entry point ────────────────────────────────────────────────────
    async def full_audit(self) -> dict:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=20,
            verify=False,
        ) as client:
            pages = await self._crawl(client, max_pages=40)

            homepage_html = pages[0]["html"] if pages else ""

            basic, advanced, cms = await asyncio.gather(
                asyncio.gather(
                    self._data_leaks(pages),
                    self._sensitive_paths(client),
                    self._security_headers(client),
                    self._javascript_secrets(client, pages),
                    self._cookie_security(client),
                    self._form_security(pages),
                    self._info_disclosure(client),
                    self._robots_mining(client),
                    self._cors_check(client),
                    self._html_comments(pages),
                    return_exceptions=True,
                ),
                run_advanced_checks(client, pages, self.url),
                scan_cms(client, self.base, homepage_html),
                return_exceptions=True,
            )

            # Merge advanced findings (convert AdvFinding → Finding)
            if isinstance(advanced, list):
                for af in advanced:
                    if isinstance(af, AdvFinding):
                        self.findings.append(Finding(
                            severity=af.severity,
                            category=af.category,
                            title=af.title,
                            description=af.description,
                            evidence=af.evidence,
                            recommendation=af.recommendation,
                        ))

            # Merge CMS findings
            if isinstance(cms, list):
                for cf in cms:
                    if isinstance(cf, CmsFinding):
                        self.findings.append(Finding(
                            severity=cf.severity,
                            category=cf.category,
                            title=cf.title,
                            description=cf.description,
                            evidence=cf.evidence,
                            recommendation=cf.recommendation,
                        ))

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

        # Run Nuclei + Nikto in parallel if available
        external_scans = []
        if is_available("nuclei"):
            external_scans.append(self._run_nuclei())
        if is_available("nikto"):
            external_scans.append(self._run_nikto())
        if external_scans:
            ext_results = await asyncio.gather(*external_scans, return_exceptions=True)
            for result in ext_results:
                if isinstance(result, list):
                    self.findings.extend(result)
            self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

        counts = {s: sum(1 for f in self.findings if f.severity == s)
                  for s in ("critical", "high", "medium", "low", "info")}
        counts["total"]  = len(self.findings)
        counts["pages_crawled"] = len(pages)
        counts["nuclei"] = is_available("nuclei")
        counts["nikto"]  = is_available("nikto")

        return {
            "target":   self.url,
            "domain":   self.domain,
            "summary":  counts,
            "findings": [
                {
                    "severity":       f.severity,
                    "category":       f.category,
                    "title":          f.title,
                    "description":    f.description,
                    "evidence":       f.evidence[:20],
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }

    # ── Nuclei integration (7,000+ vulnerability templates) ───────────────────
    async def _run_nuclei(self) -> list[Finding]:
        """Run Nuclei scanner and convert findings to our Finding format."""
        import json
        _NUCLEI_SEV_MAP = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info",
        }
        findings = []
        try:
            code, stdout, stderr = await run_tool(
                "nuclei",
                [
                    "-u", self.url,
                    "-jsonl",
                    "-severity", "critical,high,medium",
                    "-silent",
                    "-timeout", "10",
                    "-retries", "1",
                    "-no-color",
                    "-rate-limit", "50",
                ],
                timeout=180,
            )
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                sev = _NUCLEI_SEV_MAP.get(
                    entry.get("info", {}).get("severity", "info"), "info"
                )
                template_id = entry.get("template-id", "unknown")
                name = entry.get("info", {}).get("name", template_id)
                matched = entry.get("matched-at", self.url)
                matcher_name = entry.get("matcher-name", "")
                desc = entry.get("info", {}).get("description", "")
                tags = entry.get("info", {}).get("tags", [])
                if isinstance(tags, list):
                    tags = ", ".join(tags)

                evidence = [f"Template: {template_id}"]
                if matched:
                    evidence.append(f"URL: {matched}")
                if matcher_name:
                    evidence.append(f"Matcher: {matcher_name}")
                if tags:
                    evidence.append(f"Tags: {tags}")

                ref = entry.get("info", {}).get("reference", [])
                rec = ""
                if ref:
                    if isinstance(ref, list):
                        rec = "References: " + ", ".join(ref[:3])
                    else:
                        rec = f"Reference: {ref}"

                findings.append(Finding(
                    severity=sev,
                    category=f"Nuclei — {template_id}",
                    title=f"[Nuclei] {name}",
                    description=desc or f"Nuclei template {template_id} matched",
                    evidence=evidence,
                    recommendation=rec,
                ))
        except FileNotFoundError:
            pass
        except Exception as e:
            findings.append(Finding(
                severity="info",
                category="Nuclei",
                title="Nuclei scanner error",
                description=str(e),
            ))
        return findings

    # ── Nikto integration (7,000+ dangerous files/CGIs) ───────────────────────
    async def _run_nikto(self) -> list[Finding]:
        """Run Nikto web server scanner."""
        findings = []
        if not is_available("nikto"):
            return findings
        try:
            code, stdout, stderr = await run_tool(
                "nikto",
                ["-h", self.url, "-Format", "json", "-nointeractive", "-maxtime", "120s"],
                timeout=180,
            )
            import json
            output = stdout.strip()
            if not output:
                return findings
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                # Nikto sometimes outputs non-JSON; parse text lines
                for line in (stdout + stderr).splitlines():
                    line = line.strip()
                    if line.startswith("+") and "OSVDB" in line:
                        findings.append(Finding(
                            severity="medium",
                            category="Nikto",
                            title=f"[Nikto] {line[:80]}",
                            description=line,
                            evidence=[line],
                            recommendation="Review and fix reported issue.",
                        ))
                return findings

            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for v in vulns:
                if isinstance(v, dict):
                    desc = v.get("msg", v.get("description", str(v)))
                    osvdb = v.get("OSVDB", v.get("id", ""))
                    sev = "medium"
                    if any(kw in desc.lower() for kw in ["remote code", "rce", "sql inject"]):
                        sev = "critical"
                    elif any(kw in desc.lower() for kw in ["xss", "directory listing", "backup"]):
                        sev = "high"
                    findings.append(Finding(
                        severity=sev,
                        category=f"Nikto — OSVDB-{osvdb}" if osvdb else "Nikto",
                        title=f"[Nikto] {desc[:80]}",
                        description=desc,
                        evidence=[f"OSVDB: {osvdb}"] if osvdb else [],
                        recommendation="Fix per Nikto recommendation.",
                    ))
        except Exception as e:
            log.debug("Nikto error: %s", e)
        return findings

    _COMMON_PATHS = [
        "/", "/about", "/about-us", "/contact", "/blog", "/news", "/faq",
        "/products", "/services", "/pricing", "/shop", "/store",
        "/login", "/signin", "/signup", "/register", "/logout",
        "/search", "/results",
        "/api", "/api/v1", "/api/v2",
        "/admin", "/dashboard", "/panel", "/manage", "/management",
        "/profile", "/account", "/settings", "/preferences",
        "/help", "/support", "/docs", "/documentation",
        "/terms", "/privacy", "/legal",
        "/careers", "/jobs",
        "/sitemap", "/sitemap.xml",
    ]

    # ── Crawler ───────────────────────────────────────────────────────────────
    async def _crawl(self, client: httpx.AsyncClient, max_pages: int = 50) -> list[dict]:
        # Two-level dedup:
        # path_seen   — URL without query string, prevents crawling same page N times
        # url_fetched — exact URL, prevents duplicate HTTP requests
        path_seen:   set[str] = set()
        url_fetched: set[str] = set()
        queue: deque[str] = deque()
        pages: list[dict] = []

        def _enqueue(url: str, keep_qs: bool = True):
            """Normalise and enqueue a URL if not already seen."""
            if not url:
                return
            # Strip fragment
            url = url.split("#")[0]
            if not url.startswith(("http://", "https://")):
                return
            # Must be same origin
            if not url.startswith(self.base):
                return
            path_key = url.split("?")[0]
            if keep_qs:
                # Keep parameterised URL for SQLi/XSS testing,
                # but only queue it once per path+qs combo
                if url not in url_fetched:
                    queue.append(url)
            else:
                if path_key not in path_seen:
                    path_seen.add(path_key)
                    queue.append(url)

        # ── Seed 1: sitemap.xml ───────────────────────────────────────────────
        sitemap_urls = await self._parse_sitemap(client)
        for u in sitemap_urls[:30]:
            _enqueue(u, keep_qs=False)

        # ── Seed 2: target URL itself ─────────────────────────────────────────
        _enqueue(self.url, keep_qs=False)

        # ── Seed 3: common paths (catches SPAs with no HTML links) ────────────
        for path in self._COMMON_PATHS:
            _enqueue(urljoin(self.base, path), keep_qs=False)

        # ── BFS fetch loop ────────────────────────────────────────────────────
        while queue and len(pages) < max_pages:
            batch: list[str] = []
            while queue and len(batch) < 8:
                url = queue.popleft()
                if url not in url_fetched:
                    url_fetched.add(url)
                    path_seen.add(url.split("?")[0])
                    batch.append(url)

            if not batch:
                break

            fetched = await asyncio.gather(
                *[self._fetch(client, u) for u in batch],
                return_exceptions=True,
            )

            for result in fetched:
                if isinstance(result, Exception) or result is None:
                    continue
                if result["status"] not in (200, 201):
                    continue
                pages.append(result)
                soup = BeautifulSoup(result["html"], "lxml")

                # <a href> — keep query strings for param discovery
                for tag in soup.find_all("a", href=True):
                    href = tag["href"].strip()
                    if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                        continue
                    full = urljoin(result["url"], href)
                    _enqueue(full, keep_qs=True)

                # <form action> — form targets are key for POST-based vuln testing
                for form in soup.find_all("form"):
                    action = (form.get("action") or "").strip()
                    if action:
                        full = urljoin(result["url"], action)
                        _enqueue(full, keep_qs=True)
                    # Build a synthetic GET URL from form inputs for GET forms
                    method = (form.get("method") or "get").lower()
                    if method == "get":
                        params = {}
                        for inp in form.find_all(["input", "select", "textarea"]):
                            name  = inp.get("name")
                            value = inp.get("value", "test")
                            if name and inp.get("type", "text") not in ("submit", "button", "image", "reset", "file", "hidden"):
                                params[name] = value
                        if params and action:
                            from urllib.parse import urlencode
                            synthetic = urljoin(result["url"], action) + "?" + urlencode(params)
                            _enqueue(synthetic, keep_qs=True)

                # Inline <script> — extract URL-like strings (catches SPA routes)
                for script in soup.find_all("script"):
                    if not script.string:
                        continue
                    # Match paths that look like page routes or API endpoints
                    for m in re.finditer(
                        r'["\']((/?[a-zA-Z0-9_-]+){1,6}(?:\?[^"\'<>\s]{1,120})?)["\']',
                        script.string,
                    ):
                        candidate = m.group(1)
                        if candidate.startswith("/") and len(candidate) > 1:
                            _enqueue(urljoin(self.base, candidate), keep_qs=True)

        return pages

    async def _parse_sitemap(self, client: httpx.AsyncClient) -> list[str]:
        """Parse sitemap.xml (and sitemap index) to seed the crawler."""
        urls: list[str] = []
        to_fetch = [f"{self.base}/sitemap.xml", f"{self.base}/sitemap_index.xml"]
        seen_sitemaps: set[str] = set()

        while to_fetch:
            sm_url = to_fetch.pop(0)
            if sm_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sm_url)
            try:
                r = await client.get(sm_url, timeout=8)
                if r.status_code != 200 or "xml" not in r.headers.get("content-type", ""):
                    continue
                # Sitemap index — recurse into child sitemaps
                for m in re.finditer(r'<sitemap>\s*<loc>([^<]+)</loc>', r.text):
                    child = m.group(1).strip()
                    if child not in seen_sitemaps:
                        to_fetch.append(child)
                # Regular sitemap — collect <loc> entries
                for m in re.finditer(r'<loc>([^<]+)</loc>', r.text):
                    loc = m.group(1).strip()
                    if loc.startswith(self.base):
                        urls.append(loc)
            except Exception:
                pass

        return urls

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> dict | None:
        try:
            r = await client.get(url, timeout=15)
            return {
                "url":     url,
                "html":    r.text,
                "headers": dict(r.headers),
                "status":  r.status_code,
                "cookies": list(r.cookies.keys()),
            }
        except Exception:
            return None

    def _add(self, finding: Finding):
        self.findings.append(finding)

    # ── Data leaks ────────────────────────────────────────────────────────────
    async def _data_leaks(self, pages: list[dict]):
        emails, phones, cards, jwts = set(), set(), set(), set()
        aws_keys, google_keys, priv_keys = set(), set(), set()
        passwords, internal_ips = set(), set()

        for page in pages:
            html = page["html"]
            text = BeautifulSoup(html, "lxml").get_text(" ")

            # Emails
            for m in PAT["email"].findall(html):
                if not m.split(".")[-1] in ("png","jpg","gif","svg","css","js","ico","woff","ttf"):
                    emails.add(m)

            # Israeli phones
            for m in PAT["phone_il"].findall(text):
                digits = re.sub(r'\D', '', m)
                if 9 <= len(digits) <= 12:
                    phones.add(m.strip())

            # Credit cards
            for m in PAT["credit_card"].findall(text):
                cards.add(m)

            # JWTs
            for m in PAT["jwt"].findall(html):
                jwts.add(m[:80] + "…")

            # AWS
            for m in PAT["aws_key"].findall(html):
                aws_keys.add(m)

            # Google API
            for m in PAT["google_api"].findall(html):
                google_keys.add(m)

            # Private keys
            if PAT["private_key"].search(html):
                priv_keys.add(page["url"])

            # Passwords / secrets in source
            _pw_skip = {"true", "false", "null", "undefined", "none", "", "''", '""', "[object object]"}
            for keyword, value in PAT["password"].findall(html):
                if value.lower() not in _pw_skip and len(value) > 3:
                    passwords.add(f"{keyword} = '{value[:60]}'\n  📍 נמצא ב: {page['url']}")

            # Internal IPs
            for m in PAT["internal_ip"].findall(html):
                internal_ips.add(m)

        if emails:
            self._add(Finding("high", "data_leak",
                f"אימיילים חשופים ({len(emails)})",
                "כתובות אימייל נמצאו בקוד HTML — ייתכן שמדובר בנתוני לקוחות או ספקים.",
                sorted(emails)[:30],
                "הסר אימיילים מ-HTML. שלח אותם בצד שרת בלבד."))

        if phones:
            self._add(Finding("high", "data_leak",
                f"מספרי טלפון חשופים ({len(phones)})",
                "מספרי טלפון ישראלים נמצאו בדפי האתר — בדוק אם שייכים ללקוחות.",
                sorted(phones)[:20],
                "אל תכלול מספרי טלפון של לקוחות ב-HTML ציבורי."))

        if cards:
            self._add(Finding("critical", "data_leak",
                f"מספרי כרטיס אשראי חשופים ({len(cards)}) ⚠️",
                "נמצאו תבניות של מספרי כרטיסי אשראי! הפרת PCI-DSS — עלול לגרור קנסות חמורים.",
                [f"**** **** **** {c[-4:]}" for c in cards],
                "הסר מיידית. אין לשמור/להציג מספרי כרטיס. פנה ל-PCI compliance."))

        if jwts:
            self._add(Finding("critical", "data_leak",
                f"JWT Tokens חשופים ({len(jwts)})",
                "טוקני JWT חשופים ב-HTML — תוקף יכול להתחזות למשתמשים.",
                list(jwts)[:5],
                "אל תכלול טוקנים ב-HTML. השתמש ב-HttpOnly cookies."))

        if aws_keys:
            self._add(Finding("critical", "secrets",
                f"AWS Access Keys חשופים ({len(aws_keys)}) ⚠️",
                "מפתחות AWS נמצאו בקוד! תוקף יכול לגשת לכל שירותי ה-AWS שלך ולגרום נזק כלכלי.",
                list(aws_keys),
                "בטל מיידית ב-AWS Console. השתמש ב-IAM roles במקום keys."))

        if google_keys:
            self._add(Finding("high", "secrets",
                f"Google API Keys חשופים ({len(google_keys)})",
                "מפתחות Google API בקוד הפרונטאנד — ניתן לנצל לחיובים על חשבונך.",
                list(google_keys),
                "הגבל ב-Google Console לדומיינים ספציפיים. שקול להעביר לבקאנד."))

        if priv_keys:
            self._add(Finding("critical", "secrets",
                "מפתחות פרטיים (Private Keys) חשופים ⚠️",
                "נמצאו מפתחות קריפטוגרפיים פרטיים — מאפשר גישה מלאה לתקשורת מוצפנת.",
                list(priv_keys),
                "הסר מיידית ובטל/חדש את כל המפתחות הרלוונטיים."))

        if passwords:
            self._add(Finding("critical", "secrets",
                f"סיסמאות/מפתחות Hardcoded ({len(passwords)})",
                "נמצאו credentials בקוד המקור הציבורי — גישה מיידית לתוקף.",
                list(passwords)[:10],
                "הסר הכל לחלוטין. השתמש ב-environment variables ו-secrets manager."))

        if internal_ips:
            self._add(Finding("medium", "info_disclosure",
                f"כתובות IP פנימיות חשופות ({len(internal_ips)})",
                "כתובות IP פנימיות חושפות את מבנה הרשת הפנימית.",
                sorted(internal_ips),
                "הסר IP פנימיים מכל תגובה ציבורית."))

    # ── Sensitive paths ───────────────────────────────────────────────────────
    async def _sensitive_paths(self, client: httpx.AsyncClient):
        # Fetch a guaranteed-404 baseline to detect SPA catch-all (returns index.html for every URL)
        baseline_len = None
        baseline_snippet = None
        try:
            rand_path = f"/webint-no-such-path-{id(self)}"
            b = await client.get(self.base + rand_path, timeout=8)
            if b.status_code == 200:
                baseline_len = len(b.text)
                baseline_snippet = b.text[:200]
        except Exception:
            pass

        def _is_spa_catchall(r) -> bool:
            if baseline_len is None:
                return False
            # Same length (±50 bytes) → same page
            if abs(len(r.text) - baseline_len) < 50:
                return True
            # Same opening HTML snippet
            if baseline_snippet and r.text[:200] == baseline_snippet:
                return True
            return False

        spa_filtered: list[str] = []

        async def _probe(path: str, severity: str, description: str):
            try:
                r = await client.get(self.base + path, timeout=8)
                if r.status_code == 200 and _is_spa_catchall(r):
                    spa_filtered.append(path)
                    return
                if r.status_code in (200, 403):
                    sev  = severity if r.status_code == 200 else "low"
                    note = "גישה נחסמה (403)" if r.status_code == 403 else f"נגיש! HTTP {r.status_code}"
                    evidence = [f"{self.base}{path} → HTTP {r.status_code}"]
                    if r.status_code == 200:
                        body = r.text[:2000].strip()
                        if body:
                            evidence.append("--- תוכן התגובה (2000 תווים ראשונים) ---")
                            evidence.append(body)
                    self._add(Finding(sev, "exposure",
                        f"{description} חשוף: {path}",
                        f"הקובץ/נתיב {path} קיים בשרת ({note}).",
                        evidence,
                        f"חסום גישה ל-{path} בהגדרות השרת. מחק אם אינו נחוץ."))
            except Exception:
                pass

        await asyncio.gather(
            *[_probe(p, s, d) for p, s, d in SENSITIVE_PATHS],
            return_exceptions=True,
        )

        if spa_filtered:
            self._add(Finding("info", "exposure",
                f"SPA catch-all זוהה — {len(spa_filtered)} נתיבים סוננו (false positives)",
                "האתר מחזיר HTTP 200 + אותו index.html לכל URL לא קיים (React/Vue/Angular SPA). "
                "הנתיבים הבאים נראו כ-200 OK אך אינם קיימים באמת — הוסרו מהתוצאות:",
                spa_filtered[:30],
                "אין פעולה נדרשת בנושא זה. הנתיבים אינם קיימים על השרת."))

    # ── Security headers ──────────────────────────────────────────────────────
    async def _security_headers(self, client: httpx.AsyncClient):
        try:
            r = await client.get(self.url)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            for header, meta in REQUIRED_HEADERS.items():
                if header not in hdrs:
                    self._add(Finding(meta["severity"], "headers",
                        f"חסר Header אבטחה: {header}",
                        f"ה-Header '{header}' חסר — חושף לסוגי התקפות ספציפיים.",
                        [],
                        meta["rec"]))

            # Server version
            server = hdrs.get("server", "")
            if server and any(c.isdigit() for c in server):
                self._add(Finding("low", "info_disclosure",
                    f"גרסת שרת חשופה: {server}",
                    "גרסת השרת חשופה — מאפשרת לתוקף למצוא CVEs ספציפיים.",
                    [f"Server: {server}"],
                    "Nginx: server_tokens off | Apache: ServerTokens Prod"))

            # X-Powered-By
            powered = hdrs.get("x-powered-by", "")
            if powered:
                self._add(Finding("low", "info_disclosure",
                    f"X-Powered-By חשוף: {powered}",
                    "הטכנולוגיה הפנימית חשופה — מסייעת לפינגרפרינטינג.",
                    [f"X-Powered-By: {powered}"],
                    "הסר: header_always unset X-Powered-By"))

            # HTTP (not HTTPS)
            if self.url.startswith("http://"):
                self._add(Finding("high", "headers",
                    "האתר נגיש ב-HTTP ללא הצפנה",
                    "תעבורה לא מוצפנת — ניתן ליירט נתוני לקוחות (Man-in-the-Middle).",
                    [self.url],
                    "הפנה את כל HTTP ל-HTTPS. הגדר HSTS."))

        except Exception:
            pass

    # ── JavaScript secrets ────────────────────────────────────────────────────
    async def _javascript_secrets(self, client: httpx.AsyncClient, pages: list[dict]):
        js_urls: set[str] = set()
        for page in pages:
            soup = BeautifulSoup(page["html"], "lxml")
            for tag in soup.find_all("script", src=True):
                src = tag["src"]
                if src.startswith("http") and self.domain in src:
                    js_urls.add(src)
                elif src.startswith("/"):
                    js_urls.add(urljoin(self.base, src))

        found: list[str] = []
        for js_url in list(js_urls)[:25]:
            try:
                r = await client.get(js_url, timeout=10)
                js = r.text
                for keyword, value in PAT["password"].findall(js):
                    val_lower = value.lower()
                    kw_lower = keyword.lower().replace("_", "")
                    # Skip placeholders: value equals keyword, looks like a variable name, or is a known dummy
                    if val_lower in ("true", "false", "null", "undefined", "none", "", "xxx", "***"):
                        continue
                    if val_lower == keyword.lower() or val_lower.replace("_", "") == kw_lower:
                        continue
                    if val_lower in ("your_token", "your_key", "your_secret", "changeme",
                                     "placeholder", "example", "test", "demo", "sample",
                                     "insert_here", "enter_here", "fill_in"):
                        continue
                    if len(value) < 6:
                        continue
                    found.append(f"{keyword} = '{value[:60]}'\n  📄 {js_url.split('/')[-1]}")
                for m in PAT["aws_key"].findall(js):
                    found.append(f"AWS key in JS: {m}")
                for m in PAT["google_api"].findall(js):
                    found.append(f"Google API key in JS: {m}")
                if PAT["private_key"].search(js):
                    found.append(f"Private key in JS: {js_url}")
            except Exception:
                pass

        if found:
            self._add(Finding("critical", "secrets",
                f"סודות בקבצי JavaScript ({len(found)})",
                "Credentials, API keys או סיסמאות נמצאו בקבצי JS ציבוריים!",
                found[:15],
                "אין לשמור secrets בפרונטאנד. כל שימוש ב-API keys — בבקאנד בלבד."))

    # ── Cookie security ───────────────────────────────────────────────────────
    async def _cookie_security(self, client: httpx.AsyncClient):
        try:
            r = await client.get(self.url)
            raw_cookies = [v for k, v in r.headers.multi_items()
                           if k.lower() == "set-cookie"]

            for cookie_str in raw_cookies:
                lower  = cookie_str.lower()
                name   = cookie_str.split("=")[0].strip()

                if "secure" not in lower:
                    self._add(Finding("medium", "cookies",
                        f"Cookie ללא Secure flag: {name}",
                        f"ה-cookie '{name}' יכול להישלח ב-HTTP בלתי מוצפן.",
                        [cookie_str[:120]],
                        "הוסף Secure flag לכל הcookies."))

                is_auth = any(s in name.lower() for s in
                              ["session","token","auth","user","sid","login","jwt"])
                if is_auth and "httponly" not in lower:
                    self._add(Finding("high", "cookies",
                        f"Cookie אימות ללא HttpOnly: {name}",
                        f"ה-cookie '{name}' נגיש ל-JavaScript — גניבה ע\"י XSS.",
                        [cookie_str[:120]],
                        "הוסף HttpOnly לכל cookies של authentication/session."))

                if "samesite" not in lower:
                    self._add(Finding("low", "cookies",
                        f"Cookie ללא SameSite: {name}",
                        f"ה-cookie '{name}' חשוף להתקפות CSRF.",
                        [cookie_str[:120]],
                        "הוסף SameSite=Strict או SameSite=Lax."))
        except Exception:
            pass

    # ── Form security ─────────────────────────────────────────────────────────
    async def _form_security(self, pages: list[dict]):
        for page in pages:
            soup = BeautifulSoup(page["html"], "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", "")

                if action.startswith("http://"):
                    self._add(Finding("high", "forms",
                        "טופס שולח נתונים ב-HTTP",
                        f"טופס בדף {page['url']} שולח ל-{action} ללא הצפנה.",
                        [f'action="{action}"'],
                        "שנה את כל ה-form actions ל-HTTPS."))

                for hidden in form.find_all("input", type="hidden"):
                    name  = (hidden.get("name") or "").lower()
                    value = hidden.get("value", "")
                    if any(s in name for s in ["secret","key","password","token"]) and len(value) > 4:
                        self._add(Finding("medium", "forms",
                            f"שדה hidden עם ערך רגיש: {name}",
                            f"שדה נסתר '{name}' מכיל ערך גלוי ב-HTML source.",
                            [f'name={name} value={value[:25]}…'],
                            "ודא שערכים רגישים לא חשופים ב-HTML."))

    # ── Error / info disclosure ───────────────────────────────────────────────
    async def _info_disclosure(self, client: httpx.AsyncClient):
        probes = [
            ("/this-page-does-not-exist-xyz-audit", "404 handler"),
            ("/?id=1'",                             "SQL injection probe"),
            ("/api/nonexistent-audit",              "API 404 handler"),
        ]
        ERROR_INDICATORS = [
            ("stack trace",                 "Stack trace"),
            ("traceback (most recent call", "Python traceback"),
            ("exception in thread",         "Java exception"),
            ("syntax error",                "SQL syntax error"),
            ("mysql_fetch",                 "MySQL error"),
            ("pg_query",                    "PostgreSQL error"),
            ("ora-",                        "Oracle error"),
            ("microsoft ole db",            "MSSQL error"),
            ("warning: include",            "PHP include warning"),
            ("call to undefined function",  "PHP error"),
            ("undefined variable",          "PHP warning"),
        ]
        for path, label in probes:
            try:
                r = await client.get(self.base + path, timeout=8)
                body_lower = r.text.lower()
                for indicator, title in ERROR_INDICATORS:
                    if indicator in body_lower:
                        self._add(Finding("high", "info_disclosure",
                            f"{title} חשוף בהודעת שגיאה ({label})",
                            "הודעות שגיאה חושפות מידע פנימי — מסייע מאוד לתוקפים.",
                            [f"נמצא ב: {self.base}{path}"],
                            "הצג שגיאות גנריות למשתמש. כתוב פרטים ל-logs בלבד."))
                        break
            except Exception:
                pass

    # ── robots.txt mining ─────────────────────────────────────────────────────
    async def _robots_mining(self, client: httpx.AsyncClient):
        try:
            r = await client.get(f"{self.base}/robots.txt", timeout=8)
            if r.status_code != 200:
                return

            sensitive_keywords = [
                "admin", "api", "user", "customer", "order", "backup",
                "private", "secret", "config", "internal", "staging", "dev",
                "panel", "dashboard", "manage", "login", "auth", "token",
                "upload", "file", "db", "database", "export", "report",
            ]

            # Parse all Disallow paths
            disallowed = []
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") and ":" in line:
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and "*" not in path:
                        disallowed.append(path)

            if not disallowed:
                return

            # Report interesting keyword matches
            hits = [p for p in disallowed if any(kw in p.lower() for kw in sensitive_keywords)]
            if hits:
                self._add(Finding("info", "exposure",
                    f"robots.txt חושף {len(hits)} נתיבים רגישים",
                    "robots.txt הוא ציבורי — כל תוקף קורא אותו ראשון. הנתיבים ב-Disallow "
                    "הם המפה לאזורים הכי מעניינים באתר.",
                    hits[:20],
                    "robots.txt לא מגן על כלום. אל תסמוך עליו כהגנה — "
                    "חסום גישה בשרת לכל נתיב רגיש."))

            # ── KEY IMPROVEMENT: probe ALL disallowed paths ──────────────────
            # robots.txt tells us exactly what the admin wants to hide —
            # those are the most interesting targets to actively test.
            accessible: list[str] = []

            async def _probe_path(path: str):
                try:
                    pr = await client.get(
                        f"{self.base}{path}", timeout=6, follow_redirects=False
                    )
                    # 200 = accessible content, 403 = exists but blocked (still worth noting)
                    if pr.status_code == 200 and len(pr.text) > 100:
                        accessible.append(
                            f"{path} → HTTP 200 ({len(pr.text):,} bytes)"
                        )
                    elif pr.status_code == 403:
                        # 403 just means server-side block — robots.txt is redundant
                        pass
                except Exception:
                    pass

            await asyncio.gather(
                *[_probe_path(p) for p in disallowed[:40]],
                return_exceptions=True,
            )

            if accessible:
                self._add(Finding("high", "exposure",
                    f"נתיבי robots.txt Disallow נגישים ({len(accessible)})",
                    "נתיבים שה-robots.txt ביקש לא לסרוק — נגישים ומחזירים תוכן! "
                    "robots.txt הוא הנחיה בלבד לbots ולא הגנה. תוקפים תמיד קוראים אותו ראשון.",
                    accessible[:20],
                    "חסום גישה לנתיבים אלו בשרת (Nginx/Apache). "
                    "אל תסמוך על robots.txt כמנגנון הגנה."))

        except Exception:
            pass

    # ── CORS ──────────────────────────────────────────────────────────────────
    async def _cors_check(self, client: httpx.AsyncClient):
        try:
            r = await client.get(
                self.url,
                headers={**HEADERS, "Origin": "https://evil-attacker.com"},
                timeout=8,
            )
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                self._add(Finding("medium", "cors",
                    "CORS Wildcard — כל אתר יכול לבצע בקשות",
                    "Access-Control-Allow-Origin: * מאפשר לכל דומיין לקרוא תגובות API שלך.",
                    [f"Access-Control-Allow-Origin: {acao}"],
                    "הגדר רשימת מקורות מורשים במפורש."))

            elif acao == "https://evil-attacker.com":
                self._add(Finding("high", "cors",
                    "CORS Origin Reflection — חולשה חמורה",
                    "השרת מחזיר כל Origin שנשלח כמורשה — מאפשר גניבת נתונים מכל אתר.",
                    [f"Sent: evil-attacker.com → Reflected: {acao}"],
                    "אמת whitelist של מקורות מורשים בלבד."))

            if acao and acac.lower() == "true":
                self._add(Finding("medium", "cors",
                    "CORS עם Credentials פעיל",
                    "CORS עם Allow-Credentials מאפשר שליחת session cookies לדומיינים אחרים.",
                    [f"ACAO: {acao} | ACAC: {acac}"],
                    "ודא שרק דומיינים ידועים ומהימנים מורשים עם credentials."))
        except Exception:
            pass

    # ── HTML comments ─────────────────────────────────────────────────────────
    async def _html_comments(self, pages: list[dict]):
        """Find sensitive information accidentally left in HTML comments."""
        sensitive_in_comments: list[str] = []
        sensitive_kw = [
            "password","passwd","secret","token","api","key","debug","todo",
            "fixme","hack","credential","database","db_pass","admin",
        ]
        for page in pages:
            for comment in PAT["html_comment"].findall(page["html"]):
                comment_lower = comment.lower()
                if any(kw in comment_lower for kw in sensitive_kw):
                    snippet = comment.strip()[:100]
                    sensitive_in_comments.append(f"[{page['url']}] <!-- {snippet}… -->")

        if sensitive_in_comments:
            self._add(Finding("medium", "info_disclosure",
                f"מידע רגיש בהערות HTML ({len(sensitive_in_comments)})",
                "נמצאו הערות HTML עם מילות מפתח רגישות — לעיתים מכילות passwords, TODOs, או מידע פנימי.",
                sensitive_in_comments[:10],
                "הסר כל הערת HTML לפני production. בדוק את כל ה-comments."))
