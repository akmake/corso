"""
Adaptive Security Scanner
=========================
A systematic, multi-phase scanner where each phase's findings drive the next.

Phase 1 — Fingerprinting:  fast recon to understand the attack surface
Phase 2 — Surface mapping:  targeted tests based on what was discovered
Phase 3 — Exploitation:     deep testing based on Phase 2 results
Phase 4 — Chain analysis:   combining findings into attack chains
"""

import asyncio
import re
import ssl
import socket
import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Any
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

import aiohttp

# ── Finding model ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str        # critical / high / medium / low / info
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""
    phase: int = 1
    tags: list = field(default_factory=list)   # e.g. ["sqli", "login-form"]

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "phase": self.phase,
            "tags": self.tags,
        }

# ── Attack chain model ─────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    title: str
    severity: str
    steps: list
    description: str

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "steps": self.steps,
            "description": self.description,
        }

# ── HTTP helpers ───────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
}

async def _get(session: aiohttp.ClientSession, url: str, **kwargs) -> aiohttp.ClientResponse | None:
    try:
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=12))
        kwargs.setdefault("ssl", False)
        kwargs.setdefault("allow_redirects", True)
        return await session.get(url, headers=HEADERS, **kwargs)
    except Exception:
        return None

async def _post(session: aiohttp.ClientSession, url: str, data=None, json_body=None, **kwargs) -> aiohttp.ClientResponse | None:
    try:
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=12))
        kwargs.setdefault("ssl", False)
        return await session.post(url, headers=HEADERS, data=data, json=json_body, **kwargs)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

# ── Main scanner class ─────────────────────────────────────────────────────────

class AdaptiveScanner:
    def __init__(self, url: str, log_fn: Callable[[str], None]):
        parsed = urlparse(url if "://" in url else "https://" + url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.url = url if "://" in url else "https://" + url
        self.domain = parsed.netloc
        self.log = log_fn
        self.findings: list[Finding] = []
        self.surface: dict[str, Any] = {}   # shared state between phases
        self.chains: list[AttackChain] = []

    # ── Public entry point ─────────────────────────────────────────────────────

    async def run(self) -> dict:
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            self.session = session

            self.log("▶ שלב 1/4 — טביעת אצבע ומיפוי פני השטח")
            await self._phase1_fingerprint()

            self.log(f"✔ שלב 1 הושלם — זוהו: {', '.join(self._surface_summary())}")
            self.log("▶ שלב 2/4 — בדיקות ממוקדות לפי מה שהתגלה")
            await self._phase2_targeted()

            self.log("▶ שלב 3/4 — ניסיונות ניצול מעמיקים")
            await self._phase3_exploit()

            self.log("▶ שלב 4/4 — ניתוח שרשראות תקיפה")
            self._phase4_chains()

        findings_dicts = [f.to_dict() for f in self.findings]
        summary = self._summarize(findings_dicts)
        self.log(f"✔ סריקה הושלמה — {summary['total']} ממצאים ({summary['critical']} קריטי, {summary['high']} גבוה)")

        return {
            "findings": findings_dicts,
            "attack_surface": self.surface,
            "chains": [c.to_dict() for c in self.chains],
            "summary": summary,
            "decision_log": self.surface.get("_decisions", []),
        }

    # ── Phase 1: Fingerprinting ────────────────────────────────────────────────

    async def _phase1_fingerprint(self):
        tasks = [
            self._fp_headers(),
            self._fp_common_paths(),
            self._fp_ssl(),
            self._fp_dns(),
            self._fp_technology(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fp_headers(self):
        resp = await _get(self.session, self.url, allow_redirects=True)
        if not resp:
            self._add(Finding("high", "Connectivity", "אתר לא ניתן להגעה", f"לא ניתן להתחבר ל-{self.url}", phase=1))
            return

        hdrs = dict(resp.headers)
        self.surface["status_code"] = resp.status
        self.surface["headers"] = hdrs
        self.surface["final_url"] = str(resp.url)
        self.surface["cookies"] = [c.key for c in self.session.cookie_jar]

        self.log(f"  → HTTP {resp.status} | {self.domain}")

        # Security headers audit
        sec_headers = {
            "Strict-Transport-Security": ("high", "חסר HSTS", "אין אכיפת HTTPS — ניתן לתקיפת Downgrade"),
            "Content-Security-Policy": ("high", "חסר CSP", "ניתן ל-XSS בגלל היעדר Content-Security-Policy"),
            "X-Frame-Options": ("medium", "חסר X-Frame-Options", "פגיע ל-Clickjacking"),
            "X-Content-Type-Options": ("low", "חסר X-Content-Type-Options", "MIME type sniffing אפשרי"),
            "Referrer-Policy": ("low", "חסר Referrer-Policy", "דליפת מידע ב-Referrer header"),
            "Permissions-Policy": ("low", "חסר Permissions-Policy", "גישה לא מוגבלת ל-API-ים של הדפדפן"),
        }
        missing = []
        for h, (sev, title, desc) in sec_headers.items():
            if h.lower() not in {k.lower() for k in hdrs}:
                missing.append(h)
                self._add(Finding(sev, "Security Headers", title, desc,
                                  evidence=[f"Header {h} חסר בתגובה"],
                                  recommendation=f"הוסף את ה-header: {h}",
                                  phase=1, tags=["headers"]))
        self.surface["missing_headers"] = missing

        # Server disclosure
        server = hdrs.get("Server", hdrs.get("server", ""))
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
            self.surface["server_version"] = server
            self._add(Finding("medium", "Information Disclosure", "גרסת שרת חשופה",
                               f"Server header חושף: {server}",
                               evidence=[f"Server: {server}"],
                               recommendation="הסתר גרסת שרת",
                               phase=1, tags=["disclosure"]))

        # X-Powered-By
        powered = hdrs.get("X-Powered-By", hdrs.get("x-powered-by", ""))
        if powered:
            self.surface["powered_by"] = powered
            self._add(Finding("medium", "Information Disclosure", "X-Powered-By חושף טכנולוגיה",
                               f"X-Powered-By: {powered}",
                               evidence=[f"X-Powered-By: {powered}"],
                               recommendation="הסר header זה",
                               phase=1, tags=["disclosure"]))

        # Cookie flags
        for c_header in resp.headers.getall("set-cookie", []):
            c_lower = c_header.lower()
            name = c_header.split("=")[0].strip()
            issues = []
            if "httponly" not in c_lower:
                issues.append("חסר HttpOnly")
            if "secure" not in c_lower and resp.url.scheme == "https":
                issues.append("חסר Secure flag")
            if "samesite" not in c_lower:
                issues.append("חסר SameSite (סיכון CSRF)")
            if issues:
                self._add(Finding("medium", "Cookie Security", f"Cookie לא מאובטח: {name}",
                                   f"ה-cookie {name} חסר: {', '.join(issues)}",
                                   evidence=[f"Set-Cookie: {c_header[:120]}"],
                                   recommendation="הוסף HttpOnly; Secure; SameSite=Strict",
                                   phase=1, tags=["cookie", "csrf"]))

        # CORS
        cors_origin = hdrs.get("Access-Control-Allow-Origin", hdrs.get("access-control-allow-origin", ""))
        if cors_origin == "*":
            self.surface["cors_wildcard"] = True
            self._add(Finding("high", "CORS", "CORS Wildcard — גישה חופשית",
                               "כל אתר יכול לבצע cross-origin requests לאתר זה",
                               evidence=["Access-Control-Allow-Origin: *"],
                               recommendation="הגבל CORS לדומיינים ספציפיים",
                               phase=1, tags=["cors"]))

    async def _fp_common_paths(self):
        self.log("  → בדיקת נתיבים נפוצים")
        probe_paths = [
            # Sensitive files
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
            "/config.php", "/wp-config.php", "/web.config", "/config.yml", "/config.json",
            "/database.yml", "/.htpasswd", "/backup.sql", "/dump.sql",
            # Admin / Login
            "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
            "/login", "/signin", "/dashboard", "/panel", "/cpanel", "/phpmyadmin",
            # API docs
            "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
            "/swagger.json", "/openapi.json", "/api-docs", "/graphql",
            "/api/docs", "/redoc", "/.well-known/security.txt",
            # Info disclosure
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/server-status", "/server-info", "/.DS_Store",
            # Common vulns
            "/xmlrpc.php", "/wp-json/wp/v2/users", "/.git/COMMIT_EDITMSG",
        ]

        found_paths = []
        login_paths = []
        api_paths = []
        git_exposed = False

        async def check_path(path):
            nonlocal git_exposed
            url = self.base_url.rstrip("/") + path
            resp = await _get(self.session, url, allow_redirects=False)
            if not resp:
                return
            if resp.status in (200, 206, 403):
                body = await _text(resp)
                found_paths.append({"path": path, "status": resp.status, "size": len(body)})

                # .git exposed
                if ".git" in path and resp.status == 200:
                    git_exposed = True
                    self._add(Finding("critical", "Source Code Exposure", f"Git repository חשוף: {path}",
                                       "קוד המקור של האתר נגיש לכולם",
                                       evidence=[f"GET {url} → {resp.status}"],
                                       recommendation="חסום גישה לתיקיית .git בהגדרות שרת",
                                       phase=1, tags=["git", "source-code"]))

                # .env exposed
                if ".env" in path and resp.status == 200 and len(body) > 5:
                    self._add(Finding("critical", "Secrets Exposure", f"קובץ סביבה חשוף: {path}",
                                       "קובץ .env חשוף — עלול להכיל API keys, passwords, DB credentials",
                                       evidence=[f"GET {url} → {resp.status}", body[:300]],
                                       recommendation="הסר קבצי .env מה-webroot",
                                       phase=1, tags=["env", "secrets"]))

                # Backup SQL
                if any(x in path for x in [".sql", "backup", "dump"]) and resp.status == 200:
                    self._add(Finding("critical", "Database Exposure", f"קובץ DB גיבוי חשוף: {path}",
                                       "קובץ גיבוי של מסד נתונים נגיש",
                                       evidence=[f"GET {url} → {resp.status} ({len(body)} bytes)"],
                                       recommendation="מחק קבצי גיבוי מה-webroot",
                                       phase=1, tags=["database", "backup"]))

                # API docs
                if any(x in path for x in ["/swagger", "/openapi", "/api-docs", "/graphql"]) and resp.status == 200:
                    api_paths.append(path)
                    self.surface.setdefault("api_endpoints", []).append(url)

                # Login pages
                if any(x in path for x in ["/login", "/signin", "/wp-login", "/admin"]) and resp.status == 200:
                    login_paths.append(url)
                    self.surface.setdefault("login_pages", []).append(url)

                # Server status
                if path in ("/server-status", "/server-info") and resp.status == 200:
                    self._add(Finding("high", "Information Disclosure", f"Apache {path} חשוף",
                                       "מידע רגיש על השרת נגיש",
                                       evidence=[f"GET {url} → 200"],
                                       recommendation=f"חסום גישה ל-{path}",
                                       phase=1, tags=["apache", "disclosure"]))

                # WordPress users API
                if path == "/wp-json/wp/v2/users" and resp.status == 200:
                    try:
                        users = json.loads(body)
                        names = [u.get("slug", u.get("name", "")) for u in users[:5]]
                        self._add(Finding("medium", "WordPress", "WordPress users API חשוף",
                                           f"רשימת משתמשים נגישה: {', '.join(names)}",
                                           evidence=[f"GET {url} → 200", body[:300]],
                                           recommendation="הגבל גישה ל-REST API",
                                           phase=1, tags=["wordpress", "enumeration"]))
                    except Exception:
                        pass

                # phpMyAdmin
                if "phpmyadmin" in path.lower() and resp.status in (200, 403):
                    self._add(Finding("high", "Admin Panel Exposure", "phpMyAdmin חשוף",
                                       "ממשק ניהול DB נגיש מהאינטרנט",
                                       evidence=[f"GET {url} → {resp.status}"],
                                       recommendation="הגבל גישה ל-phpMyAdmin לפי IP",
                                       phase=1, tags=["phpmyadmin", "admin"]))

                # Robots.txt
                if path == "/robots.txt" and resp.status == 200:
                    disallowed = re.findall(r"Disallow:\s*(.+)", body)
                    if disallowed:
                        self.surface["robots_disallow"] = disallowed
                        self._add(Finding("info", "Reconnaissance", "robots.txt חושף נתיבים רגישים",
                                           f"Disallow entries: {disallowed[:10]}",
                                           evidence=disallowed[:10],
                                           recommendation="בדוק שנתיבים אלו מוגנים בנוסף",
                                           phase=1, tags=["robots", "recon"]))

        await asyncio.gather(*[check_path(p) for p in probe_paths], return_exceptions=True)

        self.surface["found_paths"] = found_paths
        self.surface["git_exposed"] = git_exposed
        self.surface["login_pages"] = self.surface.get("login_pages", [])
        self.surface["api_endpoints"] = self.surface.get("api_endpoints", [])

        self.log(f"  → נמצאו {len(found_paths)} נתיבים | {len(self.surface['login_pages'])} עמודי login | {len(self.surface['api_endpoints'])} API endpoints")

    async def _fp_ssl(self):
        try:
            parsed = urlparse(self.url)
            if parsed.scheme != "https":
                self._add(Finding("high", "TLS/SSL", "האתר לא משתמש ב-HTTPS",
                                   "תקשורת לא מוצפנת — ניתן לציתות",
                                   evidence=[f"URL scheme: {parsed.scheme}"],
                                   recommendation="הוסף TLS certificate והפנה HTTP → HTTPS",
                                   phase=1, tags=["ssl", "tls"]))
                return

            host = parsed.netloc.split(":")[0]
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def get_cert():
                try:
                    with socket.create_connection((host, 443), timeout=8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            return ssock.getpeercert()
                except Exception:
                    return None

            cert = await loop.run_in_executor(None, get_cert)
            if not cert:
                return

            self.surface["ssl_cert"] = True
            # Check expiry
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                import datetime
                try:
                    exp = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    self.surface["ssl_days_left"] = days_left
                    if days_left < 0:
                        self._add(Finding("critical", "TLS/SSL", "TLS certificate פג תוקף",
                                           f"Certificate פג {-days_left} ימים",
                                           evidence=[f"notAfter: {not_after_str}"],
                                           recommendation="חדש את ה-certificate מיד",
                                           phase=1, tags=["ssl"]))
                    elif days_left < 30:
                        self._add(Finding("high", "TLS/SSL", f"TLS certificate עומד לפוג ({days_left} ימים)",
                                           "Certificate יפוג בקרוב",
                                           evidence=[f"notAfter: {not_after_str}"],
                                           recommendation="חדש את ה-certificate",
                                           phase=1, tags=["ssl"]))
                except Exception:
                    pass
        except Exception:
            pass

    async def _fp_dns(self):
        try:
            host = urlparse(self.url).netloc.split(":")[0]
            loop = asyncio.get_event_loop()

            # Basic IP resolution
            def resolve():
                try:
                    return socket.gethostbyname_ex(host)
                except Exception:
                    return None

            result = await loop.run_in_executor(None, resolve)
            if result:
                ips = result[2]
                self.surface["ips"] = ips
                self.log(f"  → DNS: {host} → {', '.join(ips)}")

                # Check for private/internal IPs exposed
                for ip in ips:
                    parts = list(map(int, ip.split(".")))
                    is_private = (
                        parts[0] == 10 or
                        (parts[0] == 172 and 16 <= parts[1] <= 31) or
                        (parts[0] == 192 and parts[1] == 168)
                    )
                    if is_private:
                        self._add(Finding("medium", "Information Disclosure", "IP פרטי מוחזר ב-DNS",
                                           f"כתובת IP פרטית: {ip}",
                                           evidence=[f"DNS {host} → {ip}"],
                                           recommendation="בדוק שלא מדובר בטעות הגדרה",
                                           phase=1, tags=["dns"]))
        except Exception:
            pass

    async def _fp_technology(self):
        resp = await _get(self.session, self.url)
        if not resp:
            return
        body = await _text(resp)
        self.surface["body_length"] = len(body)

        techs = []
        cms = None

        # CMS detection
        if "wp-content" in body or "wp-json" in body or "/wp-includes/" in body:
            techs.append("WordPress")
            cms = "wordpress"
            self.surface["cms"] = "wordpress"
        elif "Joomla" in body or "/components/com_" in body:
            techs.append("Joomla")
            cms = "joomla"
            self.surface["cms"] = "joomla"
        elif "Drupal" in body or "drupal.js" in body:
            techs.append("Drupal")
            cms = "drupal"
            self.surface["cms"] = "drupal"
        elif "shopify" in body.lower() or "cdn.shopify.com" in body:
            techs.append("Shopify")
            self.surface["cms"] = "shopify"

        # Framework detection
        if "react" in body.lower() and ("__REACT" in body or "data-reactroot" in body or "_reactFiber" in body):
            techs.append("React")
            self.surface["spa"] = True
        if "angular" in body.lower() and ("ng-version" in body or "ng-app" in body):
            techs.append("Angular")
            self.surface["spa"] = True
        if "vue" in body.lower() and ("data-v-" in body or "__vue__" in body):
            techs.append("Vue.js")
            self.surface["spa"] = True
        if "__NEXT_DATA__" in body:
            techs.append("Next.js")
        if "nuxt" in body.lower():
            techs.append("Nuxt.js")

        # Backend detection from headers
        hdrs = self.surface.get("headers", {})
        powered = str(hdrs.get("X-Powered-By", hdrs.get("x-powered-by", ""))).lower()
        if "php" in powered:
            techs.append("PHP")
            self.surface["backend"] = "php"
        elif "asp.net" in powered:
            techs.append("ASP.NET")
            self.surface["backend"] = "aspnet"

        # BaaS detection
        if "supabase" in body.lower() or "supabase.co" in body:
            techs.append("Supabase")
            self.surface["baas"] = "supabase"
        if "firebase" in body.lower() or "firebaseapp.com" in body:
            techs.append("Firebase")
            self.surface["baas"] = "firebase"
        if "amplify" in body.lower() and "aws-amplify" in body:
            techs.append("AWS Amplify")
            self.surface["baas"] = "amplify"

        # Forms detection
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        form_data = []
        for form_html in forms[:10]:
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            form_data.append({
                "action": action.group(1) if action else "",
                "method": method.group(1).upper() if method else "GET",
                "inputs": inputs,
            })
        self.surface["forms"] = form_data
        has_login_form = any(
            any(x in str(f["inputs"]).lower() for x in ["password", "pass", "pwd"])
            for f in form_data
        )
        if has_login_form:
            self.surface.setdefault("login_pages", []).append(self.url)
            self.log(f"  → נמצא טופס login בעמוד הראשי")

        # JS files
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE)
        self.surface["js_files"] = js_files[:20]

        # API patterns in HTML/JS
        api_patterns = re.findall(r'["\'](/api/[^"\'?#\s]{2,60})["\']', body)
        api_patterns += re.findall(r'fetch\(["\']([^"\']+)["\']', body)
        if api_patterns:
            self.surface.setdefault("api_endpoints", []).extend(
                [urljoin(self.base_url, p) for p in api_patterns[:20]]
            )

        self.surface["technologies"] = list(set(techs))
        if techs:
            self.log(f"  → טכנולוגיות: {', '.join(techs)}")

    # ── Phase 2: Targeted tests based on Phase 1 surface ──────────────────────

    async def _phase2_targeted(self):
        decisions = []
        tasks = []

        cms = self.surface.get("cms")
        if cms == "wordpress":
            decisions.append("WordPress זוהה → בדיקת plugins, themes, גרסה")
            tasks.append(self._p2_wordpress())
        if cms == "joomla":
            decisions.append("Joomla זוהה → בדיקת גרסה וחולשות ידועות")
            tasks.append(self._p2_joomla())

        if self.surface.get("login_pages"):
            decisions.append(f"נמצאו {len(self.surface['login_pages'])} עמודי login → בדיקת SQL Injection וברוט-פורס")
            tasks.append(self._p2_login_attacks())

        if self.surface.get("api_endpoints"):
            decisions.append(f"נמצאו {len(self.surface['api_endpoints'])} API endpoints → בדיקת IDOR ו-SSRF")
            tasks.append(self._p2_api_attacks())

        if self.surface.get("baas"):
            decisions.append(f"BaaS זוהה ({self.surface['baas']}) → בדיקת rules והרשאות")
            tasks.append(self._p2_baas())

        if self.surface.get("git_exposed"):
            decisions.append("Git repository חשוף → ניסיון dump של קוד המקור")
            tasks.append(self._p2_git_dump())

        if self.surface.get("forms"):
            decisions.append(f"נמצאו {len(self.surface['forms'])} טפסים → בדיקת XSS ו-CSRF")
            tasks.append(self._p2_forms())

        if self.surface.get("cors_wildcard"):
            decisions.append("CORS wildcard זוהה → בדיקת CORS exploitation")
            tasks.append(self._p2_cors())

        if not self.surface.get("spa"):
            decisions.append("אתר לא SPA → פאזינג נתיבים")
            tasks.append(self._p2_dir_enum())

        # Always run these
        tasks += [
            self._p2_injection_probes(),
            self._p2_open_redirect(),
            self._p2_sensitive_info(),
        ]

        self.surface["_decisions"] = decisions
        for d in decisions:
            self.log(f"  ⚡ {d}")

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _p2_wordpress(self):
        base = self.base_url
        self.log("  → WordPress: סריקת plugins וגרסה")

        # Version detection
        resp = await _get(self.session, f"{base}/readme.html")
        if resp and resp.status == 200:
            body = await _text(resp)
            ver = re.search(r'Version\s+([\d.]+)', body, re.IGNORECASE)
            if ver:
                self.surface["wp_version"] = ver.group(1)
                self._add(Finding("medium", "WordPress", f"WordPress גרסה {ver.group(1)} חשופה",
                                   "readme.html חשוף וחושף גרסת WP",
                                   evidence=[f"GET {base}/readme.html → 200", f"Version: {ver.group(1)}"],
                                   recommendation="מחק readme.html מה-server",
                                   phase=2, tags=["wordpress", "version"]))

        # Common vulnerable plugins
        plugins = [
            "contact-form-7", "elementor", "woocommerce", "yoast-seo",
            "wordfence", "akismet", "jetpack", "wpforms-lite",
            "revslider", "wp-file-manager", "all-in-one-wp-migration",
        ]
        found_plugins = []
        async def check_plugin(p):
            url = f"{base}/wp-content/plugins/{p}/readme.txt"
            resp = await _get(self.session, url, allow_redirects=False)
            if resp and resp.status == 200:
                found_plugins.append(p)
        await asyncio.gather(*[check_plugin(p) for p in plugins], return_exceptions=True)

        if found_plugins:
            self.surface["wp_plugins"] = found_plugins
            # Known dangerous plugins
            risky = {"revslider", "wp-file-manager", "all-in-one-wp-migration"}
            for p in found_plugins:
                if p in risky:
                    self._add(Finding("high", "WordPress", f"Plugin בעל היסטוריית חולשות: {p}",
                                       f"ה-plugin {p} ידוע בחולשות קריטיות בעבר",
                                       evidence=[f"נמצא ב-{base}/wp-content/plugins/{p}/"],
                                       recommendation=f"עדכן {p} לגרסה האחרונה",
                                       phase=2, tags=["wordpress", "plugin", "cve"]))

        # XML-RPC
        resp = await _get(self.session, f"{base}/xmlrpc.php")
        if resp and resp.status == 200:
            body = await _text(resp)
            if "xmlrpc" in body.lower():
                self.surface["xmlrpc"] = True
                self._add(Finding("high", "WordPress", "XML-RPC מופעל",
                                   "XML-RPC מאפשר ברוט-פורס ומתקפות amplification",
                                   evidence=[f"GET {base}/xmlrpc.php → 200"],
                                   recommendation="השבת XML-RPC אם אינו נדרש",
                                   phase=2, tags=["wordpress", "xmlrpc", "bruteforce"]))

    async def _p2_joomla(self):
        base = self.base_url
        resp = await _get(self.session, f"{base}/administrator/")
        if resp and resp.status == 200:
            self._add(Finding("medium", "Joomla", "Joomla Admin panel נגיש",
                               "/administrator/ נגיש מהאינטרנט",
                               evidence=[f"GET {base}/administrator/ → 200"],
                               recommendation="הגבל גישה לפי IP",
                               phase=2, tags=["joomla", "admin"]))
        resp = await _get(self.session, f"{base}/README.txt")
        if resp and resp.status == 200:
            body = await _text(resp)
            ver = re.search(r'Joomla!\s*([\d.]+)', body, re.IGNORECASE)
            if ver:
                self._add(Finding("low", "Joomla", f"גרסת Joomla חשופה: {ver.group(1)}",
                                   "README.txt חושף גרסה",
                                   evidence=[f"Version: {ver.group(1)}"],
                                   recommendation="מחק README.txt",
                                   phase=2, tags=["joomla", "version"]))

    async def _p2_login_attacks(self):
        self.log("  → בדיקת SQL Injection בטפסי login")
        for login_url in self.surface.get("login_pages", [])[:3]:
            # Find form on the page
            resp = await _get(self.session, login_url)
            if not resp:
                continue
            body = await _text(resp)

            # Extract form fields
            form_match = re.search(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
            if not form_match:
                continue
            form_html = form_match.group(1)
            action = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', body, re.IGNORECASE)
            form_action = urljoin(login_url, action.group(1)) if action else login_url

            inputs = re.findall(r'<input[^>]+name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            input_types = dict(re.findall(r'<input[^>]+name=["\']([^"\']*)["\'][^>]*type=["\']([^"\']*)["\']', form_html, re.IGNORECASE))

            # Build payload dict
            sqli_payloads = [
                ("' OR '1'='1", "' OR '1'='1"),
                ("admin'--", "anything"),
                ("' OR 1=1--", "pass"),
            ]

            for user_payload, pass_payload in sqli_payloads:
                post_data = {}
                for inp in inputs:
                    t = input_types.get(inp, "text").lower()
                    if t == "hidden":
                        # try to preserve hidden fields from the page
                        hidden_val = re.search(rf'name=["\'][^"\']*{re.escape(inp)}[^"\']*["\'][^>]*value=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                        post_data[inp] = hidden_val.group(1) if hidden_val else ""
                    elif t == "password":
                        post_data[inp] = pass_payload
                    elif t == "submit":
                        post_data[inp] = "submit"
                    else:
                        post_data[inp] = user_payload

                resp2 = await _post(self.session, form_action, data=post_data, allow_redirects=True)
                if not resp2:
                    continue
                body2 = await _text(resp2)

                # SQLi indicators
                sql_errors = [
                    "you have an error in your sql syntax",
                    "warning: mysql", "unclosed quotation mark",
                    "quoted string not properly terminated",
                    "syntax error", "ORA-", "microsoft ole db",
                    "pg_query", "sqlstate",
                ]
                sql_found = any(e.lower() in body2.lower() for e in sql_errors)

                if sql_found:
                    self.surface["sqli_login"] = True
                    self._add(Finding("critical", "SQL Injection", f"SQL Injection בטופס Login: {form_action}",
                                       f"שגיאת SQL ב-response לאחר payload: {user_payload}",
                                       evidence=[
                                           f"URL: {form_action}",
                                           f"Payload: username={user_payload}",
                                           f"Response contains SQL error",
                                       ],
                                       recommendation="השתמש ב-prepared statements, אל תבנה SQL באופן ישיר",
                                       phase=2, tags=["sqli", "login", "critical"]))
                    break

                # Login bypass check
                if resp2.status in (200, 302):
                    bypass_indicators = ["dashboard", "welcome", "logout", "profile", "admin panel"]
                    if any(x in body2.lower() for x in bypass_indicators):
                        self.surface["login_bypass"] = True
                        self._add(Finding("critical", "Authentication Bypass", f"SQL Injection מאפשר bypass של login",
                                           f"Payload '{user_payload}' גרם לכניסה מוצלחת",
                                           evidence=[f"POST {form_action} → {resp2.status}"],
                                           recommendation="תקן SQL Injection מיד",
                                           phase=2, tags=["sqli", "auth-bypass"]))
                        break

    async def _p2_api_attacks(self):
        self.log("  → בדיקת IDOR ב-API endpoints")
        api_endpoints = self.surface.get("api_endpoints", [])

        idor_found = []
        for ep in api_endpoints[:15]:
            # Try to inject numeric IDs
            for base_id in [1, 2, 0, 999, -1]:
                test_url = re.sub(r'/\d+', f'/{base_id}', ep)
                if test_url == ep:
                    test_url = ep.rstrip("/") + f"/{base_id}"
                resp = await _get(self.session, test_url)
                if resp and resp.status == 200:
                    body = await _text(resp)
                    # Check for data leak patterns
                    if any(x in body for x in ['"email"', '"password"', '"token"', '"user"', '"id":']):
                        idor_found.append(test_url)
                        self._add(Finding("high", "IDOR", f"IDOR בנתיב: {test_url}",
                                           "גישה לנתונים ללא בדיקת הרשאות",
                                           evidence=[f"GET {test_url} → 200", body[:200]],
                                           recommendation="הוסף authorization check לכל endpoint",
                                           phase=2, tags=["idor", "api"]))
                        break

        # SSRF via URL parameters
        if api_endpoints:
            ssrf_params = ["url", "uri", "redirect", "callback", "proxy", "fetch", "load", "src", "href", "to"]
            for ep in api_endpoints[:8]:
                parsed = urlparse(ep)
                params = parse_qs(parsed.query)
                for param in ssrf_params:
                    test_url = ep + ("&" if "?" in ep else "?") + f"{param}=http://169.254.169.254/latest/meta-data/"
                    resp = await _get(self.session, test_url)
                    if resp and resp.status == 200:
                        body = await _text(resp)
                        if any(x in body for x in ["ami-id", "instance-id", "security-credentials", "169.254"]):
                            self._add(Finding("critical", "SSRF", f"SSRF על parameter '{param}': {ep}",
                                               "שרת ניגש לכתובות פנימיות — AWS metadata נגיש",
                                               evidence=[f"GET {test_url} → 200", body[:300]],
                                               recommendation="הוסף allowlist של URLs מותרים",
                                               phase=2, tags=["ssrf", "aws", "metadata"]))

    async def _p2_baas(self):
        baas = self.surface.get("baas")
        self.log(f"  → בדיקת {baas} הרשאות")

        resp = await _get(self.session, self.url)
        if not resp:
            return
        body = await _text(resp)

        if baas == "supabase":
            key_match = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
            url_match = re.search(r'https://[a-z0-9]+\.supabase\.co', body)
            if key_match and url_match:
                supabase_url = url_match.group(0)
                anon_key = key_match.group(0)
                self.surface["supabase_url"] = supabase_url
                self.surface["supabase_key"] = anon_key[:30] + "..."

                # Test open table access
                test_resp = await _get(self.session, f"{supabase_url}/rest/v1/users?select=*&limit=1",
                                        headers={**HEADERS, "apikey": anon_key, "Authorization": f"Bearer {anon_key}"})
                if test_resp and test_resp.status == 200:
                    body2 = await _text(test_resp)
                    self._add(Finding("critical", "BaaS / Supabase", "Supabase — גישה פתוחה לטבלה 'users'",
                                       "ניתן לקרוא נתוני משתמשים ללא אימות",
                                       evidence=[f"GET {supabase_url}/rest/v1/users → 200", body2[:300]],
                                       recommendation="הגדר RLS policies על כל הטבלאות",
                                       phase=2, tags=["supabase", "baas", "data-exposure"]))

        elif baas == "firebase":
            fb_match = re.search(r'https://([a-z0-9-]+)\.firebaseio\.com', body)
            if fb_match:
                fb_url = fb_match.group(0)
                self.surface["firebase_url"] = fb_url
                test_resp = await _get(self.session, f"{fb_url}/.json")
                if test_resp and test_resp.status == 200:
                    b = await _text(test_resp)
                    if b and b != "null":
                        self._add(Finding("critical", "BaaS / Firebase", "Firebase Realtime DB ציבורי",
                                           "מסד הנתונים נגיש לכולם ללא אימות",
                                           evidence=[f"GET {fb_url}/.json → 200", b[:300]],
                                           recommendation="הגדר Firebase Security Rules",
                                           phase=2, tags=["firebase", "baas", "data-exposure"]))

    async def _p2_git_dump(self):
        self.log("  → ניסיון חילוץ .git")
        base = self.base_url
        git_files = [
            ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
            ".git/FETCH_HEAD", ".git/logs/HEAD",
        ]
        for f in git_files:
            url = f"{base}/{f}"
            resp = await _get(self.session, url, allow_redirects=False)
            if resp and resp.status == 200:
                body = await _text(resp)
                if body.strip():
                    self._add(Finding("critical", "Source Code Exposure", f"Git file נגיש: {f}",
                                       "ניתן לשחזר קוד מקור מה-git repository",
                                       evidence=[f"GET {url} → 200", body[:200]],
                                       recommendation="חסום גישה לתיקיית .git",
                                       phase=2, tags=["git", "source-code"]))

    async def _p2_forms(self):
        self.log("  → בדיקת XSS בטפסים")
        xss_payload = '<script>alert("XSS")</script>'
        xss_payload2 = '"><img src=x onerror=alert(1)>'

        for form in self.surface.get("forms", [])[:5]:
            action = form.get("action", "")
            if not action:
                action = self.url
            form_url = urljoin(self.base_url, action)
            method = form.get("method", "GET").upper()

            for payload in [xss_payload, xss_payload2]:
                post_data = {inp: payload for inp in form.get("inputs", ["q"])
                             if "password" not in inp.lower()}

                if method == "POST":
                    resp = await _post(self.session, form_url, data=post_data)
                else:
                    params = urlencode(post_data)
                    resp = await _get(self.session, f"{form_url}?{params}")

                if not resp:
                    continue
                body = await _text(resp)

                # Reflected XSS: payload appears unescaped
                if payload in body or payload.replace('"', '&quot;') not in body:
                    if xss_payload.split("<")[1].split(">")[0] in body:
                        self.surface["xss_reflected"] = True
                        self._add(Finding("high", "XSS", f"Reflected XSS בטופס: {form_url}",
                                           f"Payload חוזר ב-response ללא escaping",
                                           evidence=[f"POST {form_url}", f"payload={payload[:60]}", body[:200]],
                                           recommendation="Escape כל input לפני הצגה, השתמש ב-CSP",
                                           phase=2, tags=["xss", "reflected"]))
                        break

        # CSRF check
        for form in self.surface.get("forms", [])[:5]:
            inputs = [i.lower() for i in form.get("inputs", [])]
            has_csrf = any(x in " ".join(inputs) for x in ["csrf", "_token", "authenticity_token", "nonce"])
            if not has_csrf and form.get("method", "GET").upper() == "POST":
                self._add(Finding("medium", "CSRF", f"טופס POST ללא CSRF token: {form.get('action', '/')}",
                                   "טופס לא מוגן מפני CSRF",
                                   evidence=[f"Inputs: {form.get('inputs', [])}"],
                                   recommendation="הוסף CSRF token לכל טופס POST",
                                   phase=2, tags=["csrf"]))

    async def _p2_cors(self):
        self.log("  → בדיקת CORS exploitation")
        headers_with_origin = {**HEADERS, "Origin": "https://evil.com"}
        resp = await _get(self.session, self.url, headers=headers_with_origin)
        if not resp:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil.com" or (acao == "*" and acac.lower() == "true"):
            self._add(Finding("critical", "CORS", "CORS misconfiguration — גנב credentials",
                               f"Origin זדוני מקובל, ACAC={acac}",
                               evidence=[f"ACAO: {acao}", f"ACAC: {acac}"],
                               recommendation="אל תשלב wildcard עם Allow-Credentials",
                               phase=2, tags=["cors", "credentials"]))

    async def _p2_dir_enum(self):
        self.log("  → פאזינג נתיבים נוספים")
        extra_paths = [
            "/backup", "/old", "/test", "/dev", "/staging", "/debug",
            "/tmp", "/temp", "/upload", "/uploads", "/files",
            "/api/v1/users", "/api/v1/admin", "/api/v2/users",
            "/wp-content/uploads/", "/include", "/includes",
        ]
        for path in extra_paths:
            url = self.base_url.rstrip("/") + path
            resp = await _get(self.session, url, allow_redirects=False)
            if resp and resp.status == 200:
                body = await _text(resp)
                self._add(Finding("medium", "Directory Exposure", f"נתיב חשוף: {path}",
                                   f"GET {url} החזיר 200",
                                   evidence=[f"GET {url} → 200 ({len(body)} bytes)"],
                                   recommendation=f"הגבל גישה ל-{path}",
                                   phase=2, tags=["directory", "exposure"]))

    async def _p2_injection_probes(self):
        self.log("  → בדיקת injection ב-URL parameters")
        # Get all links from homepage with params
        resp = await _get(self.session, self.url)
        if not resp:
            return
        body = await _text(resp)

        links_with_params = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', body, re.IGNORECASE)
        links_with_params = [urljoin(self.base_url, l) for l in links_with_params[:10]]

        payloads = {
            "sqli": "' OR '1'='1",
            "xss": '<script>alert(1)</script>',
            "lfi": "../../../etc/passwd",
            "ssti": "{{7*7}}",
            "cmd": "; sleep 2 #",
        }

        for url in links_with_params[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in list(params.keys())[:3]:
                for inj_type, payload in payloads.items():
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    new_query = urlencode({k: v[0] for k, v in new_params.items()})
                    test_url = urlunparse(parsed._replace(query=new_query))

                    resp2 = await _get(self.session, test_url)
                    if not resp2:
                        continue
                    body2 = await _text(resp2)

                    # SSTI detection
                    if inj_type == "ssti" and "49" in body2:
                        self._add(Finding("critical", "SSTI", f"Server-Side Template Injection ב-?{param_name}",
                                           "Expression 7*7=49 הוחזר — ביצוע קוד על השרת",
                                           evidence=[f"GET {test_url} → contains '49'"],
                                           recommendation="אל תשתמש ב-template rendering על input משתמש",
                                           phase=2, tags=["ssti", "rce"]))

                    # LFI detection
                    if inj_type == "lfi" and ("root:x:0" in body2 or "/bin/bash" in body2):
                        self._add(Finding("critical", "LFI", f"Local File Inclusion ב-?{param_name}",
                                           "/etc/passwd נחשף",
                                           evidence=[f"GET {test_url}", body2[:200]],
                                           recommendation="Whitelist קבצים מותרים, אל תשתמש ב-user input לנתיבי קבצים",
                                           phase=2, tags=["lfi", "rce"]))

                    # SQL errors
                    sql_errors = ["you have an error in your sql", "warning: mysql", "syntax error", "ORA-"]
                    if inj_type == "sqli" and any(e.lower() in body2.lower() for e in sql_errors):
                        self._add(Finding("critical", "SQL Injection", f"SQL Injection ב-parameter '{param_name}'",
                                           "שגיאת SQL ב-response",
                                           evidence=[f"GET {test_url}", body2[:200]],
                                           recommendation="השתמש ב-prepared statements",
                                           phase=2, tags=["sqli"]))

    async def _p2_open_redirect(self):
        resp = await _get(self.session, self.url)
        if not resp:
            return
        body = await _text(resp)

        redirect_params = re.findall(
            r'href=["\'][^"\']*[?&]((?:redirect|next|url|return|goto|target|redir)=[^"\'&]+)["\']',
            body, re.IGNORECASE
        )
        for param_str in redirect_params[:5]:
            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{param_str.split('=')[0]}=https://evil.com"
            resp2 = await _get(self.session, test_url, allow_redirects=False)
            if resp2 and resp2.status in (301, 302, 303, 307, 308):
                loc = resp2.headers.get("Location", "")
                if "evil.com" in loc:
                    self._add(Finding("high", "Open Redirect", f"Open Redirect ב-?{param_str.split('=')[0]}",
                                       "משתמש ניתן להפנייה לאתר זדוני",
                                       evidence=[f"GET {test_url} → {resp2.status}", f"Location: {loc}"],
                                       recommendation="Whitelist URL destinations מותרים",
                                       phase=2, tags=["redirect", "phishing"]))

    async def _p2_sensitive_info(self):
        self.log("  → חיפוש מידע רגיש בקוד")
        resp = await _get(self.session, self.url)
        if not resp:
            return
        body = await _text(resp)

        # JS files for secrets
        for js_url in self.surface.get("js_files", [])[:8]:
            full_url = urljoin(self.base_url, js_url)
            resp2 = await _get(self.session, full_url)
            if resp2:
                js_body = await _text(resp2)
                body += js_body

        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
            "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Private Key Header": r"-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----",
            "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,50}",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36}",
            "Password in HTML": r'(?i)password["\s:=]+["\'][^"\']{4,30}["\']',
            "Internal IP": r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+\b',
        }

        found_secrets = []
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body)
            for match in matches[:3]:
                # Avoid false positives for JWTs that are anon keys (public)
                if name == "JWT Token" and self.surface.get("baas"):
                    continue
                found_secrets.append((name, match))
                self._add(Finding("critical", "Secrets Exposure", f"{name} חשוף ב-source code",
                                   f"נמצא {name} בקוד הלקוח",
                                   evidence=[match[:80] + ("..." if len(match) > 80 else "")],
                                   recommendation="הסר credentials מ-frontend code, השתמש ב-environment variables",
                                   phase=2, tags=["secrets", "credentials"]))

        if found_secrets:
            self.surface["secrets_found"] = len(found_secrets)

    # ── Phase 3: Deep exploitation based on Phase 2 results ───────────────────

    async def _phase3_exploit(self):
        tasks = []

        if self.surface.get("sqli_login") or self._has_tag("sqli"):
            self.log("  → SQLi זוהה בשלב 2 → ניסיון חילוץ נתונים")
            tasks.append(self._p3_sqli_deep())

        if self._has_tag("xss") or self.surface.get("xss_reflected"):
            self.log("  → XSS זוהה בשלב 2 → בדיקת stored XSS ו-CSP bypass")
            tasks.append(self._p3_xss_deep())

        if self.surface.get("xmlrpc"):
            self.log("  → XML-RPC זוהה → ניסיון ברוט-פורס")
            tasks.append(self._p3_xmlrpc_bruteforce())

        if self.surface.get("cors_wildcard") or self._has_tag("cors"):
            tasks.append(self._p3_cors_deep())

        if not tasks:
            self.log("  → שלב 3: אין ממצאים שמצדיקים ניצול מעמיק")
            return

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _p3_sqli_deep(self):
        # Try error-based and time-based blind SQLi on any form
        for form in self.surface.get("forms", [])[:2]:
            action = urljoin(self.base_url, form.get("action", "") or self.url)
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            # Time-based blind SQLi probe
            payloads_time = [
                "' AND SLEEP(3)-- -",
                "'; WAITFOR DELAY '0:0:3'-- -",
                "' AND pg_sleep(3)-- -",
            ]
            for payload in payloads_time:
                post_data = {inp: payload for inp in inputs if "pass" not in inp.lower()}
                post_data.update({inp: "test123" for inp in inputs if "pass" in inp.lower()})

                t0 = time.time()
                resp = await _post(self.session, action, data=post_data)
                elapsed = time.time() - t0

                if elapsed >= 2.8:
                    self._add(Finding("critical", "SQL Injection (Blind)", f"Blind SQL Injection (time-based): {action}",
                                       f"SLEEP({3}) גרם לעיכוב של {elapsed:.1f}s — blind SQLi אושר",
                                       evidence=[f"POST {action}", f"Payload: {payload}", f"Elapsed: {elapsed:.2f}s"],
                                       recommendation="השתמש ב-prepared statements בכל שאילתות SQL",
                                       phase=3, tags=["sqli", "blind", "time-based"]))
                    return

    async def _p3_xss_deep(self):
        # Try more XSS bypasses if basic was found
        bypasses = [
            '"><svg onload=alert(1)>',
            "javascript:alert(1)",
            "';alert(1)//",
            '<img src=x onerror=alert`1`>',
        ]
        csp = self.surface.get("headers", {}).get("Content-Security-Policy", "")
        if csp:
            self._add(Finding("info", "XSS / CSP", "CSP מוגדר — XSS מוגבל",
                               f"Content-Security-Policy: {csp[:100]}",
                               evidence=[f"CSP: {csp[:150]}"],
                               recommendation="וודא ש-CSP לא מכיל 'unsafe-inline'",
                               phase=3, tags=["xss", "csp"]))
            if "unsafe-inline" in csp:
                self._add(Finding("high", "XSS / CSP", "CSP מכיל 'unsafe-inline' — XSS עדיין אפשרי",
                                   "הגדרת CSP עם unsafe-inline מסכלת את מטרתה",
                                   evidence=[f"CSP: {csp[:150]}"],
                                   recommendation="הסר 'unsafe-inline' מ-CSP",
                                   phase=3, tags=["xss", "csp"]))

    async def _p3_xmlrpc_bruteforce(self):
        # Test XML-RPC multicall amplification
        base = self.base_url
        payload = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>"""
        resp = await _post(self.session, f"{base}/xmlrpc.php",
                            data=payload.encode(),
                            headers={**HEADERS, "Content-Type": "text/xml"})
        if resp and resp.status == 200:
            body = await _text(resp)
            if "getUsersBlogs" in body or "wp.getUsersBlogs" in body:
                self._add(Finding("high", "WordPress XML-RPC", "XML-RPC מאפשר user enumeration ו-bruteforce",
                                   "system.listMethods חושף endpoints — ניתן ל-bruteforce credentials",
                                   evidence=["XML-RPC system.listMethods → 200", "wp.getUsersBlogs נגיש"],
                                   recommendation="השבת XML-RPC בhooks: add_filter('xmlrpc_enabled', '__return_false')",
                                   phase=3, tags=["wordpress", "xmlrpc", "bruteforce"]))

    async def _p3_cors_deep(self):
        # Test null origin
        headers_null = {**HEADERS, "Origin": "null"}
        resp = await _get(self.session, self.url, headers=headers_null)
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "null":
                self._add(Finding("high", "CORS", "CORS מקבל Origin: null",
                                   "ניתן לתקוף מ-sandboxed iframes",
                                   evidence=["Origin: null → Access-Control-Allow-Origin: null"],
                                   recommendation="אל תאפשר Origin: null",
                                   phase=3, tags=["cors"]))

    # ── Phase 4: Chain analysis ────────────────────────────────────────────────

    def _phase4_chains(self):
        tags_present = set()
        for f in self.findings:
            tags_present.update(f.tags)

        # Chain: CORS + Credentials = account takeover
        if "cors" in tags_present and "cookie" in tags_present:
            self.chains.append(AttackChain(
                title="CORS + Cookie → גניבת session",
                severity="critical",
                steps=[
                    "CORS wildcard מאפשר cross-origin requests",
                    "Cookie ללא SameSite נשלח עם הבקשה",
                    "תוקף יכול לקרוא session cookie של קורבן",
                    "Account takeover מלא",
                ],
                description="שילוב CORS wildcard עם cookie ללא הגנות מאפשר גניבת sessions"
            ))

        # Chain: SQLi + Login = DB dump
        if "sqli" in tags_present and "login" in tags_present:
            self.chains.append(AttackChain(
                title="SQL Injection בלוגין → חילוץ כל מסד הנתונים",
                severity="critical",
                steps=[
                    "SQL Injection בטופס הלוגין",
                    "Union-based או blind SQLi לחילוץ טבלאות",
                    "גניבת passwords, מיילים, נתוני לקוחות",
                    "כניסה כ-admin וכיבוש מלא של האתר",
                ],
                description="SQL Injection בלוגין מאפשר גישה לכל מסד הנתונים"
            ))

        # Chain: Git exposed = source code = more vulns
        if "git" in tags_present or "source-code" in tags_present:
            self.chains.append(AttackChain(
                title="Git חשוף → קוד מקור → גילוי credentials",
                severity="critical",
                steps=[
                    "תיקיית .git נגישה מהאינטרנט",
                    "שחזור קוד מקור עם כלים כמו git-dumper",
                    "חיפוש API keys, passwords, database strings בקוד",
                    "שימוש ב-credentials לגישה לשרת/DB",
                ],
                description="Git חשוף מאפשר שחזור קוד מקור ומציאת credentials"
            ))

        # Chain: SSRF = internal network pivot
        if "ssrf" in tags_present:
            self.chains.append(AttackChain(
                title="SSRF → גישה לרשת הפנימית",
                severity="critical",
                steps=[
                    "SSRF על URL parameter",
                    "גישה ל-AWS metadata (169.254.169.254)",
                    "גנבת IAM credentials",
                    "גישה ל-S3 buckets, שירותים פנימיים",
                ],
                description="SSRF מאפשר לתוקף להשתמש בשרת כ-proxy לגישה לרשת הפנימית"
            ))

        # Chain: LFI + Log poisoning = RCE
        if "lfi" in tags_present:
            self.chains.append(AttackChain(
                title="LFI + Log Poisoning → RCE",
                severity="critical",
                steps=[
                    "Local File Inclusion על parameter",
                    "הזרקת PHP code ל-access log דרך User-Agent",
                    "LFI על קובץ הלוג → הרצת קוד",
                    "Remote Code Execution מלא",
                ],
                description="LFI יכול להוביל ל-RCE דרך log poisoning"
            ))

        # Chain: Open redirect + phishing
        if "redirect" in tags_present:
            self.chains.append(AttackChain(
                title="Open Redirect → Phishing מאמין",
                severity="high",
                steps=[
                    "Open redirect בדומיין הלגיטימי",
                    "שליחת לינק עם הדומיין האמין לקורבן",
                    "הפניה לאתר פישינג",
                    "גנבת credentials של משתמשים",
                ],
                description="Open redirect משתמש בדומיין אמין כגשר לפישינג"
            ))

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _add(self, finding: Finding):
        # Deduplicate by title
        for existing in self.findings:
            if existing.title == finding.title:
                return
        self.findings.append(finding)

    def _has_tag(self, tag: str) -> bool:
        return any(tag in f.tags for f in self.findings)

    def _surface_summary(self) -> list[str]:
        parts = []
        if self.surface.get("cms"):
            parts.append(self.surface["cms"].title())
        if self.surface.get("technologies"):
            parts.extend(self.surface["technologies"][:3])
        if self.surface.get("login_pages"):
            parts.append(f"{len(self.surface['login_pages'])} login pages")
        if self.surface.get("api_endpoints"):
            parts.append(f"{len(self.surface['api_endpoints'])} API endpoints")
        if self.surface.get("baas"):
            parts.append(f"BaaS:{self.surface['baas']}")
        if not parts:
            parts.append("HTTP headers בלבד")
        return parts

    def _summarize(self, findings: list) -> dict:
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
        for f in findings:
            sev = f.get("severity", "info")
            s[sev] = s.get(sev, 0) + 1
        return s
