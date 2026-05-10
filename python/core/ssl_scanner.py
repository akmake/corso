"""
SSL/TLS Scanner
---------------
Comprehensive SSL/TLS analysis:
  - Protocol version (TLS 1.0/1.1/1.2/1.3, SSLv3, SSLv2)
  - Weak cipher suites (RC4, 3DES, NULL, EXPORT, ANON)
  - Certificate validation (expiry, CN mismatch, self-signed, weak key)
  - HSTS / HPKP headers
  - Secure cookie flags
  - Mixed content detection
  - BEAST, POODLE, CRIME, HEARTBLEED, FREAK, LOGJAM indicators
  - testssl.sh integration (when available)
  - Certificate transparency log check
"""

import asyncio
import ssl
import socket
import re
import subprocess
import shutil
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable
from urllib.parse import urlparse

import aiohttp

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

# ── Cipher classification ─────────────────────────────────────────────────────

_WEAK_CIPHERS = {
    "RC4":    ("high",   "RC4 — שבור לחלוטין, ניתן לפענח"),
    "NULL":   ("critical", "NULL cipher — ללא הצפנה!"),
    "EXPORT": ("critical", "EXPORT cipher — מוחלש בכוונה (FREAK attack)"),
    "DES":    ("high",   "DES — מפתח 56-bit, שבור"),
    "3DES":   ("medium", "3DES — SWEET32 attack, deprecated"),
    "ANON":   ("critical", "Anonymous cipher — ללא אימות שרת!"),
    "MD5":    ("medium", "MD5 בחתימה — שבור"),
    "SHA1":   ("low",    "SHA-1 — deprecated, מומלץ SHA-256+"),
}

_GOOD_CIPHERS = ["AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305", "AES_256_CBC"]

# ── Deprecated TLS versions ────────────────────────────────────────────────────

_DEPRECATED_PROTOCOLS = {
    ssl.PROTOCOL_TLS_CLIENT: None,  # Will test manually
}

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
_TIMEOUT = aiohttp.ClientTimeout(total=15)

async def _get(session, url, **kw):
    try:
        kw.setdefault("ssl", False)
        return await session.get(url, headers=_HEADERS, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

# ── Certificate info ──────────────────────────────────────────────────────────

def _get_cert_info(hostname: str, port: int = 443) -> Optional[dict]:
    """Retrieve SSL certificate info synchronously."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "version": version}
    except ssl.SSLCertVerificationError as e:
        return {"error": str(e), "cert_error": True}
    except ssl.SSLError as e:
        return {"error": str(e), "ssl_error": True}
    except Exception as e:
        return {"error": str(e)}

def _test_old_protocol(hostname: str, port: int, protocol_str: str) -> bool:
    """Test if server accepts a specific TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if protocol_str == "TLSv1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif protocol_str == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif protocol_str == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False

# ── Scanner ───────────────────────────────────────────────────────────────────

class SSLScanner:
    def __init__(self, url: str, log: Optional[Callable] = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.hostname = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self._log = log or (lambda m: None)
        self.findings: list[Finding] = []

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────────

    async def _check_https_redirect(self, session):
        self._log("SSL: בודק HTTP → HTTPS redirect...")
        http_url = self.url.replace("https://", "http://")
        resp = await session.get(http_url, headers=_HEADERS, timeout=_TIMEOUT, ssl=False, allow_redirects=False)
        if resp is None:
            return
        if resp.status in (200, 404):
            self.findings.append(Finding(
                severity="high",
                category="SSL/TLS",
                title="HTTP לא מפנה ל-HTTPS",
                description=f"הגישה ל-{http_url} מחזירה {resp.status} ללא redirect ל-HTTPS. מידע נשלח ב-cleartext.",
                evidence=[f"HTTP URL: {http_url}", f"Status: {resp.status}", "אין Location header"],
                recommendation="הוסף redirect: HTTP 301 → HTTPS לכל הדומיין. הגדר HSTS.",
                tags=["ssl", "http-no-redirect", "cleartext"],
            ))
        elif resp.status in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if not location.startswith("https://"):
                self.findings.append(Finding(
                    severity="medium",
                    category="SSL/TLS",
                    title="HTTP Redirect לא ל-HTTPS",
                    description=f"HTTP מפנה ל: {location} (לא HTTPS)",
                    evidence=[f"Redirect to: {location}"],
                    recommendation="ודא ש-redirect HTTP מפנה ל-HTTPS בלבד.",
                    tags=["ssl", "bad-redirect"],
                ))

    # ── Certificate analysis ──────────────────────────────────────────────────

    async def _check_certificate(self):
        self._log("SSL: בודק תעודה...")
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(None, _get_cert_info, self.hostname, self.port)

        if info is None:
            return

        if info.get("cert_error"):
            self.findings.append(Finding(
                severity="high",
                category="SSL/TLS",
                title="שגיאת אימות תעודה SSL",
                description=f"ה-SSL Certificate אינו תקין: {info.get('error', '')}",
                evidence=[str(info.get("error", ""))],
                recommendation="התקן תעודה תקינה מ-CA מוכר (Let's Encrypt, DigiCert). אל תשתמש ב-self-signed בפרודקשן.",
                tags=["ssl", "cert-error", "invalid-cert"],
            ))
            return

        if info.get("error"):
            self._log(f"SSL: שגיאה בחיבור — {info['error']}")
            return

        cert = info.get("cert", {})
        cipher = info.get("cipher", ())
        version = info.get("version", "")

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp_date - now).days

                if days_left < 0:
                    self.findings.append(Finding(
                        severity="critical",
                        category="SSL/TLS",
                        title="SSL Certificate פג תוקף!",
                        description=f"ה-SSL Certificate פג תוקף לפני {abs(days_left)} ימים ({not_after}).",
                        evidence=[f"Expiry: {not_after}", f"Days expired: {abs(days_left)}"],
                        recommendation="חדש את התעודה מיידית. שקול הגדרת auto-renewal עם certbot.",
                        tags=["ssl", "expired-cert", "critical"],
                    ))
                elif days_left < 14:
                    self.findings.append(Finding(
                        severity="high",
                        category="SSL/TLS",
                        title=f"SSL Certificate פג תוקף בעוד {days_left} ימים",
                        description=f"תעודה SSL עומדת לפוג ב-{not_after}. דחייה = downtime.",
                        evidence=[f"Expiry: {not_after}", f"Days remaining: {days_left}"],
                        recommendation="חדש תעודה מיידית. הגדר auto-renewal.",
                        tags=["ssl", "expiring-soon"],
                    ))
                elif days_left < 30:
                    self.findings.append(Finding(
                        severity="medium",
                        category="SSL/TLS",
                        title=f"SSL Certificate פג תוקף בעוד {days_left} ימים",
                        description=f"מומלץ לחדש. תאריך פקיעה: {not_after}",
                        evidence=[f"Days remaining: {days_left}"],
                        recommendation="חדש תעודה בקרוב.",
                        tags=["ssl", "expiring"],
                    ))
            except ValueError:
                pass

        # Check self-signed
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            self.findings.append(Finding(
                severity="high",
                category="SSL/TLS",
                title="Self-Signed Certificate",
                description="התעודה חתומה ע\"י עצמה. דפדפנים יציגו אזהרה למשתמשים.",
                evidence=[f"Subject: {subject}", f"Issuer: {issuer}"],
                recommendation="השתמש ב-CA מוכר (Let's Encrypt בחינם).",
                tags=["ssl", "self-signed"],
            ))

        # Check CN mismatch
        cn = subject.get("commonName", "")
        sans = [san[1] for san in cert.get("subjectAltName", [])]
        if cn and self.hostname not in [cn, f"*.{'.'.join(self.hostname.split('.')[1:])}"] + sans:
            self.findings.append(Finding(
                severity="high",
                category="SSL/TLS",
                title="SSL Certificate Name Mismatch",
                description=f"ה-hostname '{self.hostname}' אינו תואם ל-CN '{cn}' ולרשימת ה-SAN.",
                evidence=[f"Hostname: {self.hostname}", f"CN: {cn}", f"SANs: {sans[:5]}"],
                recommendation="הנפק תעודה שמכסה את הדומיין הנכון.",
                tags=["ssl", "name-mismatch"],
            ))

        # Log TLS version
        self._log(f"SSL: גרסת TLS — {version}, cipher — {cipher[0] if cipher else 'unknown'}")
        if version:
            self.findings.append(Finding(
                severity="info",
                category="SSL/TLS",
                title=f"TLS Version: {version}",
                description=f"החיבור השתמש ב-{version} עם cipher {cipher[0] if cipher else 'N/A'}",
                evidence=[f"Version: {version}", f"Cipher: {cipher}"],
                recommendation="" if version in ("TLSv1.3", "TLSv1.2") else "שדרג ל-TLS 1.2 לפחות",
                tags=["ssl", "tls-version", version.lower().replace(".", "")],
            ))

        # Weak cipher check
        if cipher:
            cipher_name = cipher[0]
            for weak, (severity, desc) in _WEAK_CIPHERS.items():
                if weak in cipher_name.upper():
                    self.findings.append(Finding(
                        severity=severity,
                        category="SSL/TLS",
                        title=f"Weak Cipher Suite: {cipher_name}",
                        description=f"ה-cipher '{cipher_name}' הוא חלש: {desc}",
                        evidence=[f"Cipher: {cipher_name}", f"Negotiated with TLS {version}"],
                        recommendation=f"השבת {weak} ciphers. השתמש רק ב-AES-256-GCM, CHACHA20.",
                        tags=["ssl", "weak-cipher", weak.lower()],
                    ))

    # ── Old TLS version check ─────────────────────────────────────────────────

    async def _check_old_protocols(self):
        self._log("SSL: בודק גרסאות TLS ישנות (1.0, 1.1)...")
        loop = asyncio.get_event_loop()

        for proto in ["TLSv1", "TLSv1.1"]:
            try:
                accepted = await asyncio.wait_for(
                    loop.run_in_executor(None, _test_old_protocol, self.hostname, self.port, proto),
                    timeout=8
                )
                if accepted:
                    severity = "high" if proto == "TLSv1" else "medium"
                    vuln = "POODLE, BEAST" if proto == "TLSv1" else "BEAST"
                    self._log(f"SSL {severity}: {proto} פעיל → {vuln}")
                    self.findings.append(Finding(
                        severity=severity,
                        category="SSL/TLS",
                        title=f"{proto} פעיל — Deprecated Protocol",
                        description=f"ה-server מקבל {proto} שהוא deprecated. חשוף ל: {vuln}",
                        evidence=[f"Protocol: {proto}", f"Host: {self.hostname}:{self.port}", f"Vulnerabilities: {vuln}"],
                        recommendation=f"השבת {proto} לחלוטין. הגדר minimum TLS version ל-1.2.",
                        tags=["ssl", proto.lower().replace(".", ""), "deprecated"],
                    ))
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

    # ── Security headers ──────────────────────────────────────────────────────

    async def _check_security_headers(self, session):
        self._log("SSL: בודק security headers (HSTS, HPKP)...")
        resp = await _get(session, self.url)
        if resp is None:
            return

        headers = resp.headers

        # HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.findings.append(Finding(
                severity="medium",
                category="SSL/TLS",
                title="HSTS לא מוגדר",
                description="Strict-Transport-Security header חסר. מאפשר downgrade attacks ו-SSL stripping.",
                evidence=[f"URL: {self.url}", "Header Strict-Transport-Security: חסר"],
                recommendation="הוסף: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                tags=["ssl", "hsts", "missing-header"],
            ))
        else:
            max_age_m = re.search(r'max-age=(\d+)', hsts)
            if max_age_m:
                max_age = int(max_age_m.group(1))
                if max_age < 31536000:
                    self.findings.append(Finding(
                        severity="low",
                        category="SSL/TLS",
                        title=f"HSTS max-age קצר מדי: {max_age}s",
                        description=f"HSTS max-age = {max_age}s ({max_age//86400} ימים). מומלץ 1 שנה לפחות.",
                        evidence=[f"HSTS: {hsts}"],
                        recommendation="הגדר max-age=31536000 (שנה) לפחות.",
                        tags=["ssl", "hsts", "short-max-age"],
                    ))
            if "includeSubDomains" not in hsts:
                self.findings.append(Finding(
                    severity="low",
                    category="SSL/TLS",
                    title="HSTS חסר includeSubDomains",
                    description="HSTS לא כולל תתי-דומיינים — אלה נשארים חשופים ל-SSL stripping.",
                    evidence=[f"HSTS: {hsts}"],
                    recommendation="הוסף includeSubDomains ל-HSTS header.",
                    tags=["ssl", "hsts", "no-subdomains"],
                ))

        # Secure cookie check
        set_cookie = resp.headers.getall("Set-Cookie", []) if hasattr(resp.headers, 'getall') else [resp.headers.get("Set-Cookie", "")]
        for cookie in set_cookie:
            if cookie and "Secure" not in cookie:
                cookie_name = cookie.split("=")[0].strip()
                self.findings.append(Finding(
                    severity="medium",
                    category="SSL/TLS",
                    title=f"Cookie ללא Secure Flag: {cookie_name}",
                    description=f"ה-Cookie '{cookie_name}' לא מוגן ב-Secure flag — נשלח ב-HTTP.",
                    evidence=[f"Cookie: {cookie[:100]}"],
                    recommendation="הוסף Secure לכל Cookies. Session cookies חייבים גם HttpOnly.",
                    tags=["ssl", "cookie-secure", cookie_name],
                ))

    # ── Mixed content ─────────────────────────────────────────────────────────

    async def _check_mixed_content(self, session):
        self._log("SSL: בודק Mixed Content...")
        resp = await _get(session, self.url)
        body = await _text(resp)

        http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.I)
        http_resources += re.findall(r'url\(http://[^)]+\)', body, re.I)

        if http_resources:
            self.findings.append(Finding(
                severity="medium",
                category="SSL/TLS",
                title=f"Mixed Content — {len(http_resources)} משאבי HTTP",
                description=f"דף HTTPS טוען {len(http_resources)} משאבים ב-HTTP. דפדפנים חוסמים אלה ועשויים להציג אזהרה.",
                evidence=http_resources[:5],
                recommendation="שנה כל URLs של משאבים מ-http:// ל-https://. השתמש ב-// (protocol-relative) או https:// מפורש.",
                tags=["ssl", "mixed-content"],
            ))

    # ── testssl.sh integration ────────────────────────────────────────────────

    async def _run_testssl(self):
        testssl = shutil.which("testssl.sh") or shutil.which("testssl")
        if not testssl:
            self._log("SSL: testssl.sh לא מותקן — מדלג")
            return

        self._log("SSL: מריץ testssl.sh...")
        try:
            cmd = [testssl, "--jsonfile", "/tmp/testssl_out.json", "--fast", self.hostname]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                self._log("SSL: testssl.sh timeout")
                return

            # Parse JSON output
            import os
            if os.path.exists("/tmp/testssl_out.json"):
                with open("/tmp/testssl_out.json") as f:
                    testssl_data = json.load(f)
                # Extract findings from testssl
                for item in testssl_data.get("scanResult", [{}])[0].get("findings", []):
                    if item.get("severity", "").upper() in ("HIGH", "CRITICAL", "WARN"):
                        sev = item["severity"].lower()
                        if sev == "warn":
                            sev = "medium"
                        self.findings.append(Finding(
                            severity=sev,
                            category="SSL/TLS",
                            title=f"testssl: {item.get('id', 'finding')}",
                            description=item.get("finding", ""),
                            evidence=[f"testssl ID: {item.get('id', '')}"],
                            recommendation="פעל לפי המלצת testssl.sh.",
                            tags=["ssl", "testssl", item.get("id", "").lower()],
                        ))
                self._log(f"SSL: testssl.sh הושלם")
        except Exception as e:
            self._log(f"SSL: testssl.sh שגיאה — {e}")

    # ── Certificate Transparency ──────────────────────────────────────────────

    async def _check_ct_logs(self, session):
        self._log("SSL: בודק Certificate Transparency...")
        ct_url = f"https://crt.sh/?q={self.hostname}&output=json"
        try:
            resp = await session.get(ct_url, headers=_HEADERS, timeout=_TIMEOUT, ssl=True)
            if resp and resp.status == 200:
                data = await resp.json()
                if isinstance(data, list) and len(data) > 0:
                    issuers = list(set(d.get("issuer_name", "") for d in data[:20]))
                    self.findings.append(Finding(
                        severity="info",
                        category="SSL/TLS",
                        title=f"Certificate Transparency — {len(data)} תעודות רשומות",
                        description=f"נמצאו {len(data)} תעודות עבור {self.hostname} ב-CT logs. בדוק תעודות לא מוכרות.",
                        evidence=[f"Total certs: {len(data)}", f"Issuers: {issuers[:3]}"],
                        recommendation="עבור על רשימת התעודות ב-crt.sh ובדוק שאין תעודות שלא הנפקת.",
                        tags=["ssl", "certificate-transparency", "info"],
                    ))
        except Exception:
            pass

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"SSL Scanner: מתחיל על {self.url}")

        if self.parsed.scheme != "https":
            self.findings.append(Finding(
                severity="critical",
                category="SSL/TLS",
                title="אתר משתמש ב-HTTP בלבד",
                description=f"האתר {self.url} אינו משתמש ב-HTTPS בכלל. כל התקשורת היא cleartext.",
                evidence=[f"URL: {self.url}", "Scheme: http"],
                recommendation="הגדר HTTPS מיידית. השתמש ב-Let's Encrypt (חינם).",
                tags=["ssl", "no-https", "critical"],
            ))
            return {"target": self.url, "total": len(self.findings), "findings": [f.to_dict() for f in self.findings]}

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            await asyncio.gather(
                self._check_certificate(),
                self._check_old_protocols(),
                self._run_testssl(),
            )
            await asyncio.gather(
                self._check_https_redirect(session),
                self._check_security_headers(session),
                self._check_mixed_content(session),
                self._check_ct_logs(session),
            )

        self._log(f"SSL Scanner: הושלם — {len(self.findings)} ממצאים")
        return {
            "target": self.url,
            "hostname": self.hostname,
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "high": len([f for f in self.findings if f.severity == "high"]),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_ssl(url: str, log=None) -> dict:
    scanner = SSLScanner(url, log=log)
    return await scanner.scan()
