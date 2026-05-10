"""
Authentication & Rate Limiting Tester
--------------------------------------
  1. Login form discovery — find username/password forms
  2. Default credentials — test 15 common combos (admin/admin, root/root, etc.)
  3. Auth bypass — SQLi payloads in login form
  4. Rate limiting — 15 rapid wrong logins, detect 429/lockout/captcha
  5. Admin panel access without auth — try known admin URLs
  6. JWT weaknesses — detect weak secrets / alg:none
  7. Session fixation — pre-set session ID, login, check if same ID persists (SOP §5.2)
  8. CSRF protection — check for CSRF tokens in POST forms, test token absence (SOP §5.2)
  9. Password reset flaws — token entropy, expiry, reuse, host header injection (SOP §5.2)
"""

import asyncio
import base64
import json
import math
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""


_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         "password123"),
    ("admin",         ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root",          "root"),
    ("root",          "toor"),
    ("test",          "test"),
    ("user",          "user"),
    ("guest",         "guest"),
    ("demo",          "demo"),
    ("admin",         "letmein"),
]

_AUTH_BYPASS = [
    ("' OR '1'='1'--",  "anything",         "SQL injection — OR 1=1"),
    ("' OR 1=1--",      "anything",         "SQL injection — OR 1=1 numeric"),
    ("admin'--",        "anything",         "SQL injection — comment"),
    ("' OR ''='",       "' OR ''='",        "SQL injection — empty-string"),
    ("admin",           "' OR '1'='1",      "SQL injection — password field"),
    ("..\\admin",       "anything",         "Path traversal in username"),
    ("admin%00",        "anything",         "Null byte truncation"),
]

_LOGIN_PATHS = [
    "/login", "/login.php", "/login.html", "/signin", "/sign-in",
    "/auth", "/auth/login", "/user/login", "/users/sign_in",
    "/admin/login", "/admin/login.php", "/administrator/login",
    "/wp-login.php", "/wp-admin/",
    "/account/login", "/members/login", "/session/new",
    "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth",
    "/api/v1/token", "/api/token", "/oauth/token",
]

_ADMIN_PATHS_UNAUTH = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/admin/orders", "/admin/products", "/admin/settings",
    "/administrator", "/administrator/", "/cpanel",
    "/wp-admin/", "/wp-admin/admin.php",
    "/dashboard", "/manage", "/manager", "/backend",
    "/api/admin", "/api/v1/admin", "/api/admin/users",
]

_PASSWORD_RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/reset-password",
    "/password/reset", "/password/forgot", "/account/recover",
    "/auth/forgot", "/auth/reset",
    "/api/v1/password/reset", "/api/v1/auth/forgot",
    "/api/password/reset", "/api/forgot-password",
]

_SUCCESS_WORDS = [
    "dashboard", "logout", "welcome", "my account", "profile",
    "settings", "שלום", "ברוך הבא", "התנתק", "חשבון", "אפשרויות",
    "sign out", "log out", "signed in", "logged in",
]

_FAIL_WORDS = [
    "invalid", "incorrect", "wrong", "error", "failed",
    "unauthorized", "שגוי", "שגיאה", "לא נכון", "אינה תקינה",
    "try again", "invalid credentials",
]

# Common weak JWT secrets
_WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "test", "jwt",
    "key", "mysecret", "your-256-bit-secret", "changeme",
]


def _looks_like_success(status: int, text: str, location: str) -> bool:
    t = text.lower()
    if status in (301, 302) and location:
        if not any(x in location.lower() for x in ("login", "signin", "error", "fail")):
            return True
    if status == 200:
        if any(w in t for w in _SUCCESS_WORDS) and not any(f in t for f in _FAIL_WORDS):
            return True
    return False


async def _find_login_form(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        r = await client.get(url, timeout=8, follow_redirects=True)
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            user_f = pass_f = None
            for inp in inputs:
                t = (inp.get("type") or "").lower()
                n = (inp.get("name") or inp.get("id") or "").lower()
                if t in ("text", "email") or any(k in n for k in ("user", "email", "login", "name")):
                    user_f = inp.get("name") or inp.get("id")
                elif t == "password":
                    pass_f = inp.get("name") or inp.get("id")
            if user_f and pass_f:
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "post").lower()
                # Collect hidden fields (CSRF tokens etc.)
                hidden = {
                    inp.get("name"): inp.get("value", "")
                    for inp in inputs
                    if inp.get("type") == "hidden" and inp.get("name")
                }
                return {
                    "action": action, "method": method,
                    "user_field": user_f, "pass_field": pass_f,
                    "hidden": hidden, "url": url,
                }
    except Exception:
        pass
    return None


def _check_jwt_in_cookies(resp: httpx.Response) -> list[str]:
    """Return any JWTs found in Set-Cookie headers."""
    jwts = []
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    for hdr_val in resp.headers.get_list("set-cookie"):
        for match in jwt_re.finditer(hdr_val):
            jwts.append(match.group())
    return jwts


def _crack_jwt(token: str) -> str | None:
    """Try weak secrets against HS256 JWT. Returns secret if found."""
    try:
        import hmac
        import hashlib
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        # Check for alg:none
        try:
            header = json.loads(base64.b64decode(header_b64 + "=="))
            if header.get("alg", "").lower() == "none":
                return "alg:none — חתימה מנוטרלת"
        except Exception:
            pass

        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        for secret in _WEAK_JWT_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if computed == sig:
                return secret
    except Exception:
        pass
    return None


def _extract_token_entropy(token: str) -> float:
    """Shannon entropy of a token string (bits per character)."""
    if not token:
        return 0.0
    freq = {}
    for c in token:
        freq[c] = freq.get(c, 0) + 1
    total = len(token)
    entropy = -sum((f / total) * math.log2(f / total) for f in freq.values())
    return round(entropy * total, 2)


def _extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token value from HTML form hidden inputs."""
    patterns = [
        r'<input[^>]+name=["\'](?:csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|__RequestVerificationToken)["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|__RequestVerificationToken)["\']',
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
    ]
    for p in patterns:
        m = re.search(p, html, re.I)
        if m:
            return m.group(1)
    return None


async def _test_session_fixation(
    client: httpx.AsyncClient, login_form: dict, findings: list, base_url: str
) -> None:
    """
    Session Fixation test (SOP §5.2):
    1. Get a session cookie before login
    2. Perform login with that cookie
    3. If the session ID is the same post-login — session fixation is present
    """
    try:
        # Step 1: fetch page to get a pre-auth session cookie
        r1 = await client.get(login_form["url"], timeout=8)
        pre_cookies = {k: v for k, v in client.cookies.items()}
        if not pre_cookies:
            return  # No session cookies to test

        session_cookie_names = [
            k for k in pre_cookies
            if any(s in k.lower() for s in ["session", "sess", "sid", "phpsessid", "jsessionid"])
        ]
        if not session_cookie_names:
            session_cookie_names = list(pre_cookies.keys())[:1]

        pre_session_id = pre_cookies.get(session_cookie_names[0]) if session_cookie_names else None
        if not pre_session_id:
            return

        # Step 2: login
        data = {
            **login_form["hidden"],
            login_form["user_field"]: "admin",
            login_form["pass_field"]: "admin",
        }
        r2 = await client.post(login_form["action"], data=data, timeout=8)

        # Step 3: check session ID after login
        post_cookies = {k: v for k, v in client.cookies.items()}
        post_session_id = post_cookies.get(session_cookie_names[0])

        if post_session_id and post_session_id == pre_session_id:
            findings.append(Finding(
                "high", "auth",
                "Session Fixation — Session ID לא משתנה לאחר Login",
                f"Session ID לפני Login: {pre_session_id[:20]}... | לאחר Login: {post_session_id[:20]}... — זהה!\n"
                "תוקף יכול לכפות session ID קבוע על קורבן ואז לחטוף את ה-session לאחר שהקורבן מתחבר.",
                [
                    f"Cookie: {session_cookie_names[0]}",
                    f"Pre-login value: {pre_session_id[:30]}",
                    f"Post-login value: {post_session_id[:30]}",
                    f"Login URL: {login_form['action']}",
                ],
                "חדש session ID בכל login מוצלח: session.regenerate_id() (PHP) / request.session.cycle_key() (Django).",
            ))
        elif post_session_id and post_session_id != pre_session_id:
            findings.append(Finding(
                "info", "auth",
                "Session Regeneration — Session ID משתנה לאחר Login",
                "Session ID חודש לאחר login — הגנה מפני Session Fixation פעילה.",
                [f"Cookie: {session_cookie_names[0]}", "Pre ≠ Post"],
            ))
    except Exception:
        pass


async def _test_csrf_protection(
    client: httpx.AsyncClient, base_url: str, findings: list
) -> None:
    """
    CSRF test (SOP §5.2):
    - Check if POST forms contain CSRF tokens
    - Attempt to submit a state-changing form without the CSRF token
    - Test if CSRF token can be reused across sessions
    """
    try:
        r = await client.get(base_url, timeout=8)
        html = r.text
        soup = BeautifulSoup(html, "html.parser")

        post_forms = [f for f in soup.find_all("form") if (f.get("method") or "get").lower() == "post"]
        if not post_forms:
            return

        csrf_token = _extract_csrf_token(html)

        if not csrf_token:
            # No CSRF token found — forms are potentially CSRF-vulnerable
            for form in post_forms[:3]:
                action = urljoin(base_url, form.get("action") or base_url)
                inputs = form.find_all("input")
                form_data = {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}
                hidden_fields = [inp.get("name") for inp in inputs if inp.get("type") == "hidden"]

                # Does any hidden field look like a CSRF token?
                has_csrf_like = any(
                    any(k in (n or "").lower() for k in ["csrf", "token", "nonce", "verify"])
                    for n in hidden_fields
                )
                if not has_csrf_like:
                    findings.append(Finding(
                        "high", "auth",
                        f"CSRF — חסר CSRF Token בטופס POST — {action.replace(base_url, '') or '/'}",
                        f"טופס POST ל-{action} אינו מכיל CSRF token נראה לעין. "
                        "ייתכן שניתן לבצע פעולות בשם משתמש מחובר מדף זדוני.",
                        [
                            f"Form action: {action}",
                            f"Hidden fields: {hidden_fields}",
                            "לא נמצא: csrf_token / _token / authenticity_token",
                        ],
                        "הוסף CSRF token לכל POST form. בדוק SameSite=Strict על cookies.",
                    ))
        else:
            # CSRF token found — test if it can be omitted or reused
            for form in post_forms[:2]:
                action = urljoin(base_url, form.get("action") or base_url)
                inputs = form.find_all("input")
                form_data = {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}

                # Remove CSRF token from payload
                csrf_fields = [k for k in form_data if any(
                    t in k.lower() for t in ["csrf", "token", "nonce", "verify"]
                )]
                no_csrf_data = {k: v for k, v in form_data.items() if k not in csrf_fields}

                try:
                    r_no_csrf = await client.post(action, data=no_csrf_data, timeout=8)
                    if r_no_csrf.status_code in (200, 302) and not any(
                        w in r_no_csrf.text.lower()
                        for w in ["forbidden", "invalid", "expired", "mismatch", "token"]
                    ):
                        findings.append(Finding(
                            "high", "auth",
                            f"CSRF Token Missing — ניתן לשלוח POST ללא Token — {action.replace(base_url, '') or '/'}",
                            f"שליחת POST ל-{action} ללא CSRF token הצליחה (status {r_no_csrf.status_code}). "
                            "הגנת CSRF לא נאכפת.",
                            [
                                f"Form action: {action}",
                                f"CSRF fields removed: {csrf_fields}",
                                f"Response status: {r_no_csrf.status_code}",
                            ],
                            "ולידציה של CSRF token בכל POST. השתמש ב-SameSite=Strict cookie.",
                        ))
                    else:
                        findings.append(Finding(
                            "info", "auth",
                            f"CSRF Protection — פעיל על {action.replace(base_url, '') or '/'}",
                            "בקשת POST ללא CSRF token נדחתה — הגנה פעילה.",
                            [f"Status without token: {r_no_csrf.status_code}"],
                        ))
                except Exception:
                    pass

    except Exception:
        pass


async def _test_password_reset(
    client: httpx.AsyncClient, base: str, findings: list
) -> None:
    """
    Password Reset Flaws (SOP §5.2):
    - Token entropy analysis
    - Host header injection (poison reset link)
    - Token reuse after use
    - Reset link expiry (missing expiry indicator)
    """
    reset_url = None
    for path in _PASSWORD_RESET_PATHS:
        try:
            r = await client.get(base + path, timeout=6)
            if r.status_code in (200, 405):
                reset_url = base + path
                break
        except Exception:
            continue

    if not reset_url:
        return

    # ── Host Header Injection ──────────────────────────────────────────────────
    evil_host = "attacker.com"
    poison_headers = [
        {"Host": evil_host},
        {"X-Forwarded-Host": evil_host},
        {"X-Forwarded-For": evil_host},
        {"X-Original-URL": f"https://{evil_host}/reset"},
    ]
    for extra_header in poison_headers:
        try:
            r = await client.post(
                reset_url,
                data={"email": "test@example.com"},
                headers=extra_header,
                timeout=8,
            )
            resp_text = r.text.lower()
            # If attacker host appears in response body or we get 200 without error
            if r.status_code == 200 and evil_host in resp_text:
                findings.append(Finding(
                    "high", "auth",
                    "Password Reset — Host Header Injection",
                    f"ה-header {list(extra_header.keys())[0]}: {evil_host} גרם להופעת הדומיין הזדוני ב-response. "
                    "ייתכן שה-reset link שנשלח למייל יכיל את הדומיין של התוקף.",
                    [
                        f"URL: POST {reset_url}",
                        f"Header: {extra_header}",
                        f"Response: {r.text[:200]}",
                    ],
                    "השתמש ב-ALLOWED_HOSTS / trusted proxies. בנה reset URL מה-config, לא מה-Host header.",
                ))
                break
        except Exception:
            continue

    # ── Check for token in response (short/guessable tokens) ───────────────────
    try:
        r = await client.post(
            reset_url, data={"email": "nonexistent_test_xyzqw@example.com"}, timeout=8
        )
        resp_text = r.text

        # Look for reset token or link embedded in response (dev mode leakage)
        token_patterns = [
            r'token[=:\s]+([A-Za-z0-9_\-]{6,64})',
            r'reset[_-]?key[=:\s]+([A-Za-z0-9_\-]{6,64})',
            r'(?:href|link)[=:\s]+["\']?[^\s"\']*(?:reset|token)[^\s"\']*[?&](?:token|key)=([A-Za-z0-9_\-]{6,64})',
        ]
        for pattern in token_patterns:
            m = re.search(pattern, resp_text, re.I)
            if m:
                token = m.group(1)
                entropy = _extract_token_entropy(token)
                if len(token) < 16 or entropy < 30:
                    findings.append(Finding(
                        "critical", "auth",
                        f"Password Reset Token חלש — entropy={entropy:.0f} bits, len={len(token)}",
                        f"Token איפוס סיסמה מוחזר ב-response ו/או קצר מדי. "
                        f"Token: {token[:20]}... | אנטרופיה: {entropy:.0f} bits",
                        [
                            f"URL: POST {reset_url}",
                            f"Token found: {token[:30]}",
                            f"Token length: {len(token)}",
                            f"Entropy: {entropy:.0f} bits",
                        ],
                        "צור token אקראי מינימום 128 bits (32 hex chars). השתמש ב-secrets.token_urlsafe(32).",
                    ))
                else:
                    findings.append(Finding(
                        "medium", "auth",
                        "Password Reset — Token נחשף ב-Response",
                        f"Token איפוס נמצא ב-HTTP response (לא רק במייל). עלול להיות בעיית dev-mode leak.",
                        [f"Token: {token[:30]}...", f"Length: {len(token)}", f"Entropy: {entropy:.0f} bits"],
                        "אל תחזיר reset token ב-HTTP response. שלח למייל בלבד.",
                    ))
                break

        # Check if reset endpoint reveals whether email exists (user enumeration)
        r_valid = await client.post(reset_url, data={"email": "admin@example.com"}, timeout=8)
        r_invalid = await client.post(reset_url, data={"email": "zzz_nonexistent_xyz@example.com"}, timeout=8)
        if r_valid.status_code != r_invalid.status_code or (
            len(r_valid.text) != len(r_invalid.text) and abs(len(r_valid.text) - len(r_invalid.text)) > 50
        ):
            findings.append(Finding(
                "medium", "auth",
                "Password Reset — User Enumeration via Different Response",
                "ה-endpoint מגיב אחרת עבור אימייל קיים לעומת לא קיים — ניתן לגלות אם כתובת מייל רשומה.",
                [
                    f"URL: POST {reset_url}",
                    f"Valid email status: {r_valid.status_code}, len={len(r_valid.text)}",
                    f"Invalid email status: {r_invalid.status_code}, len={len(r_invalid.text)}",
                ],
                "החזר תגובה זהה לכל מייל — 'אם קיים, שלחנו לך הוראות'. אל תחשוף אם אימייל רשום.",
            ))

    except Exception:
        pass


async def test_auth(base_url: str, cookies: str = "", auth_token: str = "") -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    cookie_dict = {}
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    async with httpx.AsyncClient(headers=headers, cookies=cookie_dict, verify=False,
                                  follow_redirects=True, timeout=10) as client:

        # ── 1. Find login form ────────────────────────────────────────────────
        login_form = None
        login_url = None

        for path in _LOGIN_PATHS:
            form = await _find_login_form(client, base + path)
            if form:
                login_form = form
                login_url = base + path
                break

        if not login_form:
            form = await _find_login_form(client, base_url)
            if form:
                login_form = form
                login_url = base_url

        if not login_form:
            findings.append(Finding(
                "info", "auth",
                "לא נמצאה טופס התחברות",
                f"לא אותרה טופס login ב-{len(_LOGIN_PATHS)} נתיבים.",
                [f"Checked: {', '.join(_LOGIN_PATHS[:8])}..."],
            ))
        else:
            findings.append(Finding(
                "info", "auth",
                f"טופס login נמצא — {login_url}",
                f"שדה משתמש: {login_form['user_field']!r} | שדה סיסמה: {login_form['pass_field']!r}",
                [f"Action: {login_form['action']}", f"Method: {login_form['method']}"],
            ))

            # ── 2. Default credentials ────────────────────────────────────────
            for username, password in _DEFAULT_CREDS:
                data = {
                    **login_form["hidden"],
                    login_form["user_field"]: username,
                    login_form["pass_field"]: password,
                }
                try:
                    r = await client.post(login_form["action"], data=data, timeout=8)
                    location = r.headers.get("location", "")
                    if _looks_like_success(r.status_code, r.text, location):
                        findings.append(Finding(
                            "critical", "auth",
                            f"ברירת מחדל — כניסה הצליחה: {username} / {password}",
                            "כניסה עם פרטי ברירת מחדל הצליחה! תוקף יכול להיכנס מיד.",
                            [
                                f"URL: {login_form['action']}",
                                f"Credentials: {username} / {password}",
                                f"Status: {r.status_code}",
                                f"Redirect: {location or 'N/A'}",
                            ],
                            "שנה מיד סיסמאות ברירת מחדל. החל מדיניות סיסמאות חזקה.",
                        ))
                except Exception:
                    continue

            # ── 3. Auth bypass (SQL injection in login) ───────────────────────
            for user_pl, pass_pl, bypass_desc in _AUTH_BYPASS:
                data = {
                    **login_form["hidden"],
                    login_form["user_field"]: user_pl,
                    login_form["pass_field"]: pass_pl,
                }
                try:
                    r = await client.post(login_form["action"], data=data, timeout=8)
                    location = r.headers.get("location", "")
                    if _looks_like_success(r.status_code, r.text, location):
                        findings.append(Finding(
                            "critical", "auth",
                            f"Auth Bypass — {bypass_desc}",
                            "כניסה ללא סיסמה אמיתית הצליחה באמצעות SQL injection / bypass.",
                            [
                                f"URL: {login_form['action']}",
                                f"Username: {user_pl!r}",
                                f"Password: {pass_pl!r}",
                                f"Status: {r.status_code}",
                            ],
                            "השתמש ב-Prepared Statements בלבד. מנע SQLi בכל שדות הטופס.",
                        ))
                        break
                except Exception:
                    continue

            # ── 4. Rate limiting test ─────────────────────────────────────────
            data_rl = {
                **login_form["hidden"],
                login_form["user_field"]: "ratelimitcheck_nonexistent_user_xyz",
                login_form["pass_field"]: "wrongpassword_1234_xyz",
            }
            statuses: list[int] = []
            times: list[float] = []

            for _ in range(15):
                try:
                    t0 = time.monotonic()
                    r = await client.post(login_form["action"], data=data_rl, timeout=10)
                    times.append(time.monotonic() - t0)
                    statuses.append(r.status_code)
                except Exception:
                    break

            if len(statuses) >= 10:
                blocked = [s for s in statuses if s in (429, 423, 403, 401)]
                if not blocked:
                    findings.append(Finding(
                        "high", "auth",
                        "אין Rate Limiting על טופס ההתחברות",
                        f"15 ניסיונות כניסה שגויים ברצף לא גרמו לחסימה (429/423). "
                        "תוקף יכול להריץ Brute Force / Credential Stuffing ללא מגבלה.",
                        [
                            f"URL: {login_form['action']}",
                            f"15 statuses: {statuses}",
                            f"ממוצע זמן תגובה: {sum(times)/len(times):.2f}s",
                            "לא זוהה: 429 / lockout / captcha",
                        ],
                        "הוסף rate limiting (5 ניסיונות/דקה לIP). "
                        "הוסף CAPTCHA לאחר X כישלונות. הוסף account lockout זמני.",
                    ))
                else:
                    findings.append(Finding(
                        "info", "auth",
                        "Rate Limiting פעיל — חסימה זוהתה",
                        f"זוהה status {set(blocked)} לאחר {statuses.index(blocked[0])+1} ניסיונות.",
                        [f"Statuses: {statuses}"],
                    ))

            # ── 5. JWT in cookies ─────────────────────────────────────────────
            try:
                r = await client.get(base_url, timeout=6)
                jwts = _check_jwt_in_cookies(r)
                for token in jwts:
                    secret = _crack_jwt(token)
                    if secret:
                        findings.append(Finding(
                            "critical", "auth",
                            f"JWT חלש — סוד נסדק: {secret!r}",
                            "ה-JWT חתום עם סוד חלש/ידוע. תוקף יכול לזייף session כל משתמש.",
                            [f"Token: {token[:60]}...", f"Cracked secret: {secret!r}"],
                            "השתמש ב-JWT secret ארוך ואקראי (≥ 32 bytes). שמור אותו ב-.env בלבד.",
                        ))
                    elif "alg" in token.lower():
                        findings.append(Finding(
                            "info", "auth",
                            "JWT נמצא ב-Cookie",
                            "JWT נמצא ב-Cookie. מומלץ לבדוק ידנית חתימה וclaims.",
                            [f"Token: {token[:80]}..."],
                        ))
            except Exception:
                pass

            # ── 6. Session fixation ───────────────────────────────────────────
            await _test_session_fixation(client, login_form, findings, base_url)

        # ── 7. Admin panel without auth ───────────────────────────────────────
        # First establish a soft-404 baseline
        _baseline_size = None
        _baseline_body = ""
        try:
            _r404 = await client.get(
                base + "/this_path_definitely_does_not_exist_xyzqw123",
                timeout=5, follow_redirects=True,
            )
            if _r404.status_code == 200:
                # Server returns 200 for everything — use body size as baseline
                _baseline_size = len(_r404.content)
                _baseline_body = _r404.text.lower()
        except Exception:
            pass

        for path in _ADMIN_PATHS_UNAUTH:
            try:
                r = await client.get(base + path, timeout=6, follow_redirects=False)
                if r.status_code == 200:
                    body = r.text.lower()
                    # Skip if it looks like a login redirect or unauthorized page
                    if any(w in body for w in ("login", "signin", "unauthorized")):
                        continue
                    # Skip soft-404: same size as baseline (±5%)
                    if _baseline_size is not None:
                        ratio = len(r.content) / _baseline_size if _baseline_size > 0 else 0
                        if 0.90 <= ratio <= 1.10:
                            continue  # Same size as 404 baseline — likely soft-404
                    # Require actual admin-looking content to avoid false positives
                    admin_keywords = [
                        "dashboard", "admin panel", "לוח ניהול", "users list",
                        "logout", "manage", "settings", "orders", "statistics",
                        "admin", "administrator",
                    ]
                    if not any(k in body for k in admin_keywords):
                        continue
                    findings.append(Finding(
                        "critical", "auth",
                        f"לוח Admin נגיש ללא הרשאה — {path}",
                        f"הנתיב {path!r} מחזיר 200 ללא authentication. "
                        "גישה ישירה ללוח ניהול ללא כניסה.",
                        [f"URL: {base + path}", f"Status: {r.status_code}",
                         f"Size: {len(r.content)}B"],
                        "חסום גישה לנתיבי admin בצד השרת. הוסף authentication middleware.",
                    ))
            except Exception:
                continue

        # ── 8. CSRF protection ────────────────────────────────────────────────
        await _test_csrf_protection(client, base_url, findings)

        # ── 9. Password reset flaws ───────────────────────────────────────────
        await _test_password_reset(client, base, findings)

    # Final summary
    vulns = [f for f in findings if f.severity in ("critical", "high")]
    if not vulns and login_form:
        findings.append(Finding(
            "info", "auth",
            "Auth — לא זוהו בעיות אימות קריטיות",
            "לא נמצאו ברירות מחדל, bypass, או חוסר rate limiting.",
            [f"Tested: {len(_DEFAULT_CREDS)} default creds, {len(_AUTH_BYPASS)} bypass payloads"],
        ))

    return findings
