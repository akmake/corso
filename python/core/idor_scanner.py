"""
IDOR Scanner
------------
Insecure Direct Object Reference detection.

Techniques:
  1. Probe common API paths with numeric IDs (1, 2, 100...)
  2. Test sequential IDs — if /api/users/1 AND /api/users/2 both return
     different 200 responses without auth → likely IDOR
  3. Test ID=0, negative IDs, UUID brute (short)
  4. Extract IDs from crawled URLs and test neighbours
  5. Check if unauthenticated access returns the same data as auth
"""

import asyncio
import re
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


# Common API path templates to probe for IDOR
_API_PATHS = [
    ("/api/users/{id}",          "users"),
    ("/api/user/{id}",           "user"),
    ("/api/accounts/{id}",       "accounts"),
    ("/api/account/{id}",        "account"),
    ("/api/profile/{id}",        "profile"),
    ("/api/profiles/{id}",       "profiles"),
    ("/api/orders/{id}",         "orders"),
    ("/api/order/{id}",          "order"),
    ("/api/invoices/{id}",       "invoices"),
    ("/api/invoice/{id}",        "invoice"),
    ("/api/payments/{id}",       "payments"),
    ("/api/payment/{id}",        "payment"),
    ("/api/transactions/{id}",   "transactions"),
    ("/api/customers/{id}",      "customers"),
    ("/api/customer/{id}",       "customer"),
    ("/api/products/{id}",       "products"),
    ("/api/items/{id}",          "items"),
    ("/api/messages/{id}",       "messages"),
    ("/api/tickets/{id}",        "tickets"),
    ("/api/reports/{id}",        "reports"),
    ("/api/files/{id}",          "files"),
    ("/api/documents/{id}",      "documents"),
    ("/api/admin/users/{id}",    "admin-users"),
    ("/api/v1/users/{id}",       "users-v1"),
    ("/api/v1/orders/{id}",      "orders-v1"),
    ("/api/v2/users/{id}",       "users-v2"),
    ("/api/v2/orders/{id}",      "orders-v2"),
    ("/users/{id}",              "users"),
    ("/orders/{id}",             "orders"),
    ("/profile/{id}",            "profile"),
    ("/account/{id}",            "account"),
    ("/invoice/{id}",            "invoice"),
    ("/download/{id}",           "download"),
    ("/file/{id}",               "file"),
]

_ID_RE = re.compile(r'/(\d{1,10})(?:/|$|\?)')


def _extract_id_templates(urls: list[str]) -> list[tuple[str, str]]:
    """Return list of (template_url, found_id) from crawled URLs."""
    found = []
    seen: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        m = _ID_RE.search(parsed.path)
        if m:
            obj_id = m.group(1)
            template = (parsed.path[: m.start(1)] + "{id}" + parsed.path[m.end(1) :])
            key = f"{parsed.netloc}{template}"
            if key not in seen:
                seen.add(key)
                base = f"{parsed.scheme}://{parsed.netloc}"
                found.append((base + template, obj_id))
    return found


async def scan_idor(base_url: str, crawled_urls: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    tested: set[str] = set()

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept": "application/json, text/html, */*",
    }

    async def _get(client: httpx.AsyncClient, url: str) -> tuple[int, str, int]:
        try:
            r = await client.get(url, timeout=8, follow_redirects=True)
            return r.status_code, r.text[:3000], len(r.content)
        except Exception:
            return 0, "", 0

    def _content_differs(b1: str, b2: str) -> bool:
        """Returns True if responses are different (different objects returned)."""
        if abs(len(b1) - len(b2)) > 30:
            return True
        # Quick check: different non-trivial content
        strip1 = b1.strip()
        strip2 = b2.strip()
        return strip1 != strip2 and len(strip1) > 20 and len(strip2) > 20

    def _add_idor(path_label: str, id1: int, s1: int, sz1: int,
                  id2: int, s2: int, sz2: int, url_base: str, sev: str = "high"):
        findings.append(Finding(
            sev, "idor",
            f"IDOR חשוד — {path_label}",
            f"שני IDs רצופים ({id1} ו-{id2}) מחזירים נתונים שונים ללא authentication. "
            "ייתכן שניתן לגשת לנתוני משתמשים/הזמנות אחרות.",
            [
                f"URL: {url_base.replace('{id}', str(id1))} → HTTP {s1} ({sz1}B)",
                f"URL: {url_base.replace('{id}', str(id2))} → HTTP {s2} ({sz2}B)",
                "בדוק ידנית: היכנס כמשתמש A, גש ל-ID של משתמש B — האם מקבל מידע?",
            ],
            "הוסף authorization check לכל endpoint: ודא ש-session owner == resource owner. "
            "אל תסמוך על ID בלבד.",
        ))

    async with httpx.AsyncClient(headers=headers, verify=False) as client:

        # ── 1. Probe common API paths ─────────────────────────────────────────
        for path_tpl, category in _API_PATHS:
            # Try ID=1 and ID=2 first to check if endpoint exists
            url1 = base + path_tpl.replace("{id}", "1")
            url2 = base + path_tpl.replace("{id}", "2")

            if url1 in tested:
                continue
            tested.add(url1)
            tested.add(url2)

            s1, b1, sz1 = await _get(client, url1)
            if s1 != 200 or sz1 < 20:
                continue  # Endpoint doesn't exist or empty

            s2, b2, sz2 = await _get(client, url2)

            if s2 == 200 and sz2 >= 20 and _content_differs(b1, b2):
                _add_idor(f"{path_tpl} [{category}]", 1, s1, sz1, 2, s2, sz2,
                          base + path_tpl)

            # Also test ID=0 (sometimes reveals admin/default data)
            url0 = base + path_tpl.replace("{id}", "0")
            s0, b0, sz0 = await _get(client, url0)
            if s0 == 200 and sz0 > 50:
                findings.append(Finding(
                    "medium", "idor",
                    f"IDOR — גישה עם ID=0 — {path_tpl}",
                    f"ID=0 מחזיר תוצאה ב-{path_tpl!r}. עשוי לחשוף נתוני super-admin או ברירת מחדל.",
                    [f"URL: {url0}", f"Status: {s0}", f"Size: {sz0}B"],
                    "חסום IDs ≤ 0 בצד השרת.",
                ))

            # Test a high random-looking ID (if endpoint exists but returns 404 for unknown IDs,
            # yet returns 200 for sequential ones, that's still a sign of IDOR)
            url_high = base + path_tpl.replace("{id}", "9999")
            sh, bh, szh = await _get(client, url_high)
            if sh == 200 and szh >= 20 and _content_differs(b1, bh):
                # Found 3 different objects for 3 IDs — strong IDOR signal
                _add_idor(f"{path_tpl} [{category}] (IDs 1 vs 9999)", 1, s1, sz1,
                          9999, sh, szh, base + path_tpl, sev="high")

        # ── 2. Extract IDs from crawled URLs ──────────────────────────────────
        if crawled_urls:
            extracted = _extract_id_templates(crawled_urls)
            for tpl_url, found_id in extracted[:15]:
                if tpl_url in tested:
                    continue
                tested.add(tpl_url)

                try:
                    int_id = int(found_id)
                except ValueError:
                    continue

                alt_id = int_id + 1 if int_id > 0 else 2
                url_orig = tpl_url.replace("{id}", found_id)
                url_alt  = tpl_url.replace("{id}", str(alt_id))

                s1, b1, sz1 = await _get(client, url_orig)
                s2, b2, sz2 = await _get(client, url_alt)

                if s1 == 200 and s2 == 200 and sz1 >= 20 and sz2 >= 20 and _content_differs(b1, b2):
                    findings.append(Finding(
                        "high", "idor",
                        f"IDOR — ID רציף נגיש — {urlparse(url_orig).path}",
                        f"שני IDs רצופים ({found_id} ו-{alt_id}) מחזירים נתונים שונים ללא authentication.",
                        [
                            f"URL 1: {url_orig} → {s1} ({sz1}B)",
                            f"URL 2: {url_alt} → {s2} ({sz2}B)",
                        ],
                        "הוסף authorization checks. ודא ש-session מתאים ל-resource.",
                    ))

        # ── 3. Query-param based IDOR ─────────────────────────────────────────
        qs_params = ["id", "user_id", "order_id", "uid", "account_id", "customer_id"]
        for param in qs_params:
            url1 = f"{base}?{param}=1"
            url2 = f"{base}?{param}=2"
            if url1 in tested:
                continue
            tested.add(url1)

            s1, b1, sz1 = await _get(client, url1)
            s2, b2, sz2 = await _get(client, url2)

            if s1 == 200 and s2 == 200 and sz1 >= 50 and sz2 >= 50 and _content_differs(b1, b2):
                findings.append(Finding(
                    "medium", "idor",
                    f"IDOR חשוד — Query param ?{param}= ",
                    f"פרמטר ?{param}=1 ו-?{param}=2 מחזירים תוכן שונה. "
                    "ייתכן שניתן לגשת לנתוני משתמשים אחרים.",
                    [f"?{param}=1 → {s1} ({sz1}B)", f"?{param}=2 → {s2} ({sz2}B)"],
                    "הוסף server-side authorization לכל query param המייצג object ID.",
                ))

    # Summary
    vuln = [f for f in findings if f.severity in ("critical", "high", "medium")]
    if not vuln:
        findings.append(Finding(
            "info", "idor",
            f"IDOR — לא זוהו endpoint ים פגיעים ({len(_API_PATHS)} נבדקו)",
            "לא נמצאו עדויות ל-IDOR. בדיקה ידנית מומלצת עם שני משתמשים שונים.",
            [f"Endpoints tested: {len(tested)}", f"Base: {base_url}"],
        ))

    return findings
