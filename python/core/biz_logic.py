"""
Business Logic Scanner
-----------------------
E-commerce specific logic flaws:
  1. Price manipulation  — inject negative / zero price via form params & API
  2. Quantity tampering  — negative qty, decimal, zero, overflow
  3. Coupon abuse        — empty code, duplicate, stack unlimited
  4. Cart/order API tampering — JSON payload price injection
  5. Payment bypass      — skip payment step, manipulate amount field
  6. Privilege escalation via param — role=admin, is_admin=true
  7. Race condition      — 20 concurrent requests to same cart endpoint (SOP §5.3)
  8. Coupon stacking     — apply same coupon multiple times, apply several at once
  9. Workflow step-skip  — direct access to later checkout steps
"""

import asyncio
import re
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


_PRICE_PARAMS = [
    "price", "amount", "total", "cost", "value", "subtotal",
    "grand_total", "order_total", "payment_amount", "charge",
    "fee", "sum", "price_total", "item_price", "unit_price",
    "discount_amount", "tax_amount",
]

_QTY_PARAMS = [
    "quantity", "qty", "count", "num", "units", "quantity[]", "qty[]",
]

_COUPON_PARAMS = [
    "coupon", "coupon_code", "discount_code", "promo", "promo_code",
    "voucher", "code", "gift_card", "referral_code",
]

_ROLE_PARAMS = [
    "role", "is_admin", "admin", "is_staff", "user_type",
    "account_type", "membership", "level", "group",
]

_CART_ENDPOINTS = [
    "/cart", "/basket", "/checkout", "/order", "/purchase",
    "/cart/add", "/cart/update", "/cart/item",
    "/api/cart", "/api/order", "/api/checkout",
    "/api/cart/add", "/api/cart/update", "/api/basket",
    "/store/cart", "/shop/cart", "/shop/checkout",
    "/wp-json/wc/v3/cart", "/wp-json/wc/v3/orders",
    "/api/v1/cart", "/api/v1/order", "/api/v1/checkout",
    "/api/v2/cart", "/api/v2/order",
]

_PRICE_ATTACKS = [
    ("-1",          "מחיר שלילי"),
    ("-0.01",       "מחיר שלילי עשרוני"),
    ("0",           "מחיר אפס"),
    ("0.00",        "מחיר אפסי"),
    ("0.001",       "מחיר זעיר"),
    ("0.01",        "מחיר מינימלי"),
    ("999999999",   "overflow מחיר"),
    ("1e-10",       "floating point זעיר"),
]

_QTY_ATTACKS = [
    ("-1",     "כמות שלילית"),
    ("-100",   "כמות שלילית גדולה"),
    ("0",      "כמות אפס"),
    ("999999", "כמות ענקית"),
    ("1.5",    "כמות עשרונית"),
    ("1e10",   "כמות floating point"),
]

_ROLE_ATTACKS = [
    ("admin",    "role=admin"),
    ("true",     "is_admin=true"),
    ("1",        "is_admin=1"),
    ("staff",    "role=staff"),
    ("manager",  "role=manager"),
]


def _accepted(status: int, body: str) -> bool:
    """True if server seems to have accepted the manipulated value."""
    if status not in (200, 201, 302, 303):
        return False
    body_l = body.lower()
    return not any(w in body_l for w in [
        "error", "invalid", "not valid", "rejected", "שגיאה",
        "לא תקין", "bad request", "cannot", "failed", "forbidden",
    ])


async def scan_biz_logic(base_url: str, cookies: str = "", auth_token: str = "") -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    tested: set[str] = set()

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept": "application/json, text/html, */*",
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

        # ── 0. Establish soft-404 baseline ────────────────────────────────────
        # Many sites return HTTP 200 for all unknown paths (soft-404).
        # We fingerprint this to avoid false positives.
        _soft404_size: int | None = None
        _soft404_snippet: str = ""
        try:
            r404 = await client.get(base + "/xyzzy_nonexistent_path_abc123", timeout=5)
            if r404.status_code == 200:
                _soft404_size = len(r404.content)
                _soft404_snippet = r404.text[:200]
        except Exception:
            pass

        def _is_soft404(resp) -> bool:
            """True if this response looks like the site's generic soft-404 page."""
            if _soft404_size is None:
                return False
            size = len(resp.content)
            # Same size ±15%
            if _soft404_size > 0 and 0.85 <= size / _soft404_size <= 1.15:
                return True
            # If the snippet matches
            if _soft404_snippet and resp.text[:200] == _soft404_snippet:
                return True
            return False

        def _is_real_api_response(resp) -> bool:
            """True only if response looks like real API data, not a generic page."""
            ct = resp.headers.get("content-type", "")
            if "application/json" in ct:
                return True
            # Must NOT be a soft-404
            if _is_soft404(resp):
                return False
            # Must NOT be large HTML (generic page)
            if "text/html" in ct and len(resp.content) > 8_000:
                return False
            return True

        # ── 1. Discover cart / checkout endpoints ─────────────────────────────
        active_endpoints: list[str] = []
        for path in _CART_ENDPOINTS:
            url = base + path
            if url in tested:
                continue
            tested.add(url)
            try:
                r = await client.get(url, timeout=5)
                # Only count as active if NOT a soft-404
                if r.status_code in (200, 405, 422) and not _is_soft404(r):
                    active_endpoints.append(url)
                elif r.status_code in (405, 422):
                    # 405/422 always means endpoint exists (wrong method is fine)
                    active_endpoints.append(url)
            except Exception:
                continue

        if active_endpoints:
            findings.append(Finding(
                "info", "biz_logic",
                f"נמצאו {len(active_endpoints)} נקודות קצה של עגלה/קופה",
                "נמצאו endpoints הקשורים לרכישה — יתבצע fuzzing על פרמטרי מחיר/כמות.",
                active_endpoints,
            ))

        # ── 2. Crawl base page for forms with price/qty/coupon params ─────────
        try:
            r = await client.get(base_url, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            page_forms = soup.find_all("form")
        except Exception:
            page_forms = []

        for form in page_forms:
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "post").lower()
            inputs = form.find_all("input")
            form_data: dict[str, str] = {}
            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name:
                    form_data[name] = value

            field_names = [n.lower() for n in form_data]

            # Price manipulation
            for f_name in form_data:
                if any(p in f_name.lower() for p in _PRICE_PARAMS):
                    for val, desc in _PRICE_ATTACKS[:4]:
                        test_data = {**form_data, f_name: val}
                        try:
                            r = await client.request(method, action, data=test_data, timeout=8)
                            if _accepted(r.status_code, r.text):
                                findings.append(Finding(
                                    "critical", "biz_logic",
                                    f"מניפולציית מחיר — {f_name}={val} ({desc})",
                                    f"פרמטר '{f_name}'={val!r} התקבל ללא שגיאה. "
                                    "אם השרת לא מאמת מחיר בצד השרת — ניתן לרכוש בחינם.",
                                    [
                                        f"Form action: {action}",
                                        f"Param: {f_name}={val}",
                                        f"Status: {r.status_code}",
                                        "בדוק ידנית: האם ההזמנה נוצרה עם המחיר המניפולטיבי?",
                                    ],
                                    "חשב מחיר תמיד בצד השרת מתוך מסד הנתונים. "
                                    "אל תסמוך על מחיר שמגיע מה-client.",
                                ))
                                break
                        except Exception:
                            continue

            # Quantity manipulation
            for f_name in form_data:
                if any(p in f_name.lower() for p in _QTY_PARAMS):
                    for val, desc in _QTY_ATTACKS[:4]:
                        test_data = {**form_data, f_name: val}
                        try:
                            r = await client.request(method, action, data=test_data, timeout=8)
                            if _accepted(r.status_code, r.text):
                                findings.append(Finding(
                                    "high", "biz_logic",
                                    f"מניפולציית כמות — {f_name}={val} ({desc})",
                                    f"פרמטר '{f_name}'={val!r} התקבל. "
                                    "כמות שלילית עלולה ליצור זיכוי; כמות ענקית — חוסר במלאי.",
                                    [f"Param: {f_name}={val}", f"Status: {r.status_code}"],
                                    "ודא בצד השרת: כמות > 0, כמות ≤ מלאי זמין, כמות שלמה.",
                                ))
                                break
                        except Exception:
                            continue

            # Coupon abuse
            for f_name in form_data:
                if any(p in f_name.lower() for p in _COUPON_PARAMS):
                    # Test empty coupon
                    test_data = {**form_data, f_name: ""}
                    try:
                        r = await client.request(method, action, data=test_data, timeout=8)
                        if _accepted(r.status_code, r.text) and "discount" in r.text.lower():
                            findings.append(Finding(
                                "high", "biz_logic",
                                f"קופון ריק מקבל הנחה — {f_name}=''",
                                "שדה הקופון הריק מוחל כהנחה. עלול לאפשר הנחה ללא קוד.",
                                [f"Param: {f_name}=''", f"Status: {r.status_code}"],
                                "ודא שקוד קופון לא ריק ותקף לפני החלת הנחה.",
                            ))
                    except Exception:
                        pass

        # ── 3. API-based price injection ──────────────────────────────────────
        for url in active_endpoints:
            # First verify this endpoint actually responds as an API (not a soft-404)
            try:
                probe = await client.get(url, timeout=5)
                if probe.status_code == 404 or _is_soft404(probe):
                    continue
            except Exception:
                continue

            # Try JSON price injection — collect ALL vulnerable params, then emit ONE finding
            vulnerable_price = []
            for price_param in _PRICE_PARAMS[:6]:
                for val, desc in _PRICE_ATTACKS[:3]:
                    payload = {
                        price_param: val,
                        "quantity": 1,
                        "product_id": 1,
                        "item_id": 1,
                    }
                    key = f"{url}|{price_param}|{val}"
                    if key in tested:
                        continue
                    tested.add(key)
                    try:
                        r = await client.post(
                            url, json=payload, timeout=6,
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        if r.status_code in (200, 201) and _accepted(r.status_code, r.text) and _is_real_api_response(r):
                            vulnerable_price.append((price_param, val, desc))
                            break  # one success per param is enough
                    except Exception:
                        continue

            if vulnerable_price:
                path = urlparse(url).path
                params_summary = ", ".join(f"{p}={v}" for p, v, _ in vulnerable_price[:5])
                findings.append(Finding(
                    "critical", "biz_logic",
                    f"API Price Injection — {path} ({len(vulnerable_price)} פרמטרים)",
                    f"Endpoint {path} קיבל ערכי מחיר מניפולטיביים ללא שגיאה. "
                    "בדוק ידנית: האם ההזמנה נוצרה עם המחיר המניפולטיבי?",
                    [
                        f"URL: {url}",
                        f"Vulnerable params: {params_summary}",
                        f"Total vulnerable params: {len(vulnerable_price)}",
                        "דורש בדיקה ידנית לאימות שמירה בDB",
                    ],
                    "אל תסמוך על מחיר מה-client. חשב תמיד בצד השרת.",
                ))

            # Form-encoded qty injection — one finding per endpoint
            qty_found = None
            for qty_param in _QTY_PARAMS[:4]:
                payload = {qty_param: "-1", "product_id": "1"}
                key = f"{url}|qty|-1"
                if key in tested:
                    continue
                tested.add(key)
                try:
                    r = await client.post(url, data=payload, timeout=6)
                    if _accepted(r.status_code, r.text) and _is_real_api_response(r):
                        qty_found = qty_param
                        break
                except Exception:
                    continue

            if qty_found:
                findings.append(Finding(
                    "high", "biz_logic",
                    f"API כמות שלילית — {urlparse(url).path}",
                    f"API קיבל {qty_found}=-1 ללא שגיאה. כמות שלילית עלולה ליצור זיכוי.",
                    [f"URL: {url}", f"Param: {qty_found}=-1"],
                    "ודא כמות > 0 בצד השרת.",
                ))

        # ── 4. Privilege escalation via request params ────────────────────────
        for role_param in _ROLE_PARAMS:
            for attack_val, desc in _ROLE_ATTACKS:
                test_url = f"{base_url}?{role_param}={attack_val}"
                key = f"role|{role_param}|{attack_val}"
                if key in tested:
                    continue
                tested.add(key)
                try:
                    r = await client.get(test_url, timeout=6)
                    body = r.text.lower()
                    # Check if admin content appears
                    if r.status_code == 200 and any(
                        w in body for w in ("admin panel", "delete user", "manage users",
                                            "לוח ניהול", "מחק משתמש", "ניהול משתמשים")
                    ):
                        findings.append(Finding(
                            "critical", "biz_logic",
                            f"Privilege Escalation — ?{role_param}={attack_val}",
                            f"הוספת פרמטר ?{role_param}={attack_val} חשפה תוכן admin.",
                            [f"URL: {test_url}", f"Status: {r.status_code}"],
                            "אל תסמוך על פרמטרי role/admin מה-client. ודא הרשאות ב-session בצד השרת.",
                        ))
                except Exception:
                    continue

        # ── 5. Payment step skip (direct access to confirmation) ───────────────
        payment_confirm_paths = [
            "/checkout/complete", "/checkout/success", "/order/complete",
            "/order/success", "/payment/success", "/payment/complete",
            "/purchase/complete", "/purchase/success",
            "/checkout/confirm", "/order/confirm",
        ]
        for path in payment_confirm_paths:
            url = base + path
            if url in tested:
                continue
            tested.add(url)
            try:
                r = await client.get(url, timeout=6)
                body = r.text.lower()
                if r.status_code == 200 and any(
                    w in body for w in ("order confirmed", "thank you", "payment received",
                                        "ההזמנה אושרה", "תודה על רכישתך", "הזמנה התקבלה")
                ):
                    findings.append(Finding(
                        "high", "biz_logic",
                        f"דף אישור תשלום נגיש ישירות — {path}",
                        f"דף {path!r} נגיש ישירות ללא השלמת תהליך התשלום. "
                        "ייתכן שניתן לדלג על שלב התשלום.",
                        [f"URL: {url}", f"Status: {r.status_code}"],
                        "ודא שדף ה-success מחייב payment token תקף ב-session. "
                        "אל תאפשר גישה ישירה ללא מעבר מוצלח דרך שלב התשלום.",
                    ))
            except Exception:
                continue

        # ── 6. Workflow step-skip ──────────────────────────────────────────────
        checkout_steps = [
            ("/checkout/step2", "/checkout/step3", "/checkout/step4"),
            ("/checkout/shipping", "/checkout/payment", "/checkout/review"),
            ("/cart/checkout", "/checkout/billing", "/checkout/confirm"),
            ("/order/new", "/order/payment", "/order/confirm"),
        ]
        for steps in checkout_steps:
            # Try to skip to last step without visiting earlier steps
            last_step = base + steps[-1]
            if last_step in tested:
                continue
            tested.add(last_step)
            try:
                r = await client.get(last_step, timeout=6)
                if r.status_code == 200:
                    body = r.text.lower()
                    earlier_redirect = any(
                        s.split("/")[-1] in str(r.url) for s in steps[:-1]
                    )
                    if not earlier_redirect and not any(
                        w in body for w in ("login", "step 1", "cart", "empty")
                    ):
                        findings.append(Finding(
                            "high", "biz_logic",
                            f"Workflow Step-Skip — גישה ישירה ל-{steps[-1]}",
                            f"שלב {steps[-1]!r} נגיש ישירות ללא מעבר דרך שלבים קודמים. "
                            "תוקף יכול לדלג על שלבי ולידציה בתהליך הרכישה.",
                            [f"URL: {last_step}", f"Status: {r.status_code}", f"No redirect to earlier step"],
                            "ודא שכל שלב בתהליך checkout מחייב שלב קודם ב-session state.",
                        ))
            except Exception:
                continue

        # ── 7. Race condition — 20 concurrent requests ─────────────────────────
        race_endpoints = [ep for ep in active_endpoints
                         if any(k in ep for k in ["/cart", "/coupon", "/order", "/purchase"])]
        if race_endpoints:
            race_url = race_endpoints[0]
            race_payload = {"product_id": 1, "quantity": 1, "coupon": "RACE50"}
            key = f"race|{race_url}"
            if key not in tested:
                tested.add(key)
                try:
                    # Fire 20 identical requests simultaneously
                    tasks = [
                        client.post(race_url, json=race_payload,
                                    headers={**headers, "Content-Type": "application/json"},
                                    timeout=10)
                        for _ in range(20)
                    ]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    statuses = [r.status_code for r in responses if hasattr(r, "status_code")]
                    success_count = sum(1 for s in statuses if s in (200, 201))

                    if success_count > 1:
                        findings.append(Finding(
                            "high", "biz_logic",
                            f"Race Condition — {success_count}/20 בקשות מקבילות הצליחו",
                            f"שליחת 20 בקשות זהות במקביל ל-{race_url} גרמה ל-{success_count} תגובות הצלחה. "
                            "ייתכן שניתן לממש קופון פעמים, לרכוש פריטים כפולים, או לנצל slot בו-זמנית.",
                            [
                                f"URL: POST {race_url}",
                                f"Concurrent requests: 20",
                                f"Success responses: {success_count}",
                                f"All statuses: {statuses}",
                                f"Payload: {race_payload}",
                            ],
                            "הוסף mutex/locking ברמת DB. השתמש ב-idempotency keys. בדוק עם SELECT FOR UPDATE.",
                        ))
                    else:
                        findings.append(Finding(
                            "info", "biz_logic",
                            f"Race Condition — {race_url.replace(base, '')} לא נראה פגיע",
                            f"20 בקשות מקבילות: {success_count} הצליחו. נראה שיש הגנה.",
                            [f"Statuses: {statuses}"],
                        ))
                except Exception as e:
                    pass

        # ── 8. Coupon stacking / reuse ─────────────────────────────────────────
        coupon_endpoints = [
            f"{base}/api/coupon/apply",
            f"{base}/api/cart/coupon",
            f"{base}/api/v1/coupon",
            f"{base}/api/checkout/coupon",
            f"{base}/cart/coupon",
        ]
        test_coupons = ["SAVE10", "DISCOUNT20", "FREE", "100OFF", "SALE50"]
        for coupon_url in coupon_endpoints:
            if coupon_url in tested:
                continue
            tested.add(coupon_url)
            try:
                r = await client.get(coupon_url, timeout=4)
                if r.status_code == 404:
                    continue
                # Try applying same coupon twice (reuse)
                payload = {"coupon": test_coupons[0], "cart_id": "test123"}
                r1 = await client.post(coupon_url, json=payload, timeout=6,
                                       headers={**headers, "Content-Type": "application/json"})
                r2 = await client.post(coupon_url, json=payload, timeout=6,
                                       headers={**headers, "Content-Type": "application/json"})
                if r1.status_code in (200, 201) and r2.status_code in (200, 201):
                    findings.append(Finding(
                        "high", "biz_logic",
                        f"Coupon Reuse — {coupon_url.replace(base, '')}",
                        f"אותו קוד קופון ({test_coupons[0]}) הוחל פעמיים ושתי הבקשות הצליחו. "
                        "ייתכן שניתן להחיל קופון ללא הגבלה.",
                        [
                            f"URL: POST {coupon_url}",
                            f"Coupon: {test_coupons[0]}",
                            f"First apply status: {r1.status_code}",
                            f"Second apply status: {r2.status_code}",
                        ],
                        "שמור במסד נתונים אם קופון כבר הוחל. הגבל שימוש לפי user_id.",
                    ))

                # Try stacking multiple coupons
                stack_tasks = [
                    client.post(coupon_url,
                                json={"coupon": c, "cart_id": "test123"},
                                timeout=6,
                                headers={**headers, "Content-Type": "application/json"})
                    for c in test_coupons
                ]
                stack_resps = await asyncio.gather(*stack_tasks, return_exceptions=True)
                stack_ok = sum(1 for r in stack_resps if hasattr(r, "status_code") and r.status_code in (200, 201))
                if stack_ok >= 3:
                    findings.append(Finding(
                        "medium", "biz_logic",
                        f"Coupon Stacking — {stack_ok}/{len(test_coupons)} קופונים מקובצים",
                        f"{stack_ok} קופונים שונים הוחלו בו-זמנית. "
                        "ייתכן שניתן לצבור הנחות בלתי מוגבלות.",
                        [
                            f"URL: {coupon_url}",
                            f"Coupons tested: {test_coupons}",
                            f"Successful: {stack_ok}",
                        ],
                        "הגבל מספר הקופונים לעגלה אחת. בדוק totalDiscount לא עולה על מחיר הפריט.",
                    ))
                break
            except Exception:
                continue

    vuln_count = len([f for f in findings if f.severity in ("critical", "high")])
    if vuln_count == 0:
        findings.append(Finding(
            "info", "biz_logic",
            "Business Logic — לא זוהו בעיות לוגיות ברורות",
            "לא נמצאו פרמטרי מחיר/כמות פגיעים. בדיקה ידנית מומלצת עם Burp Suite.",
            [
                f"Cart endpoints found: {len(active_endpoints)}",
                f"Forms checked: {len(page_forms)}",
                "מומלץ לבדוק ידנית: שינוי מחיר ב-Burp Suite Repeater",
            ],
        ))

    return findings
