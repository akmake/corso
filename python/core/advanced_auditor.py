"""
Advanced Security Checks
------------------------
Implemented based on sqlmap, OWASP ZAP, wapiti, and sslyze research.

Checks (priority: High + Medium):
  1. SQL Injection   — error-based (sqlmap patterns) + boolean-based blind
  2. Reflected XSS   — canary taint + context-aware payloads
  3. SSL/TLS         — deprecated versions, cert expiry, weak ciphers, HSTS
  4. HTTP Methods    — PUT/DELETE/TRACE/CONNECT enumeration + XST
  5. Open Redirect   — redirect-parameter discovery + external-domain test
  6. Dir Traversal   — path-traversal payloads on detected parameters
  7. Tech Fingerprint — server/framework/CMS identification
"""

import asyncio
import difflib
import json as _json
import random
import re
import secrets
import socket
import ssl
import datetime
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

from core.tool_runner import is_available, run_tool, run_tool_json

log = __import__("logging").getLogger(__name__)

# ── Shared Finding type (mirrors auditor.py) ──────────────────────────────────
@dataclass
class Finding:
    severity:       str
    category:       str
    title:          str
    description:    str
    evidence:       list = field(default_factory=list)
    recommendation: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# 1. SQL INJECTION
# ══════════════════════════════════════════════════════════════════════════════

# Error patterns sourced from sqlmap errors.xml
_SQLI_ERRORS = {
    "MySQL": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that (?:corresponds to|fits) your MySQL server version",
        r"check the manual that (?:corresponds to|fits) your MariaDB server version",
        r"Unknown column '[^ ]+' in 'field list'", r"MySqlClient\.", r"com\.mysql\.jdbc",
        r"Pdo[./_\\]Mysql", r"MySqlException",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result", r"Npgsql\.",
        r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near", r"PostgreSQL query failed", r"PSQLException",
    ],
    "MSSQL": [
        r"Driver.*? SQL[\-\_ ]*Server", r"OLE DB.*? SQL Server", r"\bSQL Server[^\"]+Driver",
        r"Warning.*?\W(?:mssql|sqlsrv)_", r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"\[SQL Server\]", r"ODBC SQL Server Driver", r"com\.microsoft\.sqlserver\.jdbc",
        r"Pdo[./_\\](?:Mssql|SqlSrv)",
    ],
    "Oracle": [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver", r"Warning.*?\W(?:oci|ora)_",
        r"quoted string not properly terminated", r"SQL command not properly ended",
        r"oracle\.jdbc", r"OracleException",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"Warning.*?\W(?:sqlite_|SQLite3::)",
        r"\[SQLITE_ERROR\]", r"sqlite3\.OperationalError:", r"SQLiteException",
    ],
    "Generic": [
        r"java\.sql\.SQLException", r"ODBC.*?Driver", r"JET Database Engine",
        r"Access Database Engine",
    ],
}

_COMPILED_SQLI = {
    db: [re.compile(p, re.IGNORECASE | re.DOTALL) for p in pats]
    for db, pats in _SQLI_ERRORS.items()
}

# Minimal payload set that reliably triggers errors across all databases
_SQLI_PAYLOADS = [
    "'", "''", '"', "`", "%27",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "1 AND 1=CAST((SELECT 1) AS INT)--",
    "1 UNION SELECT NULL--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",  # MySQL error-based
]

_BOOLEAN_PAIRS = [
    (" AND 1=1--",       " AND 1=2--"),
    (" AND 1=1#",        " AND 1=2#"),
    ("' AND '1'='1",     "' AND '1'='2"),
    ("' AND '1'='1'--",  "' AND '1'='2'--"),
    ("') AND ('1'='1",   "') AND ('1'='2"),
]


def _sqli_detect_error(body: str) -> tuple[bool, str]:
    for db, patterns in _COMPILED_SQLI.items():
        for p in patterns:
            if p.search(body):
                return True, db
    return False, ""


def _normalize(html: str) -> str:
    html = re.sub(r'[0-9a-f]{32,}', 'TOKEN', html)
    html = re.sub(r'\d{10,13}', 'TS', html)
    html = re.sub(r'value="[^"]{20,}"', 'value="VAL"', html)
    return html.strip()


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


async def _fetch_param(client: httpx.AsyncClient, url: str, param: str, value: str) -> str:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        r = await client.get(new_url, timeout=10)
        return r.text
    except Exception:
        return ""


async def check_sqli(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[tuple] = set()

    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param, values in list(qs.items())[:6]:  # max 6 params per page
            key = (parsed.netloc + parsed.path, param)
            if key in tested:
                continue
            tested.add(key)
            original = values[0]

            # Baseline (no injection) — check false positive
            baseline = await _fetch_param(client, page["url"], param, original)
            already_vuln, _ = _sqli_detect_error(baseline)
            if already_vuln:
                continue  # App already shows SQL errors — skip

            # Error-based probes
            found = False
            for payload in _SQLI_PAYLOADS:
                if found:
                    break
                body = await _fetch_param(client, page["url"], param, original + payload)
                vuln, db = _sqli_detect_error(body)
                if vuln:
                    findings.append(Finding(
                        "high", "sqli",
                        f"SQL Injection (Error-based) — פרמטר: {param}",
                        f"פרמטר '{param}' ב-{page['url']} מגיב עם הודעת שגיאת SQL ({db}) לפייסיל: {payload!r}",
                        [f"URL: {page['url']}", f"Param: {param}", f"Payload: {payload!r}", f"DB: {db}"],
                        "השתמש ב-Prepared Statements / Parameterized Queries בלבד. אל תשתמש בהשרשת strings לשאילתות SQL.",
                    ))
                    found = True

            if found:
                continue

            # Boolean-based blind probes (only if page is stable)
            try:
                base2 = await _fetch_param(client, page["url"], param, original)
                if _similarity(_normalize(baseline), _normalize(base2)) < 0.95:
                    continue  # Unstable page — skip

                for true_pl, false_pl in _BOOLEAN_PAIRS:
                    true_body  = await _fetch_param(client, page["url"], param, original + true_pl)
                    false_body = await _fetch_param(client, page["url"], param, original + false_pl)
                    t = _normalize(true_body)
                    f = _normalize(false_body)
                    b = _normalize(baseline)

                    if _similarity(b, t) > 0.97 and _similarity(b, f) < 0.85 and _similarity(t, f) < 0.85:
                        findings.append(Finding(
                            "high", "sqli",
                            f"SQL Injection (Boolean-based Blind) — פרמטר: {param}",
                            f"פרמטר '{param}' ב-{page['url']}: תגובה שונה בין AND 1=1 לבין AND 1=2 — מעיד על Blind SQLi.",
                            [f"URL: {page['url']}", f"Param: {param}",
                             f"True payload: {true_pl!r}", f"False payload: {false_pl!r}"],
                            "השתמש ב-Prepared Statements בלבד. בצע code review מלא של כל שאילתות DB.",
                        ))
                        break
            except Exception:
                pass

    return findings


# ── SQLmap deep scan (Docker/native) ─────────────────────────────────────────

async def check_sqli_sqlmap(pages: list[dict]) -> list[Finding]:
    """Run SQLmap on pages with query parameters for deep SQL injection testing."""
    findings = []
    if not is_available("sqlmap"):
        return findings

    tested: set[str] = set()
    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        if not qs:
            continue
        key = parsed.netloc + parsed.path
        if key in tested:
            continue
        tested.add(key)

        try:
            code, stdout, stderr = await run_tool("sqlmap", [
                "-u", page["url"],
                "--batch", "--level=1", "--risk=1",
                "--threads=4", "--timeout=15",
                "--output-dir=/tmp/sqlmap_out",
                "--forms", "--crawl=0",
                "--technique=BEUSTQ",
            ], timeout=120)
            output = stdout + stderr
            if any(kw in output for kw in ["is vulnerable", "injectable", "payload:"]):
                for line in output.splitlines():
                    if "payload:" in line.lower() or "is vulnerable" in line.lower():
                        findings.append(Finding(
                            "critical", "sqli",
                            f"SQLmap: SQL Injection confirmed — {parsed.path}",
                            f"SQLmap confirmed SQL injection on {page['url']}",
                            [line.strip()],
                            "Fix immediately: use parameterized queries.",
                        ))
                        break
        except Exception as e:
            log.debug("SQLmap error on %s: %s", page["url"], e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 2. REFLECTED XSS
# ══════════════════════════════════════════════════════════════════════════════

_XSS_PAYLOADS = {
    "html_text": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "attr_generic": [
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
    ],
    "attr_url": [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "js_string": [
        "'-alert(1)-'",
        "';alert(1)//",
        '";alert(1)//',
    ],
    "js_template": ["${alert(1)}"],
    "html_comment": ["-->><script>alert(1)</script><!--"],
}


def _find_xss_context(html: str, canary: str) -> list[str]:
    contexts = []
    if canary not in html:
        return contexts
    soup = BeautifulSoup(html, "lxml")
    for tag in soup.find_all(True):
        for attr_name, attr_val in (tag.attrs or {}).items():
            val = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
            if canary in val:
                if attr_name.lower() in ("src", "href", "action", "formaction"):
                    contexts.append("attr_url")
                else:
                    contexts.append("attr_generic")
    for script in soup.find_all("script"):
        if script.string and canary in script.string:
            idx = script.string.find(canary)
            before = script.string[max(0, idx - 15):idx]
            if re.search(r'["\']$', before):
                contexts.append("js_string")
            elif re.search(r'`[^`]*$', before):
                contexts.append("js_template")
    if re.search(r'<!--[^>]*' + re.escape(canary), html):
        contexts.append("html_comment")
    if canary in soup.get_text():
        contexts.append("html_text")
    return list(set(contexts)) or ["html_text"]


def _is_unescaped(html: str, payload: str) -> bool:
    if payload in html:
        return True
    if "<" in payload:
        if "&lt;" not in html and payload.lower().replace(" ", "") in html.lower().replace(" ", ""):
            return True
    return False


async def check_xss(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[tuple] = set()

    for page in pages:
        ct = page.get("headers", {}).get("content-type", "")
        if "text/html" not in ct and ct:
            continue

        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param, values in list(qs.items())[:6]:
            key = (parsed.netloc + parsed.path, param)
            if key in tested:
                continue
            tested.add(key)
            original = values[0]

            # Phase 1: canary taint — does this param reflect in response?
            canary = "xsstest" + secrets.token_hex(4)
            try:
                body = await _fetch_param(client, page["url"], param, canary)
            except Exception:
                continue

            if canary not in body:
                continue  # Not reflected — skip

            # Phase 2: detect context, inject payloads
            contexts = _find_xss_context(body, canary)
            for ctx in contexts:
                for payload in _XSS_PAYLOADS.get(ctx, _XSS_PAYLOADS["html_text"])[:3]:
                    try:
                        r_body = await _fetch_param(client, page["url"], param, payload)
                        if _is_unescaped(r_body, payload):
                            csp = page.get("headers", {}).get("content-security-policy", "")
                            sev = "medium" if ("unsafe-inline" not in csp and csp) else "high"
                            findings.append(Finding(
                                sev, "xss",
                                f"Reflected XSS — פרמטר: {param} ({ctx})",
                                f"פרמטר '{param}' ב-{page['url']} משקף payload ללא escaping בהקשר {ctx}.",
                                [f"URL: {page['url']}", f"Param: {param}",
                                 f"Context: {ctx}", f"Payload: {payload!r}"],
                                "הפעל output encoding מתאים להקשר (HTML, JS, URL). השתמש ב-DOMPurify לצד לקוח.",
                            ))
                            break
                    except Exception:
                        continue

    return findings


# ── Dalfox XSS deep scan ─────────────────────────────────────────────────────

async def check_xss_dalfox(pages: list[dict]) -> list[Finding]:
    """Run Dalfox on pages with parameters for advanced XSS detection."""
    findings = []
    if not is_available("dalfox"):
        return findings

    tested: set[str] = set()
    for page in pages[:10]:
        parsed = urlparse(page["url"])
        if not parse_qs(parsed.query):
            continue
        key = parsed.netloc + parsed.path
        if key in tested:
            continue
        tested.add(key)

        try:
            code, stdout, stderr = await run_tool("dalfox", [
                "url", page["url"],
                "--silence", "--no-color",
                "--timeout", "10",
                "--only-discovery",
                "--output-all",
            ], timeout=90)
            for line in stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("[") and "INFO" in line:
                    continue
                if any(kw in line.lower() for kw in ["vuln", "found", "reflected", "stored", "dom"]):
                    findings.append(Finding(
                        "high", "xss",
                        f"Dalfox: XSS detected — {parsed.path}",
                        f"Dalfox found XSS vulnerability on {page['url']}",
                        [line[:200]],
                        "Apply context-aware output encoding. Use DOMPurify on client-side.",
                    ))
        except Exception as e:
            log.debug("Dalfox error on %s: %s", page["url"], e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 3. SSL/TLS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

_WEAK_CIPHERS = {
    "critical": [r"_NULL_", r"_EXPORT", r"_anon_", r"ADH_", r"AECDH_"],
    "high":     [r"_RC4_", r"\bDES\b", r"_3DES_", r"_RC2_", r"_MD5$"],
    "medium":   [r"_CBC_"],
}


def _cipher_severity(cipher: str) -> str:
    for sev, pats in _WEAK_CIPHERS.items():
        for p in pats:
            if re.search(p, cipher, re.IGNORECASE):
                return sev
    return "ok"


async def check_tls(hostname: str, port: int = 443) -> list[Finding]:
    findings = []

    # 1. Certificate + negotiated version
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_running_loop()

        def _get_cert():
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    return ss.getpeercert(), ss.version(), ss.cipher()

        cert_dict, negotiated_ver, cipher_info = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert), timeout=12
        )

        # Certificate expiry
        if cert_dict:
            not_after_str = cert_dict.get("notAfter", "")
            if not_after_str:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append(Finding("critical", "tls",
                        "תעודת SSL פגת תוקף!",
                        f"התעודה פגה לפני {-days_left} ימים. הדפדפן יציג אזהרת אבטחה חמורה.",
                        [f"פגה ב: {not_after_str}"],
                        "חדש את התעודה מיידית. שקול Let's Encrypt עם auto-renewal."))
                elif days_left < 14:
                    findings.append(Finding("critical", "tls",
                        f"תעודת SSL תפוג בעוד {days_left} ימים",
                        "תוקף קצר מאוד — חדש מיידית.",
                        [f"פגה ב: {not_after_str}"],
                        "חדש תעודה מיידית. הגדר auto-renewal."))
                elif days_left < 30:
                    findings.append(Finding("high", "tls",
                        f"תעודת SSL תפוג בעוד {days_left} ימים",
                        "חדש בהקדם.",
                        [f"פגה ב: {not_after_str}"],
                        "חדש את התעודה. הגדר התראות."))

            # Hostname validation
            san_list = []
            for field_type, value in cert_dict.get("subjectAltName", []):
                if field_type == "DNS":
                    san_list.append(value)
            cn = ""
            for part in cert_dict.get("subject", []):
                for k, v in part:
                    if k == "commonName":
                        cn = v
            valid_host = any(fnmatch.fnmatch(hostname, s) for s in san_list) or fnmatch.fnmatch(hostname, cn)
            if not valid_host and (san_list or cn):
                findings.append(Finding("high", "tls",
                    f"אי-התאמת Hostname בתעודת SSL",
                    f"התעודה הונפקה ל: {san_list or cn} אך הבקשה ל: {hostname}",
                    [f"CN: {cn}", f"SANs: {san_list}"],
                    "השג תעודה עבור הדומיין הנכון."))

        # Cipher weakness
        if cipher_info:
            cipher_name = cipher_info[0]
            sev = _cipher_severity(cipher_name)
            if sev != "ok":
                desc_map = {
                    "critical": "Cipher suite חלש קריטית — ניתן לפענח תעבורה.",
                    "high":     "Cipher suite חלש — RC4/DES/3DES פגיעים להתקפות ידועות (NOMORE, SWEET32).",
                    "medium":   "CBC mode חשוף להתקפות BEAST/Lucky13.",
                }
                findings.append(Finding(sev, "tls",
                    f"Cipher Suite חלש: {cipher_name}",
                    desc_map.get(sev, ""),
                    [f"Cipher: {cipher_name}"],
                    "הגדר את השרת לשימוש ב-ECDHE+AES-GCM או ChaCha20-Poly1305 בלבד."))

    except asyncio.TimeoutError:
        findings.append(Finding("info", "tls", "TLS timeout", f"לא הייתה גישה ל-{hostname}:{port}", [], ""))
    except Exception:
        pass

    # 2. Deprecated TLS versions
    import warnings
    for ver_name, ver_const in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                                  ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                ctx2.minimum_version = ver_const
                ctx2.maximum_version = ver_const

            def _try_ver(c=ctx2):
                with socket.create_connection((hostname, port), timeout=5) as s:
                    with c.wrap_socket(s, server_hostname=hostname):
                        return True

            loop = asyncio.get_running_loop()
            accepted = await asyncio.wait_for(loop.run_in_executor(None, _try_ver), timeout=7)
            if accepted:
                findings.append(Finding("high", "tls",
                    f"גרסת {ver_name} מיושנת מאופשרת",
                    f"RFC 8996 פסל את {ver_name}. פגיע ל-POODLE, BEAST ועוד.",
                    [f"Server accepts {ver_name}"],
                    f"השבת {ver_name} בהגדרות השרת. אפשר TLS 1.2+ בלבד."))
        except Exception:
            pass  # Version not accepted — good

    return findings


# ── testssl.sh deep TLS scan ─────────────────────────────────────────────────

async def check_tls_testssl(hostname: str, port: int = 443) -> list[Finding]:
    """Run testssl.sh for comprehensive SSL/TLS analysis."""
    findings = []
    if not is_available("testssl"):
        return findings

    try:
        code, stdout, stderr = await run_tool("testssl", [
            "--jsonfile=/dev/stdout",
            "--severity", "LOW",
            "--fast",
            "--ip=one",
            "--quiet",
            f"{hostname}:{port}",
        ], timeout=180)

        if not stdout.strip():
            return findings

        import json as _j
        try:
            items = _j.loads(stdout)
        except _j.JSONDecodeError:
            items = []
            for line in stdout.strip().splitlines():
                try:
                    items.append(_j.loads(line))
                except _j.JSONDecodeError:
                    continue

        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                   "LOW": "low", "OK": "info", "INFO": "info"}

        for item in items:
            if not isinstance(item, dict):
                continue
            severity = item.get("severity", "INFO")
            if severity in ("OK", "INFO"):
                continue
            mapped_sev = sev_map.get(severity, "info")
            finding_id = item.get("id", "unknown")
            finding_text = item.get("finding", "")
            findings.append(Finding(
                mapped_sev, "tls",
                f"testssl: {finding_id}",
                finding_text[:300],
                [f"ID: {finding_id}", f"Severity: {severity}"],
                "Update TLS configuration per testssl.sh recommendations.",
            ))
    except Exception as e:
        log.debug("testssl error on %s: %s", hostname, e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 4. HTTP METHODS
# ══════════════════════════════════════════════════════════════════════════════

async def check_http_methods(client: httpx.AsyncClient, url: str) -> list[Finding]:
    findings = []
    test_path = url.rstrip("/") + "/.audit-method-test-do-not-use"

    # TRACE — XST (Cross-Site Tracing)
    try:
        sentinel = "TRACE-AUDIT-" + secrets.token_hex(6)
        r = await client.request("TRACE", url, headers={"X-Audit": sentinel}, timeout=8)
        if sentinel in r.text or r.status_code in (200, 204):
            findings.append(Finding("medium", "http_methods",
                "HTTP TRACE מאופשר — Cross-Site Tracing (XST)",
                "TRACE משקף את בקשת ה-HTTP בחזרה. בשילוב XSS ניתן לגנוב HttpOnly cookies.",
                [f"HTTP TRACE → {r.status_code}"],
                "השבת TRACE בשרת: 'TraceEnable off' (Apache) / 'if ($request_method = TRACE)' (Nginx)."))
    except Exception:
        pass

    # PUT — arbitrary file upload
    try:
        r = await client.request("PUT", test_path, content=b"audit-test", timeout=8)
        if r.status_code in (200, 201, 204):
            findings.append(Finding("critical", "http_methods",
                "HTTP PUT מאופשר — העלאת קבצים לשרת",
                "תוקף יכול להעלות קבצים שרירותיים לשרת — web shell, defacement ועוד.",
                [f"PUT {test_path} → HTTP {r.status_code}"],
                "השבת PUT: 'Limit PUT>' (Apache) / 'limit_except GET POST HEAD' (Nginx)."))
        elif r.status_code == 403:
            findings.append(Finding("medium", "http_methods",
                "HTTP PUT קיים אך חסום (403)",
                "ה-method קיים בשרת — ייתכן שניתן לעקוף את ה-403.",
                [f"PUT {test_path} → HTTP 403"],
                "ודא שה-block אמיתי ולא עקיף."))
    except Exception:
        pass

    # DELETE
    try:
        r = await client.request("DELETE", test_path, timeout=8)
        if r.status_code in (200, 204):
            findings.append(Finding("critical", "http_methods",
                "HTTP DELETE מאופשר — מחיקת קבצים מהשרת",
                "תוקף יכול למחוק קבצים שרירותיים.",
                [f"DELETE {test_path} → HTTP {r.status_code}"],
                "השבת DELETE לחלוטין בהגדרות השרת."))
    except Exception:
        pass

    # CONNECT (potential proxy / SSRF vector)
    try:
        r = await client.request("CONNECT", url, timeout=6)
        if r.status_code not in (400, 405, 501):
            findings.append(Finding("high", "http_methods",
                "HTTP CONNECT מאופשר — פוטנציאל SSRF / proxy abuse",
                "CONNECT מאפשר לתוקף להשתמש בשרת כ-proxy לגישה לרשת פנימית.",
                [f"CONNECT → HTTP {r.status_code}"],
                "השבת CONNECT לחלוטין אלא אם השרת הוא proxy מכוון."))
    except Exception:
        pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 5. OPEN REDIRECT
# ══════════════════════════════════════════════════════════════════════════════

_REDIRECT_PARAMS = [
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "redirect_to",
    "redirectUrl", "redirectUri", "next", "target", "dest", "destination",
    "return", "returnTo", "return_to", "returnUrl", "return_url",
    "goto", "go", "link", "out", "continue", "checkout_url", "callback",
    "forward", "location", "path", "ref",
]

_REDIRECT_PAYLOAD = "https://evil-redirect-test.example.com/audit"


async def check_open_redirect(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[str] = set()

    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)

        for param in _REDIRECT_PARAMS:
            if param not in qs:
                continue
            key = f"{parsed.netloc}{parsed.path}:{param}"
            if key in tested:
                continue
            tested.add(key)

            try:
                new_qs = dict(qs)
                new_qs[param] = [_REDIRECT_PAYLOAD]
                test_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                r = await client.get(test_url, follow_redirects=False, timeout=8)

                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    if "evil-redirect-test.example.com" in loc:
                        findings.append(Finding("high", "open_redirect",
                            f"Open Redirect — פרמטר: {param}",
                            f"פרמטר '{param}' ב-{page['url']} מפנה לכל URL חיצוני ללא בדיקה — Phishing וגניבת OAuth tokens.",
                            [f"URL: {page['url']}", f"Param: {param}",
                             f"Location: {loc}", f"HTTP {r.status_code}"],
                            "אמת שה-redirect מצביע לדומיין מורשה בלבד. השתמש ב-allowlist. אל תסמוך על הערך מה-URL."))
            except Exception:
                pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 6. DIRECTORY / PATH TRAVERSAL
# ══════════════════════════════════════════════════════════════════════════════

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
]

_TRAVERSAL_CONFIRM = [
    re.compile(r"root:[x*]:0:0:", re.IGNORECASE),   # /etc/passwd
    re.compile(r"\[fonts\]", re.IGNORECASE),         # windows hosts
    re.compile(r"127\.0\.0\.1\s+localhost"),          # hosts file
]

_FILE_PARAMS = ["file", "path", "page", "template", "view", "load",
                "doc", "document", "name", "include", "filename", "dir"]


async def check_traversal(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[tuple] = set()

    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        candidates = {k: v for k, v in qs.items() if k.lower() in _FILE_PARAMS}
        if not candidates:
            continue

        for param, values in candidates.items():
            key = (parsed.netloc + parsed.path, param)
            if key in tested:
                continue
            tested.add(key)

            for payload in _TRAVERSAL_PAYLOADS[:4]:
                try:
                    body = await _fetch_param(client, page["url"], param, payload)
                    for pat in _TRAVERSAL_CONFIRM:
                        if pat.search(body):
                            findings.append(Finding("critical", "traversal",
                                f"Path Traversal — פרמטר: {param}",
                                f"פרמטר '{param}' ב-{page['url']} מאפשר קריאת קבצי מערכת.",
                                [f"URL: {page['url']}", f"Param: {param}", f"Payload: {payload}",
                                 f"Response contains: {pat.pattern}"],
                                "אמת שהנתיב נמצא בתיקייה המורשית. השתמש ב-realpath() וודא שהוא לא יוצא מה-root המורשה."))
                            break
                except Exception:
                    pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 7. TECHNOLOGY FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

# Signatures: (regex, technology, category, notes)
_TECH_SIGS = [
    # Server headers
    (re.compile(r"Apache/(\d+\.\d+)", re.I),         "server_header", "Apache",       ""),
    (re.compile(r"nginx/(\d+\.\d+)", re.I),           "server_header", "Nginx",        ""),
    (re.compile(r"Microsoft-IIS/(\d+\.\d+)", re.I),   "server_header", "IIS",          ""),
    (re.compile(r"LiteSpeed", re.I),                  "server_header", "LiteSpeed",    ""),
    # X-Powered-By
    (re.compile(r"PHP/(\d+\.\d+)", re.I),             "powered_by",    "PHP",          "EOL: PHP<8.1"),
    (re.compile(r"ASP\.NET", re.I),                   "powered_by",    "ASP.NET",      ""),
    (re.compile(r"Express", re.I),                    "powered_by",    "Express.js",   ""),
    # HTML meta
    (re.compile(r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)', re.I), "meta", "WordPress", ""),
    (re.compile(r'<meta[^>]+generator[^>]+Joomla', re.I),               "meta", "Joomla",    ""),
    (re.compile(r'<meta[^>]+generator[^>]+Drupal', re.I),               "meta", "Drupal",    ""),
    (re.compile(r'<meta[^>]+generator[^>]+Wix', re.I),                  "meta", "Wix",       ""),
    # HTML patterns
    (re.compile(r'/wp-content/', re.I),               "html",          "WordPress",    ""),
    (re.compile(r'Powered by PrestaShop', re.I),      "html",          "PrestaShop",   ""),
    (re.compile(r'data-react-root|__reactFiber', re.I), "html",        "React",        ""),
    (re.compile(r'ng-version|ng-app|angular', re.I),  "html",          "Angular",      ""),
    (re.compile(r'__vue_|data-v-\w{8}', re.I),        "html",          "Vue.js",       ""),
    (re.compile(r'__NEXT_DATA__', re.I),              "html",          "Next.js",      ""),
    (re.compile(r'window\.__NUXT__', re.I),           "html",          "Nuxt.js",      ""),
    # Cookie names
    (re.compile(r'PHPSESSID', re.I),                  "cookie",        "PHP",          ""),
    (re.compile(r'JSESSIONID', re.I),                 "cookie",        "Java/Tomcat",  ""),
    (re.compile(r'ASP\.NET_SessionId', re.I),         "cookie",        "ASP.NET",      ""),
    (re.compile(r'laravel_session', re.I),             "cookie",        "Laravel",      ""),
    (re.compile(r'django_language|csrfmiddlewaretoken', re.I), "cookie", "Django",     ""),
    (re.compile(r'rack\.session', re.I),              "cookie",        "Ruby/Rails",   ""),
]

# Known EOL / vulnerable versions to flag
_VERSION_WARNINGS = {
    "PHP":   [("5.", "critical", "PHP 5.x הגיעה ל-EOL ב-2018 — אין patches אבטחה"),
              ("7.0", "high",    "PHP 7.0 EOL"),
              ("7.1", "high",    "PHP 7.1 EOL"),
              ("7.2", "high",    "PHP 7.2 EOL"),
              ("7.3", "high",    "PHP 7.3 EOL")],
    "Apache": [("2.2", "high",  "Apache 2.2 EOL — שדרג ל-2.4")],
    "IIS":    [("6.", "critical","IIS 6 EOL — EternalBlue / MS17-010"),
               ("7.", "high",   "IIS 7 EOL")],
    "Nginx":  [("0.", "critical","Nginx 0.x EOL")],
}


async def check_tech_fingerprint(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    detected: dict[str, str] = {}  # tech -> version

    for page in pages[:5]:
        html = page.get("html", "")
        headers = page.get("headers", {})
        cookies_str = " ".join(page.get("cookies", []))

        for pattern, src, tech, _ in _TECH_SIGS:
            if tech in detected:
                continue
            target = ""
            if src == "server_header":
                target = headers.get("server", "") + headers.get("Server", "")
            elif src == "powered_by":
                target = headers.get("x-powered-by", "") + headers.get("X-Powered-By", "")
            elif src in ("meta", "html"):
                target = html
            elif src == "cookie":
                target = cookies_str

            m = pattern.search(target)
            if m:
                ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                detected[tech] = ver.strip() if ver else "detected"

    if detected:
        techs_list = [f"{t} {v}".strip() for t, v in detected.items()]
        findings.append(Finding("info", "fingerprint",
            f"טכנולוגיות מזוהות: {', '.join(list(detected.keys())[:6])}",
            "זיהוי הטכנולוגיות מאפשר לתוקף למצוא CVEs ספציפיים.",
            techs_list,
            "הסר/הסתר headers מזהים (Server, X-Powered-By). עדכן לגרסאות אחרונות."))

        # Version-specific vulnerability warnings
        for tech, version in detected.items():
            for prefix, sev, msg in _VERSION_WARNINGS.get(tech, []):
                if version.startswith(prefix):
                    findings.append(Finding(sev, "fingerprint",
                        f"{tech} {version} — גרסה מיושנת בסוף חיים (EOL)",
                        msg + f" — גרסה נוכחית: {tech} {version}.",
                        [f"Detected: {tech}/{version}"],
                        f"שדרג {tech} לגרסה הנוכחית הנתמכת בהקדם האפשרי."))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 8. SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ══════════════════════════════════════════════════════════════════════════════

async def check_ssti(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[tuple] = set()

    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param, values in list(qs.items())[:5]:
            key = (parsed.netloc + parsed.path, param, "ssti")
            if key in tested:
                continue
            tested.add(key)
            original = values[0]

            # Use random operands to avoid false positives
            a, b = random.randint(11, 97), random.randint(11, 97)
            expected = str(a * b)

            payloads = [
                (f"{{{{{a}*{b}}}}}", expected, "Jinja2/Twig/Pebble"),
                (f"${{{a}*{b}}}",    expected, "FreeMarker/Spring EL"),
                (f"#{{{a}*{b}}}",    expected, "Ruby EL/Pug"),
                (f"*{{{a}*{b}}}",    expected, "Spring SpEL"),
                (f"<%={a}*{b}%>",    expected, "ERB/JSP EL"),
            ]

            try:
                base_body = await _fetch_param(client, page["url"], param, original)
                if expected in base_body:
                    continue  # expected value already in page — skip
            except Exception:
                continue

            for payload, expect, engine in payloads:
                try:
                    body = await _fetch_param(client, page["url"], param, payload)
                    if expect in body and payload not in body:
                        findings.append(Finding(
                            "critical", "ssti",
                            f"Server-Side Template Injection (SSTI) — {engine} — פרמטר: {param}",
                            f"פרמטר '{param}' מעבד template expressions בצד שרת ({engine}). "
                            "SSTI מוביל ישירות ל-RCE (Remote Code Execution) — שליטה מלאה בשרת.",
                            [f"URL: {page['url']}", f"Param: {param}",
                             f"Payload: {payload!r}", f"Expected '{expect}' נמצא בתגובה",
                             f"Engine hint: {engine}"],
                            "אל תעבד קלט משתמש כ-template. השתמש בסביבה sandboxed. "
                            "בצע code review של כל קריאות ל-render/template.",
                        ))
                        break
                except Exception:
                    continue

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 9. OS COMMAND INJECTION
# ══════════════════════════════════════════════════════════════════════════════

async def check_cmd_injection(client: httpx.AsyncClient, pages: list[dict]) -> list[Finding]:
    findings = []
    tested: set[tuple] = set()
    marker = "cmdinjtest" + secrets.token_hex(5)

    payloads = [
        f"; echo {marker}",
        f"| echo {marker}",
        f"|| echo {marker}",
        f"& echo {marker}",
        f"&& echo {marker}",
        f"`echo {marker}`",
        f"$(echo {marker})",
        f"\n echo {marker}",
    ]

    for page in pages:
        parsed = urlparse(page["url"])
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param, values in list(qs.items())[:5]:
            key = (parsed.netloc + parsed.path, param, "cmd")
            if key in tested:
                continue
            tested.add(key)
            original = values[0]

            for payload in payloads:
                try:
                    body = await _fetch_param(client, page["url"], param, original + payload)
                    if marker in body:
                        findings.append(Finding(
                            "critical", "cmd_injection",
                            f"OS Command Injection — פרמטר: {param}",
                            f"פרמטר '{param}' מועבר ישירות לפקודת OS. "
                            "מאפשר קריאת קבצים, reverse shell, lateral movement — שליטה מלאה.",
                            [f"URL: {page['url']}", f"Param: {param}",
                             f"Payload: {payload!r}", f"Marker '{marker}' הוחזר בתגובה"],
                            "אל תעביר קלט משתמש ל-shell. "
                            "השתמש ב-subprocess עם argument list (ללא shell=True). "
                            "Whitelist על ערכים מותרים בלבד.",
                        ))
                        break
                except Exception:
                    continue

    return findings


# ── Commix deep command injection ─────────────────────────────────────────────

async def check_cmd_injection_commix(pages: list[dict]) -> list[Finding]:
    """Run Commix on pages with parameters for deep OS command injection testing."""
    findings = []
    if not is_available("commix"):
        return findings

    tested: set[str] = set()
    for page in pages[:5]:
        parsed = urlparse(page["url"])
        if not parse_qs(parsed.query):
            continue
        key = parsed.netloc + parsed.path
        if key in tested:
            continue
        tested.add(key)

        try:
            code, stdout, stderr = await run_tool("commix", [
                "--url", page["url"],
                "--batch",
                "--level=1",
                "--output-dir=/tmp/commix_out",
            ], timeout=120)
            output = stdout + stderr
            if any(kw in output.lower() for kw in ["injectable", "is vulnerable", "command execution"]):
                findings.append(Finding(
                    "critical", "cmd_injection",
                    f"Commix: Command Injection confirmed — {parsed.path}",
                    f"Commix confirmed OS command injection on {page['url']}",
                    [line.strip() for line in output.splitlines() if "vuln" in line.lower() or "inject" in line.lower()][:3],
                    "Never pass user input to shell. Use subprocess with argument lists.",
                ))
        except Exception as e:
            log.debug("Commix error on %s: %s", page["url"], e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 10. EMAIL SECURITY — SPF / DMARC / DKIM
# ══════════════════════════════════════════════════════════════════════════════

async def check_email_security(hostname: str) -> list[Finding]:
    findings = []
    try:
        import dns.resolver as _resolver
    except ImportError:
        return findings

    loop = asyncio.get_running_loop()

    def _txt(name: str) -> list[str]:
        try:
            ans = _resolver.resolve(name, "TXT", lifetime=5)
            return [b.decode(errors="ignore") for rdata in ans for b in rdata.strings]
        except Exception:
            return []

    # SPF
    spf_all = await loop.run_in_executor(None, lambda: _txt(hostname))
    spf = [r for r in spf_all if r.startswith("v=spf1")]

    if not spf:
        findings.append(Finding(
            "medium", "email_security",
            f"SPF record חסר — {hostname}",
            "ללא SPF כל שרת יכול לשלוח מיילים בשם הדומיין — Email Spoofing ו-Phishing.",
            [f"DNS TXT {hostname} → אין SPF record"],
            f"הוסף TXT record לדומיין:\nv=spf1 include:_spf.YOUR-PROVIDER.com ~all\n"
            "(התאם לספק המייל: Google Workspace, Microsoft 365, וכו')",
        ))
    else:
        val = spf[0]
        if "+all" in val:
            findings.append(Finding(
                "critical", "email_security",
                f"SPF: +all — כל שרת בעולם מורשה לשלוח! ({hostname})",
                "+all מאפשר spoofing מובטח — כל שרת מורשה לשלוח בשם הדומיין.",
                [f"SPF: {val}"],
                "שנה +all ל-~all (softfail) או -all (hardfail) מיידית.",
            ))
        elif "?all" in val:
            findings.append(Finding(
                "high", "email_security",
                f"SPF: ?all — ניטרלי, ללא הגנה ({hostname})",
                "?all לא אוכף דחיית מיילים לא מורשים.",
                [f"SPF: {val}"],
                "שנה ?all ל-~all או -all.",
            ))

    # DMARC
    dmarc_all = await loop.run_in_executor(None, lambda: _txt(f"_dmarc.{hostname}"))
    dmarc = [r for r in dmarc_all if r.startswith("v=DMARC1")]

    if not dmarc:
        findings.append(Finding(
            "medium", "email_security",
            f"DMARC record חסר — {hostname}",
            "ללא DMARC לא ניתן לאכוף SPF/DKIM — דומיין פגיע ל-Phishing ו-Email Spoofing.",
            [f"DNS TXT _dmarc.{hostname} → אין DMARC record"],
            f"הוסף TXT record ל-_dmarc.{hostname}:\n"
            f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{hostname}; pct=100",
        ))
    else:
        val = dmarc[0]
        if "p=none" in val:
            findings.append(Finding(
                "medium", "email_security",
                f"DMARC p=none — ניטור בלבד, ללא חסימה ({hostname})",
                "p=none לא חוסם מיילים מזויפים — רק שולח דוחות.",
                [f"DMARC: {val}"],
                "שדרג שלב-שלב:\n1. p=none (ניטור)\n2. p=quarantine\n3. p=reject",
            ))

    # DKIM — check common selectors
    common_selectors = [
        "default", "google", "mail", "dkim", "k1", "s1", "s2",
        "selector1", "selector2", "email", "smtp",
    ]
    dkim_found = False
    for sel in common_selectors:
        records = await loop.run_in_executor(
            None, lambda s=sel: _txt(f"{s}._domainkey.{hostname}")
        )
        if any("v=DKIM1" in r or "k=rsa" in r for r in records):
            dkim_found = True
            break

    if not dkim_found and spf:
        findings.append(Finding(
            "low", "email_security",
            f"DKIM לא נמצא בסלקטורים נפוצים — {hostname}",
            "לא נמצא DKIM record בסלקטורים נפוצים. DKIM חיוני לאימות שולח.",
            [f"סלקטורים שנבדקו: {', '.join(common_selectors)}"],
            "הגדר DKIM דרך ספק המייל שלך. DKIM + SPF + DMARC = הגנת אימייל מלאה.",
        ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 11. DATA EXPOSURE — APIs, exports, directory listing, IDOR, GraphQL
# ══════════════════════════════════════════════════════════════════════════════

# Endpoints commonly found to expose PII/transactional data without auth
_DATA_ENDPOINTS: list[tuple[str, str]] = [
    # Users / Customers
    ("/api/users",                   "users"),
    ("/api/v1/users",                "users"),
    ("/api/v2/users",                "users"),
    ("/api/customers",               "users"),
    ("/api/v1/customers",            "users"),
    ("/api/members",                 "users"),
    ("/api/accounts",                "users"),
    ("/api/subscribers",             "users"),
    ("/api/contacts",                "users"),
    ("/api/employees",               "users"),
    ("/api/staff",                   "users"),
    ("/api/users?limit=100",         "users"),
    ("/api/users?page=1",            "users"),
    ("/api/admin/users",             "users"),
    ("/admin/users",                 "users"),
    ("/wp-json/wc/v3/customers",     "users"),    # WooCommerce
    # Orders / Transactions / Payments
    ("/api/orders",                  "orders"),
    ("/api/v1/orders",               "orders"),
    ("/api/v2/orders",               "orders"),
    ("/api/transactions",            "orders"),
    ("/api/payments",                "orders"),
    ("/api/purchases",               "orders"),
    ("/api/invoices",                "orders"),
    ("/api/receipts",                "orders"),
    ("/api/orders?limit=100",        "orders"),
    ("/api/admin/orders",            "orders"),
    ("/wp-json/wc/v3/orders",        "orders"),   # WooCommerce
    # Exports / Reports
    ("/export/users.csv",            "export"),
    ("/export/orders.csv",           "export"),
    ("/export/customers.csv",        "export"),
    ("/export/data.csv",             "export"),
    ("/export/users.xlsx",           "export"),
    ("/export/orders.xlsx",          "export"),
    ("/export/",                     "export"),
    ("/reports/users.csv",           "export"),
    ("/reports/orders.csv",          "export"),
    ("/download/users.csv",          "export"),
    ("/download/orders.csv",         "export"),
    ("/admin/export/users",          "export"),
    ("/admin/export/orders",         "export"),
    ("/api/export/users",            "export"),
    # Log files
    ("/access.log",                  "logs"),
    ("/error.log",                   "logs"),
    ("/app.log",                     "logs"),
    ("/debug.log",                   "logs"),
    ("/logs/",                       "logs"),
    ("/log/",                        "logs"),
    ("/logs/access.log",             "logs"),
    ("/logs/error.log",              "logs"),
    ("/logs/app.log",                "logs"),
    # Open directories
    ("/uploads/",                    "directory"),
    ("/files/",                      "directory"),
    ("/data/",                       "directory"),
    ("/exports/",                    "directory"),
    ("/backups/",                    "directory"),
    ("/backup/",                     "directory"),
    ("/media/uploads/",              "directory"),
    ("/private/",                    "directory"),
    ("/static/data/",                "directory"),
    # Admin / internal
    ("/api/admin",                   "admin"),
    ("/api/admin/stats",             "admin"),
    ("/api/admin/dashboard",         "admin"),
    ("/api/internal",                "admin"),
    ("/_api",                        "admin"),
    ("/admin/api",                   "admin"),
]

# PII field names → (Hebrew label, severity)
_PII_FIELDS: dict[str, tuple[str, str]] = {
    "email":              ("אימייל",        "high"),
    "email_address":      ("אימייל",        "high"),
    "password":           ("סיסמה",         "critical"),
    "password_hash":      ("hash סיסמה",    "high"),
    "hashed_password":    ("hash סיסמה",    "high"),
    "pass":               ("סיסמה",         "critical"),
    "phone":              ("טלפון",          "high"),
    "phone_number":       ("טלפון",          "high"),
    "mobile":             ("נייד",           "high"),
    "credit_card":        ("כרטיס אשראי",   "critical"),
    "card_number":        ("כרטיס אשראי",   "critical"),
    "cvv":                ("CVV",            "critical"),
    "ssn":                ("SSN",            "critical"),
    "national_id":        ("ת.ז.",           "critical"),
    "id_number":          ("ת.ז.",           "critical"),
    "date_of_birth":      ("תאריך לידה",    "high"),
    "dob":                ("תאריך לידה",    "high"),
    "address":            ("כתובת",          "medium"),
    "street":             ("רחוב",           "medium"),
    "full_name":          ("שם מלא",         "medium"),
    "first_name":         ("שם פרטי",        "medium"),
    "last_name":          ("שם משפחה",      "medium"),
    "token":              ("טוקן",           "high"),
    "access_token":       ("access_token",   "high"),
    "api_key":            ("API key",        "critical"),
    "secret":             ("secret",         "critical"),
    "ip_address":         ("IP",             "medium"),
    "order_id":           ("מס' הזמנה",     "medium"),
    "transaction_id":     ("מס' עסקה",      "medium"),
    "payment_id":         ("מס' תשלום",     "medium"),
    "customer_id":        ("מס' לקוח",      "medium"),
    "user_id":            ("מס' משתמש",     "medium"),
    "username":           ("שם משתמש",       "medium"),
}

_DIR_LISTING_RE = re.compile(
    r'(<title>Index of|<h1>Index of|Directory listing for|'
    r'<pre>.*?Parent Directory)',
    re.I | re.DOTALL,
)

_GRAPHQL_INTRO = (
    '{"query":"{ __schema { queryType { name } types { name kind fields { name } } } }"}'
)

_DATA_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".json", ".xml", ".sql", ".db", ".sqlite", ".txt",
    ".zip", ".rar", ".gz", ".tar", ".7z", ".bz2",
}

_IDOR_PATHS = [
    "/api/user/{id}",
    "/api/users/{id}",
    "/api/customer/{id}",
    "/api/customers/{id}",
    "/api/order/{id}",
    "/api/orders/{id}",
    "/api/profile/{id}",
    "/api/account/{id}",
    "/api/invoice/{id}",
    "/api/transaction/{id}",
]


def _analyze_json(text: str, url: str) -> tuple[str, list[str]]:
    """
    Parse JSON response and look for PII fields.
    Returns (severity, evidence_lines) or ("", []).
    """
    try:
        data = _json.loads(text)
    except Exception:
        return "", []

    # Unwrap common wrappers: {data:[...]}, {users:[...]}, {results:[...]}, [...]
    records: list = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                records = v
                break
        if not records and any(isinstance(v, dict) for v in data.values()):
            records = [data]

    if not records:
        return "", []

    all_fields: set[str] = set()
    for rec in records[:30]:
        if isinstance(rec, dict):
            all_fields.update(k.lower().replace("-", "_") for k in rec.keys())

    found_pii: dict[str, tuple[str, str]] = {
        k: v for k, v in _PII_FIELDS.items() if k in all_fields
    }
    if not found_pii:
        return "", []

    max_sev = "medium"
    for _, sev in found_pii.values():
        if sev == "critical":
            max_sev = "critical"
            break
        if sev == "high":
            max_sev = "high"

    pii_list = ", ".join(f"{k} ({v[0]})" for k, v in list(found_pii.items())[:12])
    first_fields = list(records[0].keys())[:15] if records else []

    evidence = [
        f"URL: {url}",
        f"רשומות חשופות: {len(records)}{'+' if len(records) >= 30 else ''} (ייתכן pagination → יותר)",
        f"שדות PII שנמצאו: {pii_list}",
        f"שדות ברשומה לדוגמה: {', '.join(first_fields)}",
    ]
    return max_sev, evidence


async def check_data_exposure(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[Finding]:
    """
    Probe API endpoints, exports, logs, directories, GraphQL, IDOR.
    """
    findings: list[Finding] = []
    base    = base_url.rstrip("/")
    tested: set[str] = set()

    # ── 1. API / export / log / directory probing ─────────────────────────────
    async def _probe(path: str, category: str):
        url = base + path
        if url in tested:
            return
        tested.add(url)
        try:
            r = await client.get(url, timeout=8, follow_redirects=True)
        except Exception:
            return
        if r.status_code != 200 or len(r.content) < 20:
            return

        ct   = r.headers.get("content-type", "").lower()
        text = r.text

        # ── CSV / spreadsheet export ─────────────────────────────────────────
        if "csv" in ct or path.endswith((".csv", ".xlsx", ".xls")):
            lines  = text.splitlines()
            header = lines[0].lower() if lines else ""
            pii_in_hdr = [f for f in _PII_FIELDS if f in header]
            record_count = len(lines) - 1
            if pii_in_hdr or record_count > 0:
                sev = "critical" if any(
                    f in ("password", "credit_card", "ssn", "national_id") for f in pii_in_hdr
                ) else "high"
                findings.append(Finding(
                    sev, "data_exposure",
                    f"Export נגיש ללא הרשאה — {path}",
                    f"קובץ export עם {record_count:,} שורות נגיש לכולם ללא authentication.",
                    [f"URL: {url}",
                     f"Header: {lines[0][:120] if lines else '—'}",
                     f"שורות: {record_count:,}",
                     f"שדות PII: {', '.join(pii_in_hdr) or 'לא זוהו (בדוק ידנית)'}",
                     f"גודל: {len(r.content):,} bytes"],
                    "חסום גישה לנתיבי export לחלוטין. הוסף authentication.",
                ))
            return

        # ── Log file ─────────────────────────────────────────────────────────
        if category == "logs" and len(text) > 100:
            emails = re.findall(r'[\w.+\-]+@[\w\-]+\.\w{2,}', text[:8000])
            ips    = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text[:8000])
            paths  = re.findall(r'"(?:GET|POST|PUT|DELETE) ([^"]+)"', text[:8000])
            if emails or len(ips) > 3 or len(paths) > 5:
                findings.append(Finding(
                    "high", "data_exposure",
                    f"Log file נגיש — {path}",
                    f"קובץ log חשוף — מכיל {'אימיילים, ' if emails else ''}"
                    f"{len(ips)} כתובות IP, {len(paths)} בקשות HTTP.",
                    [f"URL: {url}",
                     f"גודל: {len(r.content):,} bytes",
                     *(f"אימייל: {e}" for e in emails[:3]),
                     *(f"IP: {ip}" for ip in ips[:3]),
                     *(f"Path: {p}" for p in paths[:3])],
                    "שמור logs מחוץ ל-webroot. חסום גישה לקבצי .log בשרת.",
                ))
            return

        # ── Directory listing ─────────────────────────────────────────────────
        if category == "directory" and _DIR_LISTING_RE.search(text):
            file_links = re.findall(r'href="([^"?#]+)"', text)
            data_files = [f for f in file_links
                         if Path(f.split("?")[0]).suffix.lower() in _DATA_EXT]
            findings.append(Finding(
                "high", "data_exposure",
                f"Directory Listing פתוח — {path}",
                f"תיקיית {path!r} חושפת את תכולתה לכולם. "
                f"נמצאו {len(file_links)} קבצים, {len(data_files)} קבצי נתונים.",
                [f"URL: {url}",
                 f"קבצים בתיקייה: {len(file_links)}",
                 *[f"📁 {f}" for f in data_files[:10]]],
                "Nginx: autoindex off;  |  Apache: Options -Indexes",
            ))
            return

        # ── JSON API ──────────────────────────────────────────────────────────
        if "json" in ct or text.lstrip()[:1] in ("[", "{"):
            sev, evidence = _analyze_json(text, url)
            if sev:
                cat_heb = {
                    "users": "משתמשים / לקוחות",
                    "orders": "הזמנות / עסקאות / תשלומים",
                    "admin":  "ממשק ניהול",
                    "export": "export",
                }.get(category, "נתונים")
                findings.append(Finding(
                    sev, "data_exposure",
                    f"API חושף {cat_heb} ללא הרשאה — {path}",
                    f"Endpoint {path} מחזיר נתונים רגישים ללא authentication. "
                    "ראה OWASP API1 (Broken Object Authorization).",
                    evidence,
                    "הוסף authentication לכל API endpoint. "
                    "בצע authorization check לפי משתמש מחובר. "
                    "לעולם אל תחזיר יותר נתונים ממה שהמשתמש צריך (principle of least privilege).",
                ))

    # Run all probes concurrently (batched)
    batch_size = 10
    items = list(_DATA_ENDPOINTS)
    for i in range(0, len(items), batch_size):
        batch = items[i: i + batch_size]
        await asyncio.gather(*[_probe(p, c) for p, c in batch], return_exceptions=True)

    # ── 2. GraphQL introspection ──────────────────────────────────────────────
    for gql_path in ["/graphql", "/api/graphql", "/graphql/v1", "/gql", "/query"]:
        url = base + gql_path
        if url in tested:
            continue
        tested.add(url)
        try:
            r = await client.post(
                url,
                content=_GRAPHQL_INTRO.encode(),
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
            if r.status_code == 200 and "__schema" in r.text:
                type_names = re.findall(r'"name"\s*:\s*"([A-Z][a-zA-Z]+)"', r.text)
                sensitive  = [t for t in type_names if any(
                    k in t.lower() for k in
                    ["user", "customer", "order", "payment", "password", "token", "auth", "cart"]
                )]
                findings.append(Finding(
                    "high", "data_exposure",
                    f"GraphQL Introspection פעיל — {gql_path}",
                    "GraphQL introspection חשוף — תוקף רואה את כל מבני הנתונים לפני ניצול.",
                    [f"URL: {url}",
                     f"Types: {len(type_names)} נמצאו",
                     f"Sensitive types: {', '.join(sensitive[:10]) or 'לא זוהו'}"],
                    "השבת introspection ב-production:\n"
                    "Apollo: introspection: false\n"
                    "GraphQL-core: validation_rules=[NoSchemaIntrospectionCustomRule]",
                ))
        except Exception:
            pass

    # ── 3. IDOR — enumerate adjacent records ──────────────────────────────────
    for tmpl in _IDOR_PATHS:
        url1 = base + tmpl.format(id=1)
        url2 = base + tmpl.format(id=2)
        if url1 in tested:
            continue
        tested.add(url1)
        tested.add(url2)
        try:
            r1, r2 = await asyncio.gather(
                client.get(url1, timeout=6),
                client.get(url2, timeout=6),
                return_exceptions=True,
            )
            if (isinstance(r1, httpx.Response) and isinstance(r2, httpx.Response)
                    and r1.status_code == 200 and r2.status_code == 200
                    and len(r1.text) > 30 and len(r2.text) > 30
                    and r1.text != r2.text):
                path_display = tmpl.replace("{id}", "N")
                findings.append(Finding(
                    "high", "data_exposure",
                    f"IDOR — גישה לנתוני משתמשים/הזמנות אחרים — {path_display}",
                    f"Endpoint {path_display} מחזיר נתוני רשומות שונות ללא authorization check. "
                    "תוקף יכול לעבור על כל ה-IDs ולגנוב את כל הרשומות.",
                    [f"GET {tmpl.format(id=1)} → HTTP {r1.status_code} ({len(r1.text)} bytes)",
                     f"GET {tmpl.format(id=2)} → HTTP {r2.status_code} ({len(r2.text)} bytes)",
                     "שתי התגובות שונות ➜ IDOR confirmed"],
                    "ודא שכל endpoint בודק שהמשתמש המחובר הוא הבעלים של הרשומה. "
                    "אל תסמוך על ID מה-URL בלבד.",
                ))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 12. WAF DETECTION (wafw00f)
# ══════════════════════════════════════════════════════════════════════════════

async def check_waf(base_url: str) -> list[Finding]:
    """Detect Web Application Firewall using wafw00f."""
    findings = []
    if not is_available("wafw00f"):
        return findings
    try:
        code, stdout, stderr = await run_tool("wafw00f", [base_url], timeout=60)
        output = stdout + stderr
        for line in output.splitlines():
            line = line.strip()
            if "is behind" in line.lower():
                findings.append(Finding(
                    "info", "waf",
                    f"WAF Detected: {line}",
                    "A Web Application Firewall was detected protecting this site.",
                    [line],
                    "WAF rules may block automated scans. Consider WAF bypass techniques for authorized pen-tests.",
                ))
            elif "no waf" in line.lower():
                findings.append(Finding(
                    "medium", "waf",
                    "No WAF detected",
                    "No Web Application Firewall was detected. The application handles all security controls directly.",
                    [line],
                    "Consider deploying a WAF (CloudFlare, AWS WAF, ModSecurity) for defense-in-depth.",
                ))
    except Exception as e:
        log.debug("wafw00f error: %s", e)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 13. HIDDEN PARAMETER DISCOVERY (Arjun)
# ══════════════════════════════════════════════════════════════════════════════

async def check_hidden_params(pages: list[dict]) -> list[Finding]:
    """Run Arjun to discover hidden HTTP parameters."""
    findings = []
    if not is_available("arjun"):
        return findings

    tested: set[str] = set()
    for page in pages[:5]:
        parsed = urlparse(page["url"])
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base in tested:
            continue
        tested.add(base)

        try:
            code, stdout, stderr = await run_tool("arjun", [
                "-u", base,
                "--stable",
                "-t", "5",
                "-oJ", "/dev/stdout",
            ], timeout=90)
            if not stdout.strip():
                continue
            import json as _j2
            try:
                data = _j2.loads(stdout)
            except _j2.JSONDecodeError:
                continue
            for url_key, params in (data if isinstance(data, dict) else {}).items():
                if isinstance(params, list) and params:
                    findings.append(Finding(
                        "medium", "hidden_params",
                        f"Hidden parameters found: {', '.join(params[:5])}",
                        f"Arjun discovered {len(params)} hidden parameters on {url_key}",
                        [f"URL: {url_key}", f"Params: {', '.join(params[:10])}"],
                        "Hidden parameters may expose undocumented functionality. Test these for injection vulnerabilities.",
                    ))
        except Exception as e:
            log.debug("Arjun error: %s", e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# Main entry point — called from WebAuditor.full_audit()
# ══════════════════════════════════════════════════════════════════════════════

async def _noop() -> list:
    return []


async def run_advanced_checks(
    client: httpx.AsyncClient,
    pages: list[dict],
    base_url: str,
) -> list[Finding]:
    """Run all advanced checks and return combined findings."""

    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"

    CHECK_NAMES = [
        "SQLi", "SQLmap Deep SQLi", "XSS", "Dalfox XSS",
        "TLS/SSL", "testssl.sh Deep TLS",
        "HTTP Methods",
        "Open Redirect", "Path Traversal", "Tech Fingerprint",
        "SSTI", "Command Injection", "Commix Deep CmdInj",
        "Email Security (SPF/DMARC/DKIM)",
        "Data Exposure (API/IDOR/GraphQL)",
        "WAF Detection",
        "Hidden Parameters (Arjun)",
    ]

    raw = await asyncio.gather(
        check_sqli(client, pages),
        check_sqli_sqlmap(pages),
        check_xss(client, pages),
        check_xss_dalfox(pages),
        check_tls(hostname, port) if is_https else _noop(),
        check_tls_testssl(hostname, port) if is_https else _noop(),
        check_http_methods(client, base_url),
        check_open_redirect(client, pages),
        check_traversal(client, pages),
        check_tech_fingerprint(client, pages),
        check_ssti(client, pages),
        check_cmd_injection(client, pages),
        check_cmd_injection_commix(pages),
        check_email_security(hostname),
        check_data_exposure(client, base_url),
        check_waf(base_url),
        check_hidden_params(pages),
        return_exceptions=True,
    )

    all_findings: list[Finding] = []
    passed: list[str] = []
    errors: list[str] = []

    for name, result in zip(CHECK_NAMES, raw):
        if isinstance(result, Exception):
            errors.append(f"{name}: {type(result).__name__}: {str(result)[:80]}")
        elif isinstance(result, list):
            vulns = [f for f in result if f.severity not in ("info",)]
            if vulns:
                all_findings.extend(result)
            else:
                all_findings.extend(result)
                if not result:
                    passed.append(name)

    params_count = sum(len(parse_qs(urlparse(p["url"]).query)) for p in pages)
    tool_checks = []
    for tool_name in ("sqlmap", "dalfox", "testssl", "commix", "wafw00f", "arjun"):
        mode = "N/A"
        if is_available(tool_name):
            from core.tool_runner import get_mode
            mode = get_mode(tool_name) or "available"
        tool_checks.append(f"{tool_name}: {mode}")

    summary_lines = [
        f"דפים שנסרקו: {len(pages)}",
        f"פרמטרים שנבדקו ל-SQLi/XSS: ~{min(params_count, 30)}",
        f"בדיקות HTTP Methods: TRACE, PUT, DELETE, CONNECT",
        f"TLS/SSL: {'נבדק' if is_https else 'דולג (HTTP)'}",
        f"כלים חיצוניים: {' | '.join(tool_checks)}",
    ]
    if passed:
        summary_lines.append(f"עברו ללא ממצאים: {', '.join(passed)}")
    if errors:
        summary_lines.append(f"שגיאות: {' | '.join(errors)}")

    all_findings.append(Finding(
        "info", "advanced_summary",
        f"בדיקות מתקדמות — סיכום ({len([f for f in all_findings if f.severity not in ('info',)])} ממצאים)",
        "17 בדיקות אקטיביות: SQLi, SQLmap, XSS, Dalfox, TLS, testssl.sh, HTTP Methods, Open Redirect, "
        "Path Traversal, Tech Fingerprint, SSTI, Command Injection, Commix, Email Security, Data Exposure, WAF, Arjun.",
        summary_lines,
        "",
    ))

    return all_findings
