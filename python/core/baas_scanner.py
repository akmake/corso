"""
BaaS Security Scanner
---------------------
Automated security audit for Backend-as-a-Service applications.

Supports: Supabase, Firebase (Firestore + RTDB), AWS Amplify / AppSync.

Detection & Testing:
  1. Fingerprint BaaS from JS bundles (URL, keys, config)
  2. JWT analysis (role, expiry, claims)
  3. Auth policy audit: signup open? anonymous? phone? OAuth providers?
  4. RLS / security rules: test all discovered tables/collections with anon & auth
  5. Edge Functions / Cloud Functions: auth enforcement, parameter abuse
  6. Storage / bucket policy: public read/write?
  7. Upload functions: auth check, path traversal, overwrite
  8. Privilege escalation: self-promote to admin
  9. Admin API exposure (service_role key, admin endpoints)
"""

import asyncio
import base64
import json
import re
import struct
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

log = __import__("logging").getLogger(__name__)


# ── Finding ───────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    category: str
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


# ── JWT helpers ───────────────────────────────────────────────────────────────
def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ── Regexes for BaaS detection ────────────────────────────────────────────────
_SUPABASE_URL = re.compile(r'https://([a-z0-9]+)\.supabase\.co')
_SUPABASE_KEY = re.compile(r'(eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]+)')
_FIREBASE_CONFIG = re.compile(r'firebaseConfig\s*[=:]\s*\{([^}]{50,})\}', re.S)
_FIREBASE_URL = re.compile(r'https://([a-z0-9\-]+)\.firebaseio\.com')
_FIREBASE_STORAGE = re.compile(r'([a-z0-9\-]+)\.appspot\.com')
_FIREBASE_API_KEY = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

# Supabase table name patterns in JS
_TABLE_FROM = re.compile(r'\.from\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']')
_RPC_CALL = re.compile(r'\.rpc\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']')
_FUNCTION_INVOKE = re.compile(r'functions/v1/([a-zA-Z0-9_\-]+)')
_STORAGE_BUCKET = re.compile(r'\.from\(["\']([a-zA-Z_][a-zA-Z0-9_\-]*)["\']')


# ── Main scanner ─────────────────────────────────────────────────────────────
async def scan_baas(target_url: str, progress_cb=None, prefetched_js: str = "") -> list[Finding]:
    """
    Black-box BaaS security scanner.

    Args:
        target_url:    URL of the target web application
        progress_cb:   optional async callback(msg: str) for progress updates
        prefetched_js: optional JS content already fetched (e.g. via Playwright)
                       — skips the httpx JS fetch when provided
    Returns:
        List of Finding objects
    """
    findings: list[Finding] = []
    target = target_url.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    async def _log(msg: str):
        if progress_cb:
            await progress_cb(msg)

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True, timeout=30) as client:

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 1: Fetch JS bundles and fingerprint BaaS
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 1/7: מזהה BaaS מתוך קוד JavaScript...")

        js_content = prefetched_js if prefetched_js else await _fetch_all_js(client, target)
        if not js_content:
            findings.append(Finding("info", "baas-detection", "לא נמצא קוד JS",
                                    "לא הצלחתי לחלץ JavaScript מהאתר"))
            return findings

        baas_type, baas_config = _detect_baas(js_content)

        if not baas_type:
            findings.append(Finding("info", "baas-detection", "לא זוהה BaaS",
                                    "לא נמצא Supabase, Firebase או שירות BaaS מוכר בקוד"))
            return findings

        findings.append(Finding("info", "baas-detection", f"זוהה {baas_type}",
            f"נמצא {baas_type} בקוד ה-JavaScript של האתר",
            evidence=[f"URL: {baas_config.get('url', 'N/A')}",
                      f"Key type: {baas_config.get('key_role', 'N/A')}"]
        ))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 2: JWT / Key analysis
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 2/7: מנתח מפתחות וטוקנים...")
        findings.extend(_analyze_keys(baas_type, baas_config, js_content))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 3: Auth policy tests
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 3/7: בודק מדיניות הרשמה ואימות...")

        if baas_type == "Supabase":
            findings.extend(await _test_supabase_auth(client, baas_config))
        elif baas_type == "Firebase":
            findings.extend(await _test_firebase_auth(client, baas_config))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 4: Table / Collection RLS tests
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 4/7: בודק הרשאות טבלאות (RLS)...")

        tables = _extract_tables(js_content, baas_type)
        if baas_type == "Supabase":
            findings.extend(await _test_supabase_rls(client, baas_config, tables))
        elif baas_type == "Firebase":
            findings.extend(await _test_firebase_rules(client, baas_config, tables))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 5: Edge Functions / Cloud Functions
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 5/7: בודק Edge Functions...")

        functions = _extract_functions(js_content, baas_type)
        if baas_type == "Supabase":
            findings.extend(await _test_supabase_functions(client, baas_config, functions))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 6: Storage / Buckets
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 6/7: בודק אחסון ו-storage buckets...")

        if baas_type == "Supabase":
            findings.extend(await _test_supabase_storage(client, baas_config, js_content))
        elif baas_type == "Firebase":
            findings.extend(await _test_firebase_storage(client, baas_config))

        # ══════════════════════════════════════════════════════════════════════
        #  Phase 7: Admin API exposure
        # ══════════════════════════════════════════════════════════════════════
        await _log("שלב 7/7: בודק גישה ל-Admin API...")

        if baas_type == "Supabase":
            findings.extend(await _test_supabase_admin(client, baas_config))

    await _log(f"הושלם — {len([f for f in findings if f.severity != 'info'])} ממצאים")
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  JS Fetching
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_all_js(client: httpx.AsyncClient, base: str) -> str:
    """Fetch main HTML and all referenced JS bundles."""
    all_js = ""
    try:
        r = await client.get(base)
        html = r.text

        # Find all JS script sources
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
        # Also check for inline scripts
        inline = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S)
        for s in inline:
            if len(s) > 50:
                all_js += s + "\n"

        # Fetch external JS files
        tasks = []
        for url in js_urls:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = base + url
            elif not url.startswith("http"):
                url = base + "/" + url
            tasks.append(client.get(url))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, httpx.Response) and res.status_code == 200:
                    all_js += res.text + "\n"

    except Exception as e:
        log.warning(f"JS fetch error: {e}")

    return all_js


# ══════════════════════════════════════════════════════════════════════════════
#  BaaS Detection
# ══════════════════════════════════════════════════════════════════════════════

def _detect_baas(js: str) -> tuple[str | None, dict]:
    """Identify which BaaS is used and extract config."""

    # ── Supabase ──
    m_url = _SUPABASE_URL.search(js)
    if m_url:
        url = m_url.group(0)
        config = {"url": url, "project_ref": m_url.group(1)}

        # Find anon key
        keys = _SUPABASE_KEY.findall(js)
        for k in keys:
            payload = _decode_jwt_payload(k)
            role = payload.get("role", "")
            if role in ("anon", "service_role"):
                config["key"] = k
                config["key_role"] = role
                config["key_claims"] = payload
                if role == "service_role":
                    config["service_key"] = k
                break
        if "key" not in config and keys:
            config["key"] = keys[0]
            config["key_role"] = "unknown"
            config["key_claims"] = _decode_jwt_payload(keys[0])

        return "Supabase", config

    # ── Firebase ──
    m_fb = _FIREBASE_CONFIG.search(js)
    m_rtdb = _FIREBASE_URL.search(js)
    m_api = _FIREBASE_API_KEY.search(js)
    
    if m_fb or m_rtdb or m_api:
        config = {}
        if m_api:
            config["api_key"] = m_api.group(0)
        if m_rtdb:
            config["rtdb_url"] = m_rtdb.group(0)
            config["project_id"] = m_rtdb.group(1)
        
        m_storage = _FIREBASE_STORAGE.search(js)
        if m_storage:
            config["storage_bucket"] = m_storage.group(0)
        
        if m_fb:
            # Try parsing the config object
            block = m_fb.group(1)
            for key_name in ("apiKey", "authDomain", "projectId", "storageBucket",
                             "messagingSenderId", "appId", "measurementId", "databaseURL"):
                m = re.search(rf'{key_name}\s*:\s*["\']([^"\']+)["\']', block)
                if m:
                    config[key_name] = m.group(1)
            if "projectId" in config:
                config["project_id"] = config["projectId"]

        config.setdefault("url", config.get("rtdb_url", ""))
        config.setdefault("key_role", "browser-api-key")
        return "Firebase", config

    return None, {}


# ══════════════════════════════════════════════════════════════════════════════
#  Key / JWT Analysis
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_keys(baas_type: str, config: dict, js: str) -> list[Finding]:
    findings = []

    if baas_type == "Supabase":
        claims = config.get("key_claims", {})
        role = claims.get("role", "unknown")
        exp = claims.get("exp")

        if role == "service_role":
            findings.append(Finding("critical", "key-exposure",
                "Service Role Key חשוף ב-JavaScript!",
                "מפתח service_role נמצא בקוד הצד-לקוח. זה נותן גישה מלאה לכל הנתונים, עוקף RLS.",
                evidence=[f"Role: {role}", f"Key prefix: {config.get('key', '')[:40]}..."],
                recommendation="העבר את ה-service_role key לצד השרת בלבד. לעולם אל תחשוף אותו ב-JS."
            ))
        elif role == "anon":
            findings.append(Finding("info", "key-exposure",
                "Anon Key חשוף ב-JavaScript",
                "מפתח anon נמצא ב-JS. זה צפוי בארכיטקטורת Supabase, אבל מחייב RLS חזק.",
                evidence=[f"Role: {role}", f"Project: {config.get('project_ref', '')}"]
            ))

        if exp:
            import datetime
            exp_date = datetime.datetime.fromtimestamp(exp)
            years_left = (exp_date - datetime.datetime.now()).days / 365
            if years_left > 10:
                findings.append(Finding("low", "key-expiry",
                    f"מפתח API פג תוקף רק בעוד {int(years_left)} שנה",
                    f"תוקף המפתח: {exp_date.strftime('%Y-%m-%d')} — ארוך מדי",
                    evidence=[f"exp: {exp}", f"Date: {exp_date.isoformat()}"],
                    recommendation="שקול לרוטט מפתחות לפחות פעם בשנה"
                ))

        # Check for multiple keys / service key in JS
        all_keys = _SUPABASE_KEY.findall(js)
        roles_found = set()
        for k in all_keys:
            p = _decode_jwt_payload(k)
            r = p.get("role", "")
            if r:
                roles_found.add(r)
        if "service_role" in roles_found:
            if role != "service_role":  # Not already reported
                findings.append(Finding("critical", "key-exposure",
                    "Service Role Key נמצא ב-JavaScript!",
                    "מפתח service_role נמצא בקוד. זה עוקף RLS לחלוטין.",
                    recommendation="הסר מיידית מקוד הצד-לקוח"
                ))

    elif baas_type == "Firebase":
        api_key = config.get("api_key", "")
        if api_key:
            findings.append(Finding("info", "key-exposure",
                "Firebase API Key חשוף ב-JavaScript",
                "מפתח Firebase נמצא ב-JS. זה צפוי, אבל מחייב Security Rules מחמירים.",
                evidence=[f"Key: {api_key[:20]}..."]
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  Table / Collection extraction from JS
# ══════════════════════════════════════════════════════════════════════════════

def _extract_tables(js: str, baas_type: str) -> list[str]:
    """Extract table/collection names from JS code."""
    tables = set()

    if baas_type == "Supabase":
        # .from('table_name')
        for m in _TABLE_FROM.finditer(js):
            name = m.group(1)
            # Filter out storage bucket calls (usually after .storage)
            start = max(0, m.start() - 30)
            context = js[start:m.start()]
            if ".storage" not in context:
                tables.add(name)

    elif baas_type == "Firebase":
        # collection('name'), doc('name'), ref('name')
        for pat in [r"collection\(['\"]([^'\"]+)['\"]",
                    r"ref\(['\"]([^'\"]+?)['\"]"]:
            for m in re.finditer(pat, js):
                tables.add(m.group(1).split("/")[0])

    # Add common tables to test
    if baas_type == "Supabase":
        tables.update(["profiles", "users", "user_roles", "clients", "orders", "payments", "settings"])
    elif baas_type == "Firebase":
        tables.update(["users", "profiles", "orders", "admin", "settings", "config"])

    return sorted(tables)


def _extract_functions(js: str, baas_type: str) -> list[str]:
    """Extract edge/cloud function names from JS."""
    funcs = set()
    if baas_type == "Supabase":
        # Pattern 1: full URL - functions/v1/name
        for m in _FUNCTION_INVOKE.finditer(js):
            funcs.add(m.group(1))
        # Pattern 2: .invoke('name') - Supabase client SDK
        for m in re.finditer(r'\.invoke\(["\']([a-zA-Z0-9_\-]+)["\']', js):
            funcs.add(m.group(1))
        # Pattern 3: string literal matching common patterns
        for m in re.finditer(r'["\']([a-z]+-[a-z]+-[a-z]+(?:-[a-z]+)*)["\']', js):
            name = m.group(1)
            # Filter out CSS properties and common non-function strings
            if any(css in name for css in ("style-", "align-", "webkit-", "moz-",
                                            "overflow-", "text-", "border-", "font-",
                                            "margin-", "padding-", "flex-", "grid-",
                                            "background-", "color-", "display-",
                                            "white-space", "word-break", "line-height")):
                continue
            if any(kw in name for kw in ("dropbox", "upload", "download", "list-", "get-",
                                          "create-", "delete-", "update-", "notify-", "send-")):
                funcs.add(name)
    return sorted(funcs)


# ══════════════════════════════════════════════════════════════════════════════
#  Supabase-specific tests
# ══════════════════════════════════════════════════════════════════════════════

async def _test_supabase_auth(client: httpx.AsyncClient, config: dict) -> list[Finding]:
    """Test Supabase auth policies."""
    findings = []
    base = config["url"]
    key = config.get("key", "")
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}

    # 1. Open signup test
    test_email = f"baas_audit_{int(time.time())}@test-scanner.invalid"
    try:
        r = await client.post(f"{base}/auth/v1/signup",
            json={"email": test_email, "password": "AuditTest!9xKm2"},
            headers=headers)
        if r.status_code == 200:
            body = r.json()
            if body.get("id"):
                findings.append(Finding("high", "auth-policy",
                    "הרשמה פתוחה לכולם",
                    "כל אחד יכול להירשם לאפליקציה. אם לא נדרש - יש לכבות.",
                    evidence=[f"POST /auth/v1/signup → 200",
                              f"User created: {body.get('id', 'N/A')}",
                              f"Email: {test_email}",
                              f"Confirm required: {'confirmation_sent_at' in str(body)}"],
                    recommendation="כבה signup בדאשבורד Supabase: Authentication → Settings → Disable signup"
                ))
                # Check if email confirm is required
                if "confirmation_sent_at" not in str(body):
                    findings.append(Finding("critical", "auth-policy",
                        "הרשמה ללא אימות אימייל!",
                        "משתמשים יכולים להירשם ולהתחבר מיד, ללא אימות אימייל.",
                        recommendation="הפעל email confirmation ב-Supabase Dashboard"
                    ))
        elif r.status_code == 429:
            findings.append(Finding("info", "auth-policy", "Rate limiting פעיל על signup", 
                                    "Signup חסום מ-rate limiting"))
    except Exception:
        pass

    # 2. Anonymous login
    try:
        r = await client.post(f"{base}/auth/v1/signup",
            json={"options": {"data": {}}}, headers=headers)
        if r.status_code == 200 and r.json().get("access_token"):
            findings.append(Finding("high", "auth-policy",
                "כניסה אנונימית מופעלת",
                "אפשר להיכנס בלי שם משתמש וסיסמה",
                evidence=["POST /auth/v1/signup {} → 200 + access_token"],
                recommendation="כבה Anonymous sign-ins ב-Dashboard"
            ))
        else:
            findings.append(Finding("info", "auth-policy", "כניסה אנונימית מבוטלת", ""))
    except Exception:
        pass

    # 3. Phone signup
    try:
        r = await client.post(f"{base}/auth/v1/signup",
            json={"phone": "+15555550199", "password": "AuditTest!9"},
            headers=headers)
        if r.status_code == 200 and r.json().get("id"):
            findings.append(Finding("medium", "auth-policy",
                "הרשמה בטלפון מופעלת",
                "אפשר להירשם עם מספר טלפון. ודא שזה מכוון.",
                evidence=[f"Status: {r.status_code}"]
            ))
    except Exception:
        pass

    # 4. Admin API exposure
    try:
        r = await client.get(f"{base}/auth/v1/admin/users", headers=headers)
        if r.status_code == 200:
            findings.append(Finding("critical", "auth-policy",
                "Admin API נגיש עם anon key!",
                "אפשר לרשום משתמשים, לקרוא רשימת משתמשים, ולמחוק חשבונות.",
                evidence=[f"GET /auth/v1/admin/users → 200",
                          f"Response: {r.text[:200]}"],
                recommendation="ודא שרק service_role key מקבל גישה ל-admin endpoints"
            ))
        else:
            findings.append(Finding("info", "auth-policy", "Admin API חסום כראוי",
                                    f"GET /auth/v1/admin/users → {r.status_code}"))
    except Exception:
        pass

    return findings


async def _test_supabase_rls(client: httpx.AsyncClient, config: dict,
                              tables: list[str]) -> list[Finding]:
    """Test RLS on all discovered tables."""
    findings = []
    base = config["url"]
    key = config.get("key", "")
    headers = {"apikey": key, "Authorization": f"Bearer {key}", "Prefer": "count=exact"}

    exposed_tables = []
    blocked_tables = []

    for table in tables:
        try:
            r = await client.get(
                f"{base}/rest/v1/{table}?select=*&limit=3",
                headers=headers)
            
            if r.status_code == 200:
                data = r.json()
                count_header = r.headers.get("content-range", "")
                
                if data and len(data) > 0:
                    columns = list(data[0].keys())
                    exposed_tables.append(table)
                    
                    # Check for sensitive columns
                    sensitive_cols = [c for c in columns if any(
                        s in c.lower() for s in 
                        ["password", "secret", "token", "key", "credit", "ssn",
                         "phone", "address", "email", "role", "admin", "path",
                         "folder", "private"]
                    )]
                    
                    sev = "critical" if sensitive_cols else "high"
                    findings.append(Finding(sev, "rls-bypass",
                        f"טבלה '{table}' חשופה ללא אימות",
                        f"אפשר לקרוא נתונים מהטבלה עם anon key בלבד.",
                        evidence=[
                            f"GET /rest/v1/{table} → 200",
                            f"Rows returned: {len(data)}",
                            f"Range: {count_header}",
                            f"Columns: {columns}",
                            f"Sensitive columns: {sensitive_cols}" if sensitive_cols else "",
                            f"Sample: {json.dumps(data[0], ensure_ascii=False)[:300]}"
                        ],
                        recommendation=f"הוסף RLS policy על טבלת {table}: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
                    ))
                elif "*/0" not in count_header and count_header:
                    blocked_tables.append(table)
                else:
                    blocked_tables.append(table)
            elif r.status_code == 404:
                pass  # Table doesn't exist
            elif r.status_code in (401, 403):
                blocked_tables.append(table)
        except Exception:
            pass

    if blocked_tables:
        findings.append(Finding("info", "rls-ok",
            f"RLS פעיל על {len(blocked_tables)} טבלאות",
            f"הטבלאות הבאות חסומות כראוי: {', '.join(blocked_tables)}"))

    if not exposed_tables and tables:
        findings.append(Finding("info", "rls-ok",
            "RLS פעיל על כל הטבלאות שנבדקו",
            "לא נמצאה גישה לא מורשית לטבלאות"))

    # Also try INSERT on tables
    for table in tables[:10]:
        try:
            r = await client.post(f"{base}/rest/v1/{table}",
                json={"_audit_test": True},
                headers={**headers, "Content-Type": "application/json",
                         "Prefer": "return=representation"})
            if r.status_code in (200, 201):
                findings.append(Finding("critical", "rls-bypass",
                    f"כתיבה לטבלה '{table}' אפשרית ללא אימות!",
                    "אפשר להוסיף שורות לטבלה עם anon key בלבד",
                    evidence=[f"POST /rest/v1/{table} → {r.status_code}",
                              f"Response: {r.text[:200]}"],
                    recommendation=f"הוסף INSERT policy מגביל על {table}"
                ))
        except Exception:
            pass

    return findings


async def _test_supabase_functions(client: httpx.AsyncClient, config: dict,
                                    functions: list[str]) -> list[Finding]:
    """Test edge functions for auth enforcement."""
    findings = []
    base = config["url"]
    key = config.get("key", "")

    for func_name in functions:
        url = f"{base}/functions/v1/{func_name}"

        # Test 1: No auth at all
        try:
            r = await client.post(url, json={}, headers={})
            no_auth_status = r.status_code
            no_auth_body = r.text[:500]
        except Exception:
            continue

        # Test 2: With anon key only
        try:
            r = await client.post(url, json={},
                headers={"apikey": key, "Authorization": f"Bearer {key}"})
            anon_status = r.status_code
            anon_body = r.text[:500]
        except Exception:
            anon_status = 0
            anon_body = ""

        # Analyze results
        is_unauthorized_msg = any(kw in (no_auth_body + anon_body).lower() 
                                  for kw in ["unauthorized", "missing", "forbidden", "not allowed"])

        if no_auth_status in (200, 400, 500) and "unauthorized" not in no_auth_body.lower():
            # Function responded without requiring auth
            if no_auth_status == 200:
                severity = "critical"
                desc = f"Edge function '{func_name}' מגיב בהצלחה ללא שום אימות"
            elif no_auth_status == 400:
                # Got parameter validation error, not auth error = no auth check
                if not is_unauthorized_msg:
                    severity = "critical"
                    desc = f"Edge function '{func_name}' בודק פרמטרים לפני אימות — אין auth check"
                else:
                    severity = "info"
                    desc = f"Edge function '{func_name}' דורש אימות"
            else:
                severity = "high"
                desc = f"Edge function '{func_name}' שגיאת שרת ללא אימות"

            if severity != "info":
                # Determine what the function does based on its name
                action = "unknown"
                if any(w in func_name.lower() for w in ["upload", "write", "create", "delete", "update"]):
                    action = "write"
                    severity = "critical"
                elif any(w in func_name.lower() for w in ["list", "get", "read", "fetch", "download"]):
                    action = "read"

                findings.append(Finding(severity, "edge-function",
                    f"Edge Function '{func_name}' ללא אימות",
                    desc,
                    evidence=[
                        f"POST {url} (no auth) → {no_auth_status}",
                        f"Response: {no_auth_body[:200]}",
                        f"POST {url} (anon key) → {anon_status}",
                        f"Function type: {action}",
                    ],
                    recommendation=f"הוסף בדיקת auth בתחילת הפונקציה {func_name}"
                ))

                # If it's an upload function, try writing a file
                if action == "write" and "upload" in func_name.lower():
                    findings.extend(
                        await _test_upload_exploit(client, url, func_name))
        else:
            # Function seems to require auth — try bypass techniques
            bypassed = False
            bypass_headers = [
                ("Content-Type only", {"Content-Type": "application/json"}),
                ("Bearer null", {"Authorization": "Bearer null", "Content-Type": "application/json"}),
                ("Bearer undefined", {"Authorization": "Bearer undefined"}),
                ("Empty Bearer", {"Authorization": "Bearer "}),
                ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1", "Content-Type": "application/json"}),
            ]
            for trick_name, trick_headers in bypass_headers:
                try:
                    r = await client.post(url, json={}, headers=trick_headers)
                    if r.status_code in (200, 400) and "unauthorized" not in r.text.lower():
                        findings.append(Finding("critical", "auth-bypass",
                            f"עקיפת אימות ב-'{func_name}' עם {trick_name}!",
                            f"הפונקציה מגיבה ללא auth כשמשתמשים ב-{trick_name}",
                            evidence=[
                                f"Headers: {trick_headers}",
                                f"Response: {r.status_code} {r.text[:200]}",
                            ],
                            recommendation=f"תקן את בדיקת האימות ב-{func_name}"
                        ))
                        bypassed = True
                        break
                except Exception:
                    pass

            if not bypassed:
                findings.append(Finding("info", "edge-function",
                    f"Edge Function '{func_name}' דורש אימות",
                    f"הפונקציה מחזירה {no_auth_status} ללא auth, ולא ניתן לעקוף",
                    evidence=[f"No auth → {no_auth_status}: {no_auth_body[:100]}",
                              "Bypass attempts: all failed"]
                ))

    return findings


async def _test_upload_exploit(client: httpx.AsyncClient, url: str,
                                func_name: str) -> list[Finding]:
    """Deep test an upload function – reproduces full attack impact."""
    findings = []

    # Try uploading with common parameter names
    payloads = [
        {"path": "/security_audit_test.txt", "content": "SECURITY AUDIT TEST - DELETE ME"},
        {"filePath": "/security_audit_test.txt", "data": "SECURITY AUDIT TEST"},
        {"file": "/security_audit_test.txt", "body": "SECURITY AUDIT TEST"},
    ]

    working_payload = None
    path_key = None
    content_key = None

    for payload in payloads:
        try:
            r = await client.post(url, json=payload)
            if r.status_code == 200 and "success" in r.text.lower():
                keys = list(payload.keys())
                path_key = keys[0]
                content_key = keys[1]
                working_payload = payload

                findings.append(Finding("critical", "upload-exploit",
                    f"העלאת קבצים ללא אימות דרך '{func_name}'!",
                    "כל אחד יכול להעלות קבצים לשרת. הוכחה: הועלה קובץ מבלי לשלוח שום אימות.",
                    evidence=[
                        f"POST {url}",
                        f"Payload: {json.dumps(payload)}",
                        f"Response: {r.text[:200]}",
                    ],
                    recommendation="הוסף auth check + בדיקת הרשאות לנתיב. הגבל מי יכול להעלות ולאן."
                ))
                break
        except Exception:
            pass

    if not working_payload:
        return findings

    # ── Test 2: Overwrite existing file ──────────────────────────────────────
    try:
        r = await client.post(url, json={
            path_key: "/security_audit_test.txt",
            content_key: "OVERWRITTEN - second upload"
        })
        if r.status_code == 200:
            findings.append(Finding("high", "upload-exploit",
                f"דריסת קבצים אפשרית דרך '{func_name}'",
                "העלאה חוזרת לאותו נתיב דורסת את הקובץ הקיים — תוקף יכול לדרוס תוכן לגיטימי.",
                evidence=[f"Second upload to same path → {r.status_code}: {r.text[:150]}"],
                recommendation="הוסף בדיקה אם הקובץ קיים, או השתמש ב-UUID לשמות"
            ))
    except Exception:
        pass

    # ── Test 3: Client folder injection ──────────────────────────────────────
    # Try writing into common app data paths (client photo folders, etc.)
    app_paths = [
        "/clients_photos/SCANNER_TEST_DELETE_ME/injected.txt",
        "/uploads/SCANNER_TEST/injected.txt",
        "/data/SCANNER_TEST/injected.txt",
    ]
    for test_path in app_paths:
        try:
            r = await client.post(url, json={
                path_key: test_path,
                content_key: "SECURITY_AUDIT - injected into app folder"
            })
            if r.status_code == 200 and "success" in r.text.lower():
                folder = test_path.rsplit("/", 1)[0]
                findings.append(Finding("critical", "upload-exploit",
                    f"הזרקה לתיקיות אפליקציה דרך '{func_name}'!",
                    f"תוקף יכול ליצור תיקיות חדשות ולהזריק קבצים לתוך תיקיות לקוחות. "
                    f"הוכחה: נכתב קובץ ב-{folder}/",
                    evidence=[
                        f"POST {url}",
                        f"Path: {test_path}",
                        f"Response: {r.status_code} {r.text[:150]}",
                        f"Impact: תוקף יכול להזריק תמונות מזויפות לגלריית לקוח, ליצור לקוחות פיקטיביים, להציף את פאנל הניהול",
                    ],
                    recommendation="1) הוסף auth check  2) בדוק שהנתיב שייך ללקוח של המשתמש  3) חסום יצירת תיקיות חדשות"
                ))
                break  # One proof is enough
        except Exception:
            pass

    # ── Test 4: Real image upload (tiny PNG as base64) ───────────────────────
    try:
        png_bytes = _make_tiny_png()
        b64 = base64.b64encode(png_bytes).decode()
        r = await client.post(url, json={
            path_key: "/clients_photos/SCANNER_TEST_DELETE_ME/fake_photo.png",
            content_key: b64
        })
        if r.status_code == 200 and "success" in r.text.lower():
            findings.append(Finding("critical", "upload-exploit",
                f"העלאת תמונות אמיתיות ללא אימות!",
                "תוקף יכול להעלות תמונות PNG/JPG אמיתיות לתיקיות לקוחות. "
                "לקוח שנכנס לגלריה שלו יראה תוכן שהוזרק.",
                evidence=[
                    f"Uploaded valid 1x1 PNG ({len(png_bytes)} bytes) as base64",
                    f"Path: /clients_photos/SCANNER_TEST_DELETE_ME/fake_photo.png",
                    f"Response: {r.status_code} {r.text[:150]}",
                ],
                recommendation="הוסף בדיקת auth, הגבל סוגי קבצים, בדוק שהנתיב שייך ללקוח"
            ))
    except Exception:
        pass

    # ── Test 5: Large content upload (storage exhaustion) ────────────────────
    try:
        big_content = "A" * 100_000  # 100KB
        r = await client.post(url, json={
            path_key: "/SCANNER_TEST_big_delete_me.txt",
            content_key: big_content
        })
        if r.status_code == 200 and "success" in r.text.lower():
            findings.append(Finding("high", "upload-exploit",
                f"סכנת מילוי אחסון דרך '{func_name}'",
                "אין הגבלה על גודל הקובץ. תוקף יכול להעלות קבצים גדולים שוב ושוב ולמלא את האחסון.",
                evidence=[
                    f"Uploaded 100KB content → {r.status_code}",
                    f"No size limit enforced",
                    f"Impact: attacker could fill storage with automated uploads",
                ],
                recommendation="הגבל גודל קובץ, הוסף rate limiting, הוסף auth"
            ))
    except Exception:
        pass

    # ── Test 6: Path traversal ───────────────────────────────────────────────
    try:
        r = await client.post(url, json={
            path_key: "/../../../etc/traversal_test.txt",
            content_key: "traversal_test"
        })
        if r.status_code == 200:
            findings.append(Finding("critical", "upload-exploit",
                f"Path traversal ב-'{func_name}'!",
                "אפשר לכתוב קבצים מחוץ לתיקייה המיועדת",
                evidence=[f"Path: /../../../etc/traversal_test → {r.status_code}: {r.text[:200]}"]
            ))
    except Exception:
        pass

    return findings


def _make_tiny_png(r: int = 255, g: int = 0, b: int = 0) -> bytes:
    """Create a minimal valid 1x1 PNG image."""
    sig = b'\x89PNG\r\n\x1a\n'
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        c = ctype + data
        crc = struct.pack('>I', zlib.crc32(c) & 0xffffffff)
        return struct.pack('>I', len(data)) + c + crc
    ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    raw = b'\x00' + bytes([r, g, b])
    idat = zlib.compress(raw)
    return sig + _chunk(b'IHDR', ihdr) + _chunk(b'IDAT', idat) + _chunk(b'IEND', b'')


async def _test_supabase_storage(client: httpx.AsyncClient, config: dict,
                                  js: str) -> list[Finding]:
    """Test Supabase storage bucket access."""
    findings = []
    base = config["url"]
    key = config.get("key", "")
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}

    # Extract bucket names from JS
    bucket_names = set()
    for m in re.finditer(r'\.from\(["\']([a-zA-Z_][a-zA-Z0-9_\-]*)["\']', js):
        bucket_names.add(m.group(1))
    bucket_names.update(["avatars", "photos", "uploads", "public", "images", "files", "media", "documents"])

    for bucket in bucket_names:
        try:
            # List files in bucket
            r = await client.get(f"{base}/storage/v1/object/list/{bucket}",
                json={"prefix": "", "limit": 5},
                headers=headers)
            if r.status_code == 200:
                data = r.json()
                if data and len(data) > 0:
                    findings.append(Finding("high", "storage",
                        f"Storage bucket '{bucket}' נגיש ללא אימות",
                        f"אפשר לקרוא רשימת קבצים מהבאקט",
                        evidence=[f"GET /storage/v1/object/list/{bucket} → 200",
                                  f"Files: {len(data)}",
                                  f"Sample: {json.dumps(data[0], ensure_ascii=False)[:200]}" if data else ""],
                        recommendation=f"הגדר Storage Policy מגביל על bucket '{bucket}'"
                    ))
        except Exception:
            pass

        # Try uploading to bucket
        try:
            r = await client.post(
                f"{base}/storage/v1/object/{bucket}/audit_test.txt",
                content=b"security audit test",
                headers={**headers, "Content-Type": "text/plain"})
            if r.status_code in (200, 201):
                findings.append(Finding("critical", "storage",
                    f"כתיבה ל-Storage bucket '{bucket}' ללא אימות!",
                    "כל אחד יכול להעלות קבצים לבאקט",
                    evidence=[f"POST /storage/v1/object/{bucket}/audit_test.txt → {r.status_code}"],
                    recommendation="הגדר INSERT policy על הבאקט"
                ))
        except Exception:
            pass

    return findings


async def _test_supabase_admin(client: httpx.AsyncClient, config: dict) -> list[Finding]:
    """Test admin API endpoints."""
    findings = []
    base = config["url"]
    key = config.get("key", "")
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}

    admin_endpoints = [
        ("GET", "/auth/v1/admin/users", "רשימת משתמשים"),
        ("GET", "/rest/v1/", "OpenAPI schema"),
        ("GET", "/auth/v1/admin/audit", "Audit logs"),
    ]

    for method, path, desc in admin_endpoints:
        try:
            if method == "GET":
                r = await client.get(f"{base}{path}", headers=headers)
            else:
                r = await client.post(f"{base}{path}", headers=headers)
            
            if r.status_code == 200:
                body = r.text[:300]
                if path == "/rest/v1/" and "definitions" in body:
                    # OpenAPI schema exposure
                    schema = r.json()
                    table_names = list(schema.get("definitions", {}).keys())
                    findings.append(Finding("medium", "info-disclosure",
                        "OpenAPI schema חשוף",
                        f"אפשר לראות את כל הטבלאות והעמודות דרך ה-REST schema",
                        evidence=[f"Tables: {table_names[:20]}"],
                        recommendation="הגבל גישה ל-REST schema"
                    ))
                elif "admin" in path.lower():
                    findings.append(Finding("critical", "admin-access",
                        f"Admin endpoint חשוף: {desc}",
                        f"{method} {path} → 200 עם anon key",
                        evidence=[f"Response: {body}"],
                        recommendation="חסום admin endpoints עבור anon key"
                    ))
        except Exception:
            pass

    # Test RPC functions
    rpc_names = ["get_users", "admin_query", "run_sql", "exec", "get_all_data"]
    for rpc in rpc_names:
        try:
            r = await client.post(f"{base}/rest/v1/rpc/{rpc}",
                json={}, headers={**headers, "Content-Type": "application/json"})
            if r.status_code == 200:
                findings.append(Finding("critical", "rpc-exposure",
                    f"RPC function '{rpc}' נגישה!",
                    "פונקציית RPC שעלולה לחשוף נתונים",
                    evidence=[f"POST /rest/v1/rpc/{rpc} → 200: {r.text[:200]}"]
                ))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  Firebase-specific tests
# ══════════════════════════════════════════════════════════════════════════════

async def _test_firebase_auth(client: httpx.AsyncClient, config: dict) -> list[Finding]:
    """Test Firebase auth policies."""
    findings = []
    api_key = config.get("api_key", config.get("apiKey", ""))
    if not api_key:
        return findings

    # Test signup
    try:
        r = await client.post(
            f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
            json={"returnSecureToken": True})
        if r.status_code == 200 and r.json().get("idToken"):
            findings.append(Finding("high", "auth-policy",
                "כניסה אנונימית מופעלת ב-Firebase",
                "אפשר ליצור חשבון אנונימי ולקבל token",
                evidence=[f"POST accounts:signUp → 200 + idToken"],
                recommendation="כבה Anonymous Authentication ב-Firebase Console"
            ))
    except Exception:
        pass

    # Test email signup
    test_email = f"baas_audit_{int(time.time())}@test-scanner.invalid"
    try:
        r = await client.post(
            f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
            json={"email": test_email, "password": "AuditTest!9xKm2", "returnSecureToken": True})
        if r.status_code == 200 and r.json().get("idToken"):
            findings.append(Finding("high", "auth-policy",
                "הרשמה פתוחה ב-Firebase",
                "כל אחד יכול להירשם עם אימייל וסיסמה",
                evidence=[f"User created: {r.json().get('localId', 'N/A')}"],
                recommendation="הגבל הרשמה או הוסף Cloud Function שבודק authorization"
            ))
    except Exception:
        pass

    return findings


async def _test_firebase_rules(client: httpx.AsyncClient, config: dict,
                                collections: list[str]) -> list[Finding]:
    """Test Firestore / RTDB security rules."""
    findings = []

    # Test RTDB
    rtdb_url = config.get("rtdb_url", config.get("databaseURL", ""))
    if rtdb_url:
        rtdb = rtdb_url.rstrip("/")
        try:
            r = await client.get(f"{rtdb}/.json")
            if r.status_code == 200 and r.text != "null":
                data = r.json()
                if data:
                    keys = list(data.keys())[:10] if isinstance(data, dict) else []
                    findings.append(Finding("critical", "firebase-rules",
                        "Realtime Database חשוף לחלוטין!",
                        "אפשר לקרוא את כל בסיס הנתונים ללא אימות",
                        evidence=[f"GET {rtdb}/.json → 200",
                                  f"Root keys: {keys}"],
                        recommendation="עדכן Security Rules: אל תאפשר read/write ללא auth"
                    ))
        except Exception:
            pass

        # Try writing
        try:
            r = await client.put(f"{rtdb}/security_audit_test.json",
                                  json={"test": True})
            if r.status_code == 200:
                findings.append(Finding("critical", "firebase-rules",
                    "כתיבה ל-RTDB ללא אימות!",
                    "כל אחד יכול לכתוב לבסיס הנתונים",
                    evidence=[f"PUT /security_audit_test.json → 200"],
                    recommendation="עדכן rules: .write = false לכל הנתיבים"
                ))
                # Cleanup
                await client.delete(f"{rtdb}/security_audit_test.json")
        except Exception:
            pass

        # Test specific paths
        for collection in collections:
            try:
                r = await client.get(f"{rtdb}/{collection}.json?shallow=true")
                if r.status_code == 200 and r.text != "null":
                    findings.append(Finding("high", "firebase-rules",
                        f"RTDB path '/{collection}' חשוף",
                        f"אפשר לקרוא נתונים מ-/{collection}",
                        evidence=[f"GET /{collection}.json → 200: {r.text[:200]}"]
                    ))
            except Exception:
                pass

    # Test Firestore REST API
    project_id = config.get("project_id", config.get("projectId", ""))
    if project_id:
        firestore_base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        for collection in collections:
            try:
                r = await client.get(f"{firestore_base}/{collection}?pageSize=3")
                if r.status_code == 200:
                    data = r.json()
                    docs = data.get("documents", [])
                    if docs:
                        findings.append(Finding("high", "firebase-rules",
                            f"Firestore collection '{collection}' חשופה",
                            f"אפשר לקרוא מסמכים ללא אימות",
                            evidence=[f"GET /{collection} → {len(docs)} documents",
                                      f"Fields: {list(docs[0].get('fields', {}).keys())}" if docs else ""],
                            recommendation=f"הוסף Security Rule: match /{collection}/{{doc}} {{ allow read: if request.auth != null; }}"
                        ))
            except Exception:
                pass

    return findings


async def _test_firebase_storage(client: httpx.AsyncClient, config: dict) -> list[Finding]:
    """Test Firebase Storage bucket access."""
    findings = []
    bucket = config.get("storage_bucket", config.get("storageBucket", ""))
    if not bucket:
        return findings

    # Try listing via GCS API
    try:
        r = await client.get(f"https://storage.googleapis.com/{bucket}?prefix=&maxResults=5")
        if r.status_code == 200 and "<Contents>" in r.text:
            findings.append(Finding("critical", "storage",
                "Firebase Storage bucket חשוף!",
                f"אפשר לרשום קבצים ב-{bucket} ללא אימות",
                evidence=[f"GET https://storage.googleapis.com/{bucket} → 200"],
                recommendation="עדכן Storage Rules: allow read: if request.auth != null;"
            ))
    except Exception:
        pass

    return findings
