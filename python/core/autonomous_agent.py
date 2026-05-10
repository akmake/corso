# python/core/autonomous_agent.py

import asyncio
import logging
from typing import Callable, Dict, Any, List, Optional

_fallback_log = logging.getLogger("AutonomousAgent")


class AutonomousPentestAgent:
    """
    רובוט סייבר אוטונומי לבדיקות חדירות.
    מקבל החלטות דינמיות בזמן אמת על בסיס מה שנאסף בשלב הריקון.
    """
    def __init__(self, target_url: str, aggressiveness: str = "normal",
                 log_fn: Optional[Callable[[str], None]] = None,
                 baas_url: str = "", baas_key: str = ""):
        self.target_url = target_url
        self.aggressiveness = aggressiveness
        self._log_fn = log_fn or (lambda msg: _fallback_log.info(msg))
        self._baas_url = baas_url.strip()
        self._baas_key = baas_key.strip()

        self.memory: Dict[str, Any] = {
            "technologies_found": set(),
            "endpoints": [],
            "api_keys": [],
            "auth_tokens": [],
            "findings": [],
            "auth_mechanism": None,
        }

    def _log(self, msg: str):
        self._log_fn(msg)

    # ──────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────

    async def execute_mission(self) -> Dict[str, Any]:
        self._log(f"🚀 מתחיל משימה אוטונומית — {self.target_url} (רמה: {self.aggressiveness})")

        # ── אם סופקו URL + key ידנית — מדלגים על שלב הזיהוי ──
        if self._baas_url and self._baas_key:
            self._log(f"⚡ מפתחות BaaS סופקו ידנית — מדלג על שלב Recon ותוקף ישירות!")
            self._log(f"🎯 יעד: {self._baas_url}")
            self.memory["technologies_found"].add("Supabase")
            self.memory["api_keys"].append(self._baas_key)
            self.memory["_prefetched_js"] = f'createClient("{self._baas_url}","{self._baas_key}")'
            await self._module_attack_baas()
            await self._phase_3_ai_analysis()
            self._log("✅ המשימה הושלמה.")
            return self._generate_report()

        await self._phase_1_recon()

        if self.aggressiveness == "recon":
            self._log("🔎 מצב Recon בלבד — עוצר ומפיק דוח.")
            return self._generate_report()

        attack_tasks = []

        has_baas = "Supabase" in self.memory["technologies_found"] or "Firebase" in self.memory["technologies_found"]
        if has_baas:
            self._log("🧠 החלטת סוכן: זוהה BaaS ישירות — מפעיל BaaS Scanner ממוקד.")
        else:
            self._log("🧠 החלטת סוכן: לא זוהה BaaS בטביעת אצבע — מריץ BaaS Scanner עמוק (ייתכן שמוסתר בבנדל).")
        attack_tasks.append(self._module_attack_baas())

        if self.memory["auth_tokens"] and self.aggressiveness == "aggressive":
            self._log("🧠 החלטת סוכן: זוהה auth token ורמה אגרסיבית — מפעיל BOLA Engine.")
            attack_tasks.append(self._module_attack_bola())

        self._log(f"⚡ מריץ {len(attack_tasks)} מודולי תקיפה...")
        await asyncio.gather(*attack_tasks, return_exceptions=True)

        # בדיקת RLS כמשתמש מאומת — תמיד כשיש Supabase
        if "Supabase" in self.memory["technologies_found"]:
            await self._test_rls_as_authenticated_user()

        await self._phase_3_ai_analysis()

        self._log("✅ המשימה הושלמה.")
        return self._generate_report()

    # ──────────────────────────────────────────────────────────────────────
    # Phase 1: Dynamic Recon (Playwright)
    # ──────────────────────────────────────────────────────────────────────

    async def _phase_1_recon(self):
        """
        כל ה-HTTP נעשה דרך Playwright (Chromium) — עוקף בעיות DNS/proxy של Python.
        Playwright מחזיר HTML + כל תוכן ה-JS שנטען בדפדפן.
        """
        self._log("👀 שלב 1: מפעיל Chromium לאיסוף HTML + JS...")
        import re

        scraped: dict = {}
        try:
            from core.scraper_playwright import PlaywrightExtractor
            scraper = PlaywrightExtractor(self.target_url)
            scraped = await scraper.extract_deep_data()
        except Exception as e:
            self._log(f"⚠️ Playwright נכשל: {type(e).__name__}: {e}")

        emails = scraped.get("emails_found", [])
        if emails:
            self._log(f"📧 מיילים: {', '.join(emails[:5])}")
        title = scraped.get("title", "")
        if title:
            self._log(f"🏷️ כותרת: {title}")

        # ── נבנה את ה-JS המשולב לסריקה ──
        combined = scraped.get("html_content", "") + "\n" + scraped.get("js_content", "")

        # ── בונוס קריטי: בקשות רשת שנלכדו (API keys ב-headers, Supabase URLs) ──
        intercepted = scraped.get("intercepted_requests", [])
        if intercepted:
            self._log(f"🌐 בקשות רשת שנלכדו: {len(intercepted)}")
            for req in intercepted:
                url = req.get("url", "")
                headers = req.get("headers", {})
                # הכנס את ה-URL לתוך הטקסט לסריקה (כדי ש-_detect_baas ימצא אותו)
                combined += f"\n{url}"
                # שלוף apikey מ-headers אם קיים
                apikey = headers.get("apikey", "")
                auth = headers.get("authorization", "")
                if apikey and len(apikey) > 20:
                    self.memory["api_keys"].append(apikey)
                    self._log(f"🔑 apikey נלכד מ-header: {apikey[:30]}...")
                if auth.startswith("Bearer ") and len(auth) > 30:
                    token = auth[7:]
                    self.memory["auth_tokens"].append(token)
                    self._log(f"🔑 Bearer token נלכד: {token[:30]}...")

        self.memory["_prefetched_js"] = combined  # נשמור לשימוש ב-BaaS scanner

        if not combined.strip():
            self._log("⚠️ לא התקבל תוכן מהדפדפן")
            return

        # טביעת אצבע טכנולוגיות
        tech_patterns = {
            "Supabase":  r"supabase\.co|supabase\.io|createClient\s*\(|SUPABASE_URL",
            "Firebase":  r"firebaseio\.com|firestore\.googleapis|initializeApp\s*\(",
            "GraphQL":   r'graphql|/__graphql',
            "Next.js":   r"__NEXT_DATA__|/_next/",
            "React":     r"react[-.]production|__reactFiber|ReactDOM",
            "Vue.js":    r"vue\.runtime|__vue__",
            "WordPress": r"wp-content|wp-includes",
            "Shopify":   r"cdn\.shopify\.com",
            "Wix":       r"wixstatic\.com|wixapps\.net",
        }
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, combined, re.IGNORECASE):
                self.memory["technologies_found"].add(tech)

        # חילוץ API keys ו-JWT מתוך ה-JS
        key_patterns = [
            (r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}', None),
            (r'(?:apikey|anon.?key|api_key|anonKey)["\s:=,]+["\']([A-Za-z0-9_\-\.]{30,})["\']', 1),
            (r'(?:SUPABASE|FIREBASE)[_A-Z]*["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']', 1),
        ]
        for pat, grp in key_patterns:
            for m in re.finditer(pat, combined, re.IGNORECASE):
                val = (m.group(grp) if grp and m.lastindex else m.group(0)) or ""
                if len(val) > 20:
                    (self.memory["auth_tokens"] if val.startswith("eyJ") else self.memory["api_keys"]).append(val)

        if self.memory["auth_tokens"]:
            self.memory["auth_mechanism"] = "JWT"

        maps = re.findall(r'["\']([^"\']+\.js\.map)["\']', combined)
        if maps:
            self._log(f"⚠️ Source Maps חשופים: {', '.join(maps[:3])}")

        techs = list(self.memory["technologies_found"]) or ["לא זוהו"]
        self._log(f"🔍 טכנולוגיות: {', '.join(techs)}")
        self._log(f"🔑 API keys: {len(self.memory['api_keys'])} | auth tokens: {len(self.memory['auth_tokens'])}")
        js_kb = len(combined) // 1024
        self._log(f"📦 JS שנלכד: {js_kb} KB")

    # ──────────────────────────────────────────────────────────────────────
    # Phase 2a: BaaS Attack
    # ──────────────────────────────────────────────────────────────────────

    async def _module_attack_baas(self):
        self._log("🔥 מפעיל BaaS Scanner (Supabase/Firebase)...")
        try:
            from core.baas_scanner import scan_baas

            async def _cb(msg):
                self._log(f"  [BaaS] {msg}")

            # מעבירים את ה-JS שנלכד על ידי Playwright — אין httpx לאתר היעד
            prefetched = self.memory.get("_prefetched_js", "")
            findings = await scan_baas(self.target_url, progress_cb=_cb, prefetched_js=prefetched)

            real = [f for f in findings if getattr(f, "severity", getattr(f, "severity", "info") if hasattr(f, "severity") else f.get("severity","info")) != "info"]
            self.memory["findings"].extend(findings)
            if real:
                self._log(f"🚨 BaaS Scanner מצא {len(real)} ממצאים אמיתיים!")
            else:
                self._log("✅ BaaS Scanner — לא נמצאו חולשות ברות-ניצול.")
        except Exception as e:
            self._log(f"⚠️ שגיאה ב-BaaS Scanner: {type(e).__name__}: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Phase 2b: BOLA / IDOR Attack (real engine)
    # ──────────────────────────────────────────────────────────────────────

    async def _module_attack_bola(self):
        self._log("🎭 מפעיל BOLA Engine — יוצר משתמשי קש...")
        try:
            from core.auth_bola_engine import BolaIdorEngine

            anon_key = (self.memory["api_keys"] or self.memory["auth_tokens"] or [""])[0]
            if not anon_key:
                self._log("⚠️ לא נמצא anon key — לא ניתן להריץ BOLA.")
                return

            # חילוץ טבלות מה-endpoints שהתגלו
            supabase_tables = self._extract_supabase_tables()
            if not supabase_tables:
                self._log("⚠️ לא זוהו טבלות Supabase — לא ניתן להריץ BOLA.")
                return

            self._log(f"   טבלאות לבדיקה: {', '.join(supabase_tables)}")
            engine = BolaIdorEngine(self.target_url, anon_key, endpoints=supabase_tables)
            findings = await engine.run_attack()

            if findings:
                self.memory["findings"].extend(findings)
                self._log(f"⚠️ BOLA Engine מצא {len(findings)} חולשות!")
            else:
                self._log("✅ BOLA Engine — לא נמצאו חולשות בידוד משתמשים.")
        except Exception as e:
            self._log(f"⚠️ שגיאה ב-BOLA Engine: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Phase 3: AI Analysis
    # ──────────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────────
    # Phase 2c: Authenticated RLS bypass test
    # ──────────────────────────────────────────────────────────────────────

    async def _test_rls_as_authenticated_user(self):
        """
        נרשם כמשתמש אמיתי ובודק מה הוא יכול לראות.
        RLS אמור להגביל כל משתמש לנתונים שלו בלבד.
        """
        self._log("🔐 בדיקת RLS — נרשם כמשתמש ובודק גישה לנתונים...")
        import httpx, random, string, re

        js = self.memory.get("_prefetched_js", "")
        # חלץ את ה-Supabase URL מה-JS
        m = re.search(r'https://([a-z0-9]+)\.supabase\.co', js)
        if not m:
            self._log("⚠️ לא נמצא Supabase URL — מדלג.")
            return
        supabase_url = f"https://{m.group(1)}.supabase.co"
        anon_key = (self.memory["api_keys"] or self.memory["auth_tokens"] or [""])[0]
        if not anon_key:
            self._log("⚠️ לא נמצא anon key — מדלג.")
            return

        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"pentest_{rand}@mailinator.com"
        password = "PentestPass123!"
        headers = {"apikey": anon_key, "Content-Type": "application/json"}

        async with httpx.AsyncClient(verify=False, timeout=20) as client:
            # ── הרשמה ──
            res = await client.post(f"{supabase_url}/auth/v1/signup",
                                    headers=headers,
                                    json={"email": email, "password": password})
            if res.status_code not in (200, 201):
                self._log(f"⚠️ הרשמה נכשלה ({res.status_code}) — אולי נדרש אישור אימייל.")
                # בדוק גישה אנונימית ישירה
                await self._probe_tables_anon(client, supabase_url, anon_key)
                return

            token = (res.json().get("access_token") or
                     (res.json().get("session") or {}).get("access_token", ""))
            if not token:
                self._log("⚠️ נרשמנו אבל לא קיבלנו token — בדיקת גישה אנונימית.")
                await self._probe_tables_anon(client, supabase_url, anon_key)
                return

            self._log(f"✅ משתמש נוצר: {email}")
            auth_headers = {**headers, "Authorization": f"Bearer {token}"}

            # ── שלוף כל טבלה ──
            tables = self._extract_supabase_tables()
            self._log(f"🔍 בודק {len(tables)} טבלאות כמשתמש מאומת...")
            exposed = []
            for table in tables:
                r = await client.get(f"{supabase_url}/rest/v1/{table}?select=*&limit=5",
                                     headers=auth_headers)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and len(data) > 0:
                        self._log(f"🚨 טבלה '{table}': {len(data)} שורות נחשפות למשתמש רגיל!")
                        exposed.append({"table": table, "rows": len(data), "sample": data[0]})
                        self.memory["findings"].append({
                            "severity": "critical",
                            "category": "RLS Bypass",
                            "title": f"RLS Bypass: טבלה '{table}' חשופה למשתמש מאומת",
                            "description": f"משתמש שנרשם ({email}) יכול לקרוא {len(data)} רשומות מטבלת '{table}' ללא הגבלה.",
                            "evidence": [str(data[0])]
                        })
                    elif r.status_code == 200 and data == []:
                        self._log(f"  ✅ '{table}': מוגן — 0 שורות")
                else:
                    self._log(f"  🔒 '{table}': חסום ({r.status_code})")

            if exposed:
                self._log(f"🚨 נמצאו {len(exposed)} טבלאות חשופות!")
            else:
                self._log("✅ RLS תקין — אף טבלה לא חשפה נתונים למשתמש חדש.")

    async def _probe_tables_anon(self, client, supabase_url: str, anon_key: str):
        """בדיקת גישה אנונימית (ללא login) לטבלאות."""
        self._log("🔍 בודק גישה אנונימית לטבלאות (ללא auth)...")
        headers = {"apikey": anon_key, "Content-Type": "application/json"}
        tables = self._extract_supabase_tables()
        for table in tables:
            r = await client.get(f"{supabase_url}/rest/v1/{table}?select=*&limit=5",
                                 headers=headers)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    self._log(f"🚨 אנונימי יכול לקרוא '{table}': {len(data)} שורות!")
                    self.memory["findings"].append({
                        "severity": "critical",
                        "category": "RLS Bypass (Anon)",
                        "title": f"גישה אנונימית לטבלה '{table}'",
                        "description": f"ללא שום אימות ניתן לקרוא נתונים מ-'{table}'.",
                        "evidence": [str(data[0])]
                    })
                else:
                    self._log(f"  ✅ '{table}': מוגן אנונימי")
            else:
                self._log(f"  🔒 '{table}': חסום ({r.status_code})")

    async def _phase_3_ai_analysis(self):
        self._log("🤖 שלב 3: מפעיל מנתח AI על ממצאים חשודים...")
        try:
            from core.ai_analyzer import VulnerabilityAIAnalyst
            analyst = VulnerabilityAIAnalyst()
            if not analyst.api_key:
                self._log("⚠️ OPENAI_API_KEY לא הוגדר — מדלג על ניתוח AI.")
                return

            # מנתח עד 3 ממצאים קריטיים כדי לא לבזבז tokens
            candidates = [
                f for f in self.memory["findings"]
                if (getattr(f, "severity", None) or f.get("severity", "")) in ("critical", "high")
            ][:3]

            if not candidates:
                self._log("✅ אין ממצאים קריטיים לניתוח AI.")
                return

            for finding in candidates:
                desc = getattr(finding, "description", None) or finding.get("description", str(finding))
                title = getattr(finding, "title", None) or finding.get("title", "Unknown")
                self._log(f"🧠 AI מנתח: {title}")
                analysis = await analyst.analyze_server_anomaly(
                    status_code=200,
                    response_body=desc,
                    target_endpoint=self.target_url,
                )
                if analysis.get("is_vulnerable"):
                    self._log(f"💡 AI: {analysis.get('vulnerability_type')} (ביטחון: {analysis.get('confidence_score')}%)")
                    if analysis.get("suggested_next_payloads"):
                        self._log(f"   פיילודים מוצעים: {analysis['suggested_next_payloads'][:2]}")
        except Exception as e:
            self._log(f"⚠️ שגיאה בניתוח AI: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _extract_supabase_tables(self) -> List[str]:
        import re
        tables = set()
        # מה-endpoints (בקשות רשת)
        for ep in self.memory["endpoints"]:
            m = re.search(r'/rest/v1/([a-zA-Z_][a-zA-Z0-9_]*)', ep)
            if m:
                tables.add(m.group(1))
        # מתוך ה-JS עצמו — .from("tablename")
        js = self.memory.get("_prefetched_js", "")
        if js:
            for m in re.finditer(r'\.from\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', js):
                tables.add(m.group(1))
            for m in re.finditer(r'/rest/v1/([a-zA-Z_][a-zA-Z0-9_]*)', js):
                tables.add(m.group(1))
        return list(tables)

    def _generate_report(self) -> Dict[str, Any]:
        def _to_dict(f):
            return f.__dict__ if hasattr(f, "__dict__") else f

        findings_list = [_to_dict(f) for f in self.memory["findings"]]
        critical_count = sum(
            1 for f in findings_list if f.get("severity") == "critical"
        )
        return {
            "target": self.target_url,
            "status": "completed",
            "summary": {
                "technologies": list(self.memory["technologies_found"]),
                "endpoints_discovered": len(self.memory["endpoints"]),
                "api_keys_found": len(self.memory["api_keys"]),
                "total_findings": len(findings_list),
                "critical_vulnerabilities": critical_count,
            },
            "findings": findings_list,
        }


# ──────────────────────────────────────────────────────────────────────
# Standalone test
# ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    def _print_log(msg):
        print(f"  >> {msg}")

    agent = AutonomousPentestAgent(
        target_url="https://example-supabase-ai-app.com",
        aggressiveness="aggressive",
        log_fn=_print_log,
    )
    report = asyncio.run(agent.execute_mission())
    print("\n" + "=" * 50)
    print(json.dumps(report, indent=2, ensure_ascii=False))
