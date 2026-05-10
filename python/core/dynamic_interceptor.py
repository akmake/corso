# python/core/dynamic_interceptor.py

import asyncio
import logging
import re
from typing import Dict, Any
from playwright.async_api import async_playwright

log = logging.getLogger("DynamicInterceptor")
log.setLevel(logging.INFO)

class DynamicReconEngine:
    """
    מנוע איסוף מודיעין דינמי מבוסס דפדפן (Playwright).
    מחקה התנהגות משתמש ולוכד מפתחות API, טוקנים וטכנולוגיות תוך כדי ריצה.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.extracted_data = {
            "technologies_found": set(),
            "endpoints": set(),
            "api_keys": set(),
            "auth_tokens": set(),
            "suspicious_files": set()
        }

    async def run_recon(self) -> Dict[str, Any]:
        """מפעיל את סשן הסריקה ומחזיר את המודיעין שנאסף"""
        log.info(f"🕵️‍♂️ מתחיל מודיעין דינמי על: {self.target_url}")
        
        async with async_playwright() as p:
            # מפעיל דפדפן מוסווה (Headless)
            browser = await p.chromium.launch(headless=True, args=['--disable-web-security'])
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            # רושם מאזין לכל בקשת רשת (כאן קורה הקסם)
            page.on("request", self._intercept_request)
            page.on("response", self._intercept_response)

            try:
                # גולש לאתר ומחכה שכל קריאות ה-AJAX/API יסתיימו
                log.info("🌐 טוען את האתר ומחכה לתעבורת רשת...")
                await page.goto(self.target_url, wait_until="networkidle", timeout=15000)
                
                # גלילה אוטומטית כדי להפעיל Lazy Loading
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2) # נותן לטריגרים לעבוד
                
            except Exception as e:
                log.warning(f"שגיאה במהלך טעינת הדף (אולי Timeout): {e}")
            finally:
                await browser.close()

        log.info("✅ איסוף המודיעין הדינמי הושלם.")
        
        # ממיר Sets ל-Lists כדי שיהיה קל לייצא ל-JSON ב-Orchestrator
        return {
            "technologies_found": list(self.extracted_data["technologies_found"]),
            "endpoints": list(self.extracted_data["endpoints"]),
            "api_keys": list(self.extracted_data["api_keys"]),
            "auth_tokens": list(self.extracted_data["auth_tokens"]),
            "suspicious_files": list(self.extracted_data["suspicious_files"])
        }

    async def _intercept_request(self, request):
        """פונקציה זו רצה על *כל* בקשת רשת שהאתר מוציא"""
        url = request.url
        headers = request.headers

        # 1. איסוף Endpoints (מסננים תמונות/CSS כדי לא להציף)
        if not re.search(r'\.(png|jpg|jpeg|gif|css|svg|woff2)$', url, re.IGNORECASE):
            self.extracted_data["endpoints"].add(url)

        # 2. זיהוי טכנולוגיות על בסיס יעדי ה-API
        if "supabase.co" in url:
            self.extracted_data["technologies_found"].add("Supabase")
        elif "firebaseio.com" in url or "firestore.googleapis" in url:
            self.extracted_data["technologies_found"].add("Firebase")
        elif "graphql" in url.lower():
            self.extracted_data["technologies_found"].add("GraphQL")

        # 3. שאיבת מפתחות מה-Headers (החלק הקריטי!)
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower == "authorization":
                # מחפש Bearer Tokens
                if value.startswith("Bearer "):
                    self.extracted_data["auth_tokens"].add(value.split(" ")[1])
            elif key_lower in ["apikey", "x-api-key", "api-key"]:
                self.extracted_data["api_keys"].add(value)

    async def _intercept_response(self, response):
        """מאזין לתשובות מהשרת כדי לתפוס Source Maps וקבצים רגישים"""
        url = response.url
        
        # חיפוש קבצי מפות מקור שמפתחים שוכחים לכבות (Source Maps)
        if url.endswith(".js.map") or url.endswith(".ts.map"):
            self.extracted_data["suspicious_files"].add(url)
            self.extracted_data["technologies_found"].add("Leaked Source Maps")

# ==========================================
# הרצה לבדיקה עצמאית של המודול
# ==========================================
if __name__ == "__main__":
    import sys
    
    # ודא שהותקן: pip install playwright && playwright install
    test_url = "https://example.com" if len(sys.argv) < 2 else sys.argv[1]
    
    recon = DynamicReconEngine(test_url)
    results = asyncio.run(recon.run_recon())
    
    print("\n--- תוצאות מודיעין דינמי ---")
    import json
    print(json.dumps(results, indent=2, ensure_ascii=False))