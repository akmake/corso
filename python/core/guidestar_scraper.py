"""
Guidestar Scraper — חיפוש עמותות לפי שם אדם
==============================================
גישה:
  1. Playwright פותח דף חיפוש → מחלץ מספרי עמותות מה-HTML
  2. לכל עמותה — נכנס לדף + לוחץ על "בעלי תפקידים" → מיירט response
  3. מחזיר רק עמותות שהשם מופיע ברשימה
"""

import asyncio
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright
try:
    from playwright_stealth import stealth_sync
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False

_executor = ThreadPoolExecutor(max_workers=2)

GUIDESTAR_URL = "https://www.guidestar.org.il"

# כפתורים אפשריים לטאב נושאי משרה
OFFICERS_TAB_TEXTS = ["בעלי תפקידים", "נושאי משרה", "חברי הנהלה", "people", "People"]


class GuidestarScraper:
    def __init__(self, name: str):
        self.name = name.strip()

    def _run_sync(self) -> dict:
        results = []
        errors  = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                locale="he-IL",
                viewport={"width": 1280, "height": 900},
            )
            page = context.new_page()
            if _HAS_STEALTH:
                stealth_sync(page)

            try:
                # ── שלב 1: חיפוש ────────────────────────────────────────
                search_url = f"{GUIDESTAR_URL}/search?q={urllib.parse.quote(self.name)}"
                page.goto(search_url, wait_until="domcontentloaded", timeout=40000)

                org_numbers = []
                for _ in range(3):
                    page.wait_for_timeout(3000)
                    found = re.findall(r'/organization/(\d{6,10})', page.content())
                    org_numbers = list(dict.fromkeys(found))[:20]
                    if org_numbers:
                        break
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

                print(f"[GUIDESTAR] org_numbers: {org_numbers}")
                if not org_numbers:
                    errors.append("לא נמצאו עמותות בחיפוש")

                # ── שלב 2: לכל עמותה — לחיצה על הטאב + ירוט response ──
                for org_num in org_numbers:
                    try:
                        founders = self._get_founders_via_click(context, org_num)
                        print(f"[GUIDESTAR] org={org_num} founders={founders}")

                        name_lower = self.name.lower()
                        matched = [f for f in founders if name_lower in f.lower()]

                        if matched:
                            results.append({
                                "org_number":   org_num,
                                "org_name":     self._extract_org_name(founders, org_num),
                                "url":          f"{GUIDESTAR_URL}/organization/{org_num}",
                                "people_url":   f"{GUIDESTAR_URL}/organization/{org_num}/people",
                                "matched_as":   matched,
                                "all_officers": founders,
                            })

                    except Exception as e:
                        errors.append(f"שגיאה בעמותה {org_num}: {str(e)}")

            except Exception as e:
                errors.append(f"חיפוש ראשי נכשל: {str(e)}")
            finally:
                browser.close()

        return {
            "name":    self.name,
            "source":  "guidestar.org.il",
            "total":   len(results),
            "results": results,
            "errors":  errors,
        }

    def _get_founders_via_click(self, context, org_num: str) -> list:
        """
        נכנס לדף עמותה, לוחץ על טאב "בעלי תפקידים",
        מצפה ל-response של apexremote עם expect_response.
        """
        org_page = context.new_page()
        if _HAS_STEALTH:
            stealth_sync(org_page)

        try:
            org_url = f"{GUIDESTAR_URL}/organization/{org_num}/people"
            org_page.goto(org_url, wait_until="domcontentloaded", timeout=25000)
            org_page.wait_for_timeout(2000)

            # מחפש כפתור הטאב
            btn = None
            for tab_text in OFFICERS_TAB_TEXTS:
                try:
                    candidate = org_page.get_by_text(tab_text, exact=False).first
                    if candidate.is_visible():
                        btn = candidate
                        print(f"[GUIDESTAR] found tab '{tab_text}' on org {org_num}")
                        break
                except Exception:
                    pass

            if btn is None:
                print(f"[GUIDESTAR] no officers tab found for {org_num}")
                return self._fetch_founders_direct(org_page, org_num)

            # לוחץ + מצפה ל-response
            try:
                with org_page.expect_response(
                    lambda r: "apexremote" in r.url,
                    timeout=8000
                ) as resp_info:
                    btn.click()

                resp = resp_info.value
                print(f"[GUIDESTAR] apexremote response status={resp.status} for {org_num}")
                body = resp.json()
                print(f"[GUIDESTAR] apexremote body={str(body)[:300]}")
                for item in (body if isinstance(body, list) else []):
                    if item.get("method") == "getMalkarFounders":
                        r = item.get("result")
                        if isinstance(r, list):
                            return r
                # לא נמצא getMalkarFounders — נסה direct
                return self._fetch_founders_direct(org_page, org_num)

            except Exception as e:
                print(f"[GUIDESTAR] expect_response error for {org_num}: {e}")
                return self._fetch_founders_direct(org_page, org_num)

        finally:
            org_page.close()

    def _fetch_founders_direct(self, page, org_number: str) -> list:
        """
        ניסיון אחרון: fetch ישיר מתוך הדפדפן עם ctx מהדף.
        """
        try:
            result = page.evaluate(
                """
                async (orgNum) => {
                    // נסה לחלץ ctx מ-window
                    let ctx = {};
                    try {
                        const vfMgr = window.Visualforce?.remoting?.Manager;
                        if (vfMgr) {
                            ctx = { vid: vfMgr.vf?.vid, csrf: vfMgr.vf?.csrf,
                                    ns: vfMgr.vf?.ns || '', ver: vfMgr.vf?.ver || 54 };
                        }
                    } catch(e) {}

                    const payload = [{ action:"GSTAR_Ctrl", method:"getMalkarFounders",
                                       data:[orgNum], type:"rpc", tid:1, ctx }];
                    const resp = await fetch("/apexremote", {
                        method: "POST",
                        headers: { "Content-Type":"application/json",
                                   "X-Requested-With":"XMLHttpRequest",
                                   "X-User-Agent":"Visualforce-Remoting" },
                        body: JSON.stringify(payload)
                    });
                    const data = await resp.json();
                    const item = data[0] || {};
                    return { result: item.result, status: item.statusCode,
                             ctx_used: ctx };
                }
                """,
                org_number,
            )
            print(f"[GUIDESTAR] direct fetch: {result}")
            if isinstance(result, dict) and isinstance(result.get("result"), list):
                return result["result"]
        except Exception as e:
            print(f"[GUIDESTAR] direct fetch error: {e}")
        return []

    def _extract_org_name(self, founders: list, org_num: str) -> str:
        return f"עמותה {org_num}"

    async def search(self) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, self._run_sync)
