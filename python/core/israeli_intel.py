"""
Israeli Intelligence Module — מודיעין ישראלי
=============================================
גישה: site: dorking על אתרים ממשלתיים ורשמיים.
כך מוצאים אדם כנושא משרה / חבר הנהלה / בעל עניין —
ולא רק כאשר שמו מופיע בשם הארגון.

מקורות:
  guidestar.org.il      — עמותות + נושאי משרה
  ica.justice.gov.il    — רשם החברות
  knesset.gov.il        — כנסת
  nevo.co.il            — פסיקות בית משפט
  data.gov.il           — נתוני ממשלה פתוחים
  ynet / haaretz / calcalist — עיתונות כלכלית

בנוסף: data.gov.il datastore עם חיפוש מדויק.
"""

import asyncio
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from bs4 import BeautifulSoup
import httpx
try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

_executor = ThreadPoolExecutor(max_workers=6)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "he,en-US;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ── אתרים ישראליים לחיפוש ממוקד ───────────────────────────────────────────────
ISRAELI_SITE_SEARCHES = [
    {
        "key":   "nonprofits",
        "label": "עמותות — גרדסטאר",
        "site":  "guidestar.org.il",
        "note":  "כולל נושאי משרה, חברי הנהלה, מייסדים",
    },
    {
        "key":   "companies",
        "label": "רשם החברות",
        "site":  "ica.justice.gov.il",
        "note":  "חברות, מנהלים, מורשי חתימה",
    },
    {
        "key":   "knesset",
        "label": "כנסת",
        "site":  "knesset.gov.il",
        "note":  "חברי כנסת, עדויות, ועדות",
    },
    {
        "key":   "court_nevo",
        "label": "פסיקות — נבו",
        "site":  "nevo.co.il",
        "note":  "פסיקות בית משפט",
    },
    {
        "key":   "court_judicial",
        "label": "בתי משפט — judicial.court.gov.il",
        "site":  "judicial.court.gov.il",
        "note":  "פסיקות ממערכת בתי המשפט הרשמית",
    },
    {
        "key":   "gov_data",
        "label": "data.gov.il",
        "site":  "data.gov.il",
        "note":  "נתוני ממשלה פתוחים",
    },
    {
        "key":   "news_biz",
        "label": "עיתונות כלכלית",
        "site":  "calcalist.co.il OR site:globes.co.il OR site:themarker.com",
        "note":  "כלכליסט, גלובס, TheMarker",
    },
    {
        "key":   "news_gen",
        "label": "חדשות כלליות",
        "site":  "ynet.co.il OR site:haaretz.co.il OR site:maariv.co.il",
        "note":  "ynet, הארץ, מעריב",
    },
    {
        "key":   "linkedin_il",
        "label": "LinkedIn ישראל",
        "site":  "linkedin.com/in",
        "note":  "פרופיל מקצועי, תפקיד, חברה",
    },
    {
        "key":   "bar_association",
        "label": "לשכת עורכי הדין",
        "site":  "israelibar.org.il",
        "note":  "חיפוש עורכי דין מורשים",
    },
    {
        "key":   "accountants",
        "label": "לשכת רואי חשבון",
        "site":  "icpas.org.il",
        "note":  "רואי חשבון מורשים",
    },
    {
        "key":   "tenders",
        "label": "מכרזים ממשלתיים",
        "site":  "mr.gov.il OR site:pras.gov.il",
        "note":  "השתתפות במכרזים ממשלתיים",
    },
]

# resource IDs ב-data.gov.il לחיפוש ממשלתי ישיר
DATAGOV_RESOURCES = {
    "associations": "be5b7935-3922-423d-b7b4-51df139a4f15",
    "companies":    "f004176c-b85f-4542-8901-7b3176f9a054",
    "tenders":      "8e23ba6e-2a9f-4073-8a44-0be67d02038c",
    # רשימת מורשי חתימה ברשם החברות
    "company_officers": "c3e7db33-c4b9-49cc-b1b5-73b2c9f0c5c8",
    # זכיינים ובעלי עסקים
    "business_licenses": "6f968f3b-4e90-4fae-ba67-0e1bba82aecd",
}


class IsraeliIntelligence:
    def __init__(self, query: str):
        self.query = query.strip()

    async def full_search(self) -> dict:
        from core.israeli_scrapers import IsraeliDirectScraper

        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=15,
            verify=False,
        ) as client:
            site_tasks      = [self._site_search(client, s) for s in ISRAELI_SITE_SEARCHES]
            profession_task = self._professional_registry_search()
            direct_task     = IsraeliDirectScraper(self.query).search_all()

            all_results = await asyncio.gather(
                *site_tasks,
                profession_task,
                direct_task,
                return_exceptions=True,
            )

        # site dorking results
        site_results: dict[str, Any] = {}
        for i, s in enumerate(ISRAELI_SITE_SEARCHES):
            r = all_results[i]
            site_results[s["key"]] = (
                r if not isinstance(r, Exception)
                else {"results": [], "error": str(r)}
            )

        n = len(ISRAELI_SITE_SEARCHES)
        profession_hits = all_results[n] if not isinstance(all_results[n], Exception) else []
        direct          = all_results[n + 1] if not isinstance(all_results[n + 1], Exception) else {}

        # pull structured data from direct scraper
        datagov_direct  = direct.get("datagov", {})
        guidestar_data  = direct.get("guidestar", {"organizations": [], "officers": []})
        b144_data       = direct.get("b144", {"results": [], "total": 0})
        courts_data     = direct.get("courts", {"results": [], "total": 0})
        opencorp_data   = direct.get("opencorporates", {"companies": [], "total": 0})

        # backward-compat guidestar list (old UI expects list)
        guidestar_orgs = guidestar_data.get("organizations", [])

        # count totals
        direct_count = (
            sum(v.get("total", 0) for v in datagov_direct.values())
            + len(guidestar_orgs)
            + len(guidestar_data.get("officers", []))
            + b144_data.get("total", 0)
            + courts_data.get("total", 0)
            + opencorp_data.get("total", 0)
        )
        site_count = sum(len(v.get("results", [])) for v in site_results.values())

        return {
            "query":       self.query,
            "total_found": site_count + direct_count + len(profession_hits),

            # DDG site-dorking results (existing)
            "site_results": site_results,
            "professions":  profession_hits,

            # backward compat (old UI)
            "guidestar": guidestar_orgs,
            "court":     courts_data.get("results", []),
            "datagov": {
                "associations": datagov_direct.get("nonprofits", {"records": [], "total": 0}),
                "companies":    datagov_direct.get("companies",  {"records": [], "total": 0}),
                "tenders":      datagov_direct.get("tenders",    {"records": [], "total": 0}),
            },

            # NEW structured data from direct scrapers
            "direct": {
                "datagov":        datagov_direct,
                "guidestar_orgs": guidestar_orgs,
                "guidestar_officers": guidestar_data.get("officers", []),
                "b144":           b144_data,
                "courts":         courts_data,
                "opencorporates": opencorp_data,
            },
        }

    # ── site: dorking ─────────────────────────────────────────────────────────
    def _ddg_search_sync(self, query: str) -> list[dict]:
        try:
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=10))
        except Exception:
            return []

    async def _site_search(self, client: httpx.AsyncClient, site_def: dict) -> dict:
        query = f'"{self.query}" site:{site_def["site"]}'
        loop  = asyncio.get_event_loop()
        raw   = await loop.run_in_executor(_executor, self._ddg_search_sync, query)
        results = [
            {"url": r.get("href"), "title": r.get("title"), "snippet": r.get("body")}
            for r in raw if r.get("href")
        ]
        return {
            "label":   site_def["label"],
            "note":    site_def["note"],
            "results": results[:8],
            "count":   len(results[:8]),
        }

    # ── Guidestar API ישיר ────────────────────────────────────────────────────
    async def _guidestar_search(self, client: httpx.AsyncClient) -> list[dict]:
        try:
            r = await client.get(
                "https://www.guidestar.org.il/api/search",
                params={"searchTerm": self.query, "pageSize": 20},
                headers={**HEADERS, "Referer": "https://www.guidestar.org.il/"},
                timeout=12,
            )
            if r.status_code == 200:
                data = r.json()
                orgs = data.get("organizations") or data.get("results") or []
                return [
                    {
                        "name":   o.get("name") or o.get("orgName"),
                        "number": o.get("orgNumber") or o.get("id"),
                        "type":   o.get("orgType", "עמותה"),
                        "status": o.get("statusDescription") or o.get("status"),
                        "url":    f"https://www.guidestar.org.il/organization/{o.get('orgNumber') or o.get('id')}",
                    }
                    for o in orgs if o
                ]
        except Exception:
            pass
        return []

    # ── data.gov.il API ───────────────────────────────────────────────────────
    async def _datagov(self, client: httpx.AsyncClient, resource_key: str) -> dict:
        rid = DATAGOV_RESOURCES[resource_key]
        try:
            r = await client.get(
                "https://data.gov.il/api/3/action/datastore_search",
                params={"resource_id": rid, "q": self.query, "limit": 50},
                timeout=15,
            )
            data = r.json()
            if data.get("success"):
                return data["result"]
            return {"records": [], "total": 0}
        except Exception as e:
            return {"records": [], "total": 0, "error": str(e)}

    def _filter_datagov(self, result: dict, query: str) -> list[dict]:
        """
        מסנן תוצאות data.gov.il כך שיוצגו רק רשומות
        שהשם המלא מופיע בהן (לא רק חלק מהמילים).
        """
        records = result.get("records", [])
        query_lower = query.lower()
        filtered = []
        for rec in records:
            # בנה טקסט אחד מכל הערכים ברשומה
            text = " ".join(str(v) for v in rec.values()).lower()
            if query_lower in text:
                clean = {k: v for k, v in rec.items() if k not in ("_id", "_full_text")}
                filtered.append(clean)
        return filtered

    # ── Court Records ─────────────────────────────────────────────────────────
    async def _court_search(self, client: httpx.AsyncClient) -> list[dict]:
        """
        חיפוש פסיקות בית משפט ב-judicial.court.gov.il.
        האתר מחייב JS אך תוצאות DDG מכילות snippets שימושיים.
        """
        results = []

        # DDG search on the official court site
        loop = asyncio.get_event_loop()

        def _run_ddg():
            try:
                with DDGS() as ddgs:
                    q = f'"{self.query}" site:judicial.court.gov.il'
                    return list(ddgs.text(q, max_results=8))
            except Exception:
                return []

        raw = await loop.run_in_executor(_executor, _run_ddg)
        for r in raw:
            if r.get("href"):
                results.append({
                    "source": "judicial.court.gov.il",
                    "url":    r["href"],
                    "title":  r.get("title", ""),
                    "snippet": r.get("body", ""),
                })

        # Also try the court system's open data API
        try:
            r = await client.get(
                "https://judicial.court.gov.il/api/search",
                params={"query": self.query, "limit": 10},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("results", data.get("items", []))[:10]:
                    results.append({
                        "source":  "judicial API",
                        "case_id": item.get("caseId") or item.get("id"),
                        "title":   item.get("title") or item.get("caseTitle"),
                        "date":    item.get("date") or item.get("decisionDate"),
                        "court":   item.get("courtName"),
                        "url":     item.get("url") or item.get("link"),
                    })
        except Exception:
            pass

        return results

    # ── Professional Registries ────────────────────────────────────────────────
    async def _professional_registry_search(self) -> list[dict]:
        """
        חיפוש ברשומות מקצועיות: לשכת עורכי דין, רואי חשבון, רופאים, מהנדסים.
        """
        loop = asyncio.get_event_loop()
        hits = []

        profession_queries = [
            (f'"{self.query}" site:israelibar.org.il',          "לשכת עורכי הדין"),
            (f'"{self.query}" site:icpas.org.il',               "לשכת רואי חשבון"),
            (f'"{self.query}" site:ima.org.il',                 "ההסתדרות הרפואית"),
            (f'"{self.query}" site:iec.org.il',                 "מהנדסים ואדריכלים"),
            (f'"{self.query}" site:molsa.gov.il',               "משרד הרווחה"),
            (f'"{self.query}" רישיון OR "נושא משרה" OR מנהל site:gov.il', "ממשלה — רישיונות"),
        ]

        async def _one_search(q: str, label: str) -> list[dict]:
            def _run():
                try:
                    with DDGS() as ddgs:
                        return list(ddgs.text(q, max_results=5))
                except Exception:
                    return []
            raw = await loop.run_in_executor(_executor, _run)
            return [
                {
                    "profession_source": label,
                    "url":     r.get("href"),
                    "title":   r.get("title", ""),
                    "snippet": r.get("body", ""),
                }
                for r in raw if r.get("href")
            ]

        tasks = [_one_search(q, label) for q, label in profession_queries]
        all_batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in all_batches:
            if isinstance(batch, list):
                hits.extend(batch)

        return hits
