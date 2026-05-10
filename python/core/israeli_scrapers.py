"""
Israeli Direct Scrapers — גישה ישירה למאגרי מידע ישראליים
==========================================================
מחליף DDG dorking בגישה ישירה ל:
  data.gov.il          CKAN API  (חברות, עמותות, מכרזים, נושאי משרה, מימון בחירות)
  guidestar.org.il     API       (עמותות + נושאי משרה)
  b144.co.il           scrape    (טלפון, כתובת, עסקים)
  psakdin.co.il        scrape    (פסיקות בית משפט)
  takdin.co.il         scrape    (פסיקות + תיקים)
  opencorporates.com   API       (חברות ישראליות — נתוני רישום בינלאומי)
"""

import asyncio
import re
import httpx
from bs4 import BeautifulSoup
from typing import Callable

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "he,en-US;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
}

DATAGOV = "https://data.gov.il/api/3/action"

# ── מאגרי data.gov.il ─────────────────────────────────────────────────────────
# resource_id → resource CKAN של data.gov.il
DATAGOV_RESOURCES = {
    "nonprofits": {
        "id":    "be5b7935-3922-423d-b7b4-51df139a4f15",
        "label": "עמותות רשומות",
    },
    "companies": {
        "id":    "f004176c-b85f-4542-8901-7b3176f9a054",
        "label": "רשם החברות (ICA)",
    },
    "tenders": {
        "id":    "8e23ba6e-2a9f-4073-8a44-0be67d02038c",
        "label": "מכרזים ממשלתיים",
    },
    "company_officers": {
        "id":    "c3e7db33-c4b9-49cc-b1b5-73b2c9f0c5c8",
        "label": "נושאי משרה בחברות",
    },
    "election_funding": {
        "id":    "d6592b63-44bc-4ac7-ada4-f26ae5d89e4a",
        "label": "מימון בחירות ומפלגות",
    },
    "licensed_contractors": {
        "id":    "9cbc9e74-f35c-468e-9e05-21f1dd98fe90",
        "label": "קבלנים רשומים",
    },
    "gov_employees": {
        "id":    "ae2c8776-6b9a-4ae4-bebe-1a97e4c75f38",
        "label": "עובדי ממשלה בכירים",
    },
}


class IsraeliDirectScraper:
    """
    Orchestrates direct scraping of all major Israeli data sources.
    Use search_all() for a single parallel call.
    """

    def __init__(self, query: str, log: Callable = print):
        self.query = query.strip()
        self.log   = log

    async def search_all(self) -> dict:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=25,
            verify=False,
        ) as client:
            datagov_task         = self._search_datagov(client)
            guidestar_task       = self._search_guidestar(client)
            b144_task            = self._search_b144(client)
            courts_task          = self._search_courts(client)
            opencorporates_task  = self._search_opencorporates(client)

            results = await asyncio.gather(
                datagov_task,
                guidestar_task,
                b144_task,
                courts_task,
                opencorporates_task,
                return_exceptions=True,
            )

        def _safe(r, default):
            return r if not isinstance(r, Exception) else default

        return {
            "datagov":        _safe(results[0], {}),
            "guidestar":      _safe(results[1], {"organizations": [], "officers": []}),
            "b144":           _safe(results[2], {"results": [], "total": 0}),
            "courts":         _safe(results[3], {"results": [], "total": 0}),
            "opencorporates": _safe(results[4], {"companies": [], "total": 0}),
        }

    # ── data.gov.il ──────────────────────────────────────────────────────────────

    async def _search_datagov(self, client: httpx.AsyncClient) -> dict:
        tasks = [
            self._datagov_resource(client, key, info)
            for key, info in DATAGOV_RESOURCES.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for (key, info), result in zip(DATAGOV_RESOURCES.items(), results):
            if isinstance(result, Exception):
                output[key] = {"label": info["label"], "records": [], "total": 0}
            else:
                output[key] = {"label": info["label"], **result}
        return output

    async def _datagov_resource(self, client: httpx.AsyncClient,
                                key: str, info: dict) -> dict:
        try:
            resp = await client.get(
                f"{DATAGOV}/datastore_search",
                params={"resource_id": info["id"], "q": self.query, "limit": 30},
                timeout=15,
            )
            data = resp.json()
            if not data.get("success"):
                return {"records": [], "total": 0}

            query_lower = self.query.lower()
            filtered = []
            for rec in data["result"].get("records", []):
                text = " ".join(str(v) for v in rec.values() if v).lower()
                if query_lower in text:
                    clean = {k: v for k, v in rec.items()
                             if k not in ("_id", "_full_text") and v not in (None, "", [])}
                    filtered.append(clean)

            return {"records": filtered, "total": len(filtered)}
        except Exception as e:
            self.log(f"datagov/{key}: {e}")
            return {"records": [], "total": 0}

    # ── Guidestar ─────────────────────────────────────────────────────────────────

    async def _search_guidestar(self, client: httpx.AsyncClient) -> dict:
        orgs, officers = [], []

        # Organizations search
        try:
            resp = await client.get(
                "https://www.guidestar.org.il/api/search",
                params={"searchTerm": self.query, "pageSize": 25},
                headers={**HEADERS, "Referer": "https://www.guidestar.org.il/"},
                timeout=12,
            )
            data = resp.json()
            for o in (data.get("organizations") or data.get("results") or []):
                org_id = o.get("orgNumber") or o.get("id", "")
                orgs.append({
                    "name":    o.get("name") or o.get("orgName") or o.get("Name", ""),
                    "number":  org_id,
                    "type":    o.get("orgType") or o.get("type", "עמותה"),
                    "status":  o.get("statusDescription") or o.get("status", ""),
                    "city":    o.get("city") or o.get("City", ""),
                    "purpose": o.get("goal") or o.get("purpose") or o.get("Goals", ""),
                    "url":     f"https://www.guidestar.org.il/organization/{org_id}",
                })
        except Exception as e:
            self.log(f"guidestar orgs: {e}")

        # Officers search (person → what positions they hold)
        try:
            resp = await client.get(
                "https://www.guidestar.org.il/api/search",
                params={"searchTerm": self.query, "pageSize": 25, "type": "officers"},
                headers={**HEADERS, "Referer": "https://www.guidestar.org.il/"},
                timeout=12,
            )
            data = resp.json()
            for o in (data.get("officers") or data.get("results") or []):
                org_id = o.get("orgNumber") or o.get("organizationId", "")
                officers.append({
                    "name":     o.get("name") or o.get("officerName", ""),
                    "role":     o.get("role") or o.get("officerRole", ""),
                    "org_name": o.get("orgName") or o.get("organizationName", ""),
                    "org_id":   org_id,
                    "url":      f"https://www.guidestar.org.il/organization/{org_id}",
                })
        except Exception as e:
            self.log(f"guidestar officers: {e}")

        return {"organizations": orgs, "officers": officers}

    # ── B144 ──────────────────────────────────────────────────────────────────────

    async def _search_b144(self, client: httpx.AsyncClient) -> dict:
        results = []

        # Try JSON API first
        try:
            resp = await client.get(
                "https://www.b144.co.il/api/search/",
                params={"q": self.query, "lang": "he", "limit": 20},
                timeout=12,
            )
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                data = resp.json()
                items = data.get("results") or data.get("items") or data.get("businesses") or []
                for item in items[:15]:
                    r = {
                        "name":    item.get("name") or item.get("title", ""),
                        "phone":   item.get("phone") or item.get("phoneNumber") or item.get("telephone", ""),
                        "address": item.get("address") or item.get("street", ""),
                        "city":    item.get("city") or item.get("cityName", ""),
                        "type":    item.get("category") or item.get("businessType", ""),
                    }
                    if r["name"]:
                        results.append(r)
        except Exception:
            pass

        # HTML scrape fallback
        if not results:
            try:
                resp = await client.get(
                    "https://www.b144.co.il/Search/",
                    params={"what": self.query, "where": ""},
                    headers={**HEADERS, "Referer": "https://www.b144.co.il/"},
                    timeout=15,
                )
                soup = BeautifulSoup(resp.text, "lxml")
                selectors = (
                    ".business-card, .result-item, [class*='BusinessCard'], "
                    "[class*='business_card'], .SearchResult, [data-type='result']"
                )
                for card in soup.select(selectors)[:15]:
                    name  = card.select_one("[class*='name'], [class*='Name'], h2, h3")
                    phone = card.select_one("[class*='phone'], [href^='tel:']")
                    addr  = card.select_one("[class*='address'], [class*='addr']")
                    city  = card.select_one("[class*='city']")
                    phone_val = ""
                    if phone:
                        phone_val = (phone.get("href", "").replace("tel:", "")
                                     or phone.get_text(strip=True))
                    r = {
                        "name":    name.get_text(strip=True) if name else "",
                        "phone":   phone_val,
                        "address": addr.get_text(strip=True) if addr else "",
                        "city":    city.get_text(strip=True) if city else "",
                    }
                    if r["name"]:
                        results.append(r)
            except Exception as e:
                self.log(f"b144 html: {e}")

        return {"results": results, "total": len(results)}

    # ── Courts ────────────────────────────────────────────────────────────────────

    async def _search_courts(self, client: httpx.AsyncClient) -> dict:
        psakdin, takdin = await asyncio.gather(
            self._search_psakdin(client),
            self._search_takdin(client),
            return_exceptions=True,
        )
        all_results = (
            (psakdin if not isinstance(psakdin, Exception) else []) +
            (takdin  if not isinstance(takdin,  Exception) else [])
        )
        return {"results": all_results, "total": len(all_results)}

    async def _search_psakdin(self, client: httpx.AsyncClient) -> list[dict]:
        results = []
        try:
            resp = await client.get(
                "https://www.psakdin.co.il/api/search",
                params={"q": self.query, "limit": 10},
                timeout=12,
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in (data.get("results") or data.get("hits") or [])[:10]:
                    results.append({
                        "source":  "psakdin.co.il",
                        "title":   item.get("title") or item.get("name", ""),
                        "date":    item.get("date") or item.get("publishDate", ""),
                        "court":   item.get("court") or item.get("courtName", ""),
                        "case":    item.get("caseNumber") or item.get("case_id", ""),
                        "url":     item.get("url") or item.get("link", ""),
                        "snippet": item.get("snippet") or item.get("summary", ""),
                    })
        except Exception:
            pass

        if not results:
            try:
                resp = await client.get(
                    "https://www.psakdin.co.il/",
                    params={"search": self.query},
                    timeout=15,
                )
                soup = BeautifulSoup(resp.text, "lxml")
                for item in soup.select(
                    ".verdict-item, .result-row, article, .case-item, [class*='verdict']"
                )[:8]:
                    title   = item.select_one("h2, h3, .title, [class*='title']")
                    date    = item.select_one(".date, time, [class*='date']")
                    court   = item.select_one(".court, [class*='court']")
                    link    = item.select_one("a[href]")
                    snippet = item.select_one("p, .snippet, [class*='snippet']")
                    r = {
                        "source":  "psakdin.co.il",
                        "title":   title.get_text(strip=True) if title else "",
                        "date":    date.get_text(strip=True) if date else "",
                        "court":   court.get_text(strip=True) if court else "",
                        "url":     link.get("href", "") if link else "",
                        "snippet": snippet.get_text(strip=True) if snippet else "",
                    }
                    if r["title"]:
                        results.append(r)
            except Exception as e:
                self.log(f"psakdin: {e}")

        return results

    async def _search_takdin(self, client: httpx.AsyncClient) -> list[dict]:
        results = []
        try:
            resp = await client.get(
                "https://www.takdin.co.il/search/results",
                params={"searchQuery": self.query, "pageNumber": 1},
                headers={**HEADERS, "Referer": "https://www.takdin.co.il/"},
                timeout=12,
            )
            soup = BeautifulSoup(resp.text, "lxml")
            for item in soup.select(
                ".search-result, .verdict, [class*='result'], [class*='verdict']"
            )[:8]:
                title = item.select_one("h2, h3, .title, a")
                date  = item.select_one(".date, time, [class*='date']")
                court = item.select_one(".court-name, [class*='court']")
                link  = item.select_one("a[href]")
                href  = link.get("href", "") if link else ""
                if href.startswith("/"):
                    href = "https://www.takdin.co.il" + href
                r = {
                    "source": "takdin.co.il",
                    "title":  title.get_text(strip=True) if title else "",
                    "date":   date.get_text(strip=True) if date else "",
                    "court":  court.get_text(strip=True) if court else "",
                    "url":    href,
                }
                if r["title"]:
                    results.append(r)
        except Exception as e:
            self.log(f"takdin: {e}")
        return results

    # ── OpenCorporates ────────────────────────────────────────────────────────────

    async def _search_opencorporates(self, client: httpx.AsyncClient) -> dict:
        results = []
        try:
            resp = await client.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={"q": self.query, "jurisdiction_code": "il", "per_page": 10},
                timeout=12,
            )
            data = resp.json()
            for c in data.get("results", {}).get("companies", [])[:10]:
                co = c.get("company", c)
                results.append({
                    "name":         co.get("name", ""),
                    "number":       co.get("company_number", ""),
                    "status":       co.get("current_status", ""),
                    "type":         co.get("company_type", ""),
                    "incorporated": co.get("incorporation_date", ""),
                    "address":      co.get("registered_address_in_full", ""),
                    "url":          co.get("opencorporates_url", ""),
                })
        except Exception as e:
            self.log(f"opencorporates: {e}")
        return {"companies": results, "total": len(results)}
