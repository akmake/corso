"""
Person Dossier — מנוע OSINT אישי עם Cascade Intelligence
=========================================================
שלב 1: 10+ שאילתות Bing+DDG מקבילות (variations שונות)
שלב 2: חילוץ ישויות אוטומטי מהתוצאות — אימיילים, טלפונים, חברות
שלב 3: כל ישות שנמצאת → חקירה עצמאית מקבילית
         אימייל → Gravatar + GitHub + SSL certs (crt.sh)
         טלפון  → פרסור + WhatsApp/Telegram links
         username → SOCMINT על 80+ פלטפורמות
שלב 4: רשומות ישראליות — data.gov.il (עמותות, חברות, מכרזים)
שלב 5: בניית גרף קשרים ממידע אמיתי בלבד
"""

import asyncio
import hashlib
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import httpx
try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

_executor = ThreadPoolExecutor(max_workers=6)

# דפי login/כניסה — לא נותנים מידע על האדם
_LOGIN_DOMAINS = frozenset({
    "accounts.google.com", "mail.google.com", "gmail.com",
    "outlook.office.com", "outlook.live.com", "login.microsoftonline.com",
    "icloud.com", "appleid.apple.com",
    "login.yahoo.com", "login.facebook.com",
})

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier
    _PH = True
except ImportError:
    _PH = False

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "he,en-US;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ── Regex ──────────────────────────────────────────────────────────────────────
_EMAIL_RE    = re.compile(r'\b([a-zA-Z][a-zA-Z0-9._%+\-]{1,40}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')
_PHONE_IL_RE = re.compile(
    r'(?<!\d)(0[5-9]\d[\s\-]?\d{3}[\s\-]?\d{4}'
    r'|0[2-9][\s\-]?\d{7}'
    r'|\+972[\s\-]?[5-9]\d[\s\-]?\d{7})(?!\d)'
)
_CO_BVM_RE   = re.compile(r'([א-ת][^\s,.\(\)]{1,30}(?:\s[^\s,.\(\)]{1,30}){0,3})\s+בע"מ')

def _is_login_page(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    return any(domain == d or domain.endswith("." + d) for d in _LOGIN_DOMAINS)

_SKIP_EMAIL_DOMAINS = {
    "example.com", "test.com", "youremail.com", "domain.com",
    "email.com", "sentry.io", "w3.org", "schema.org",
}


class PersonDossier:
    def __init__(
        self,
        name:     str,
        email:    str = "",
        phone:    str = "",
        username: str = "",
        company:  str = "",
    ):
        self.name     = name.strip()
        self.email    = email.strip()
        self.phone    = phone.strip()
        self.username = username.strip()
        self.company  = company.strip()

        # ישויות שנגלו
        self._emails:    set[str] = set()
        self._phones:    set[str] = set()
        self._companies: set[str] = set()
        self._usernames: set[str] = set()
        self._domains:   set[str] = set()

        # זרעים ראשוניים
        if email:    self._emails.add(email.lower())
        if phone:    self._phones.add(re.sub(r'[\s\-]', '', phone))
        if username: self._usernames.add(username)
        if company:  self._companies.add(company)

        # תוצאות
        self.dork_results:   list[dict]       = []
        self.email_profiles: dict[str, dict]  = {}
        self.phone_profiles: dict[str, dict]  = {}
        self.accounts:       list[dict]        = []
        self.israeli:        dict[str, Any]    = {}
        self.b144_results:   list[dict]        = []
        self.found_emails:   list[dict]        = []

        # גרף
        self._nodes:      list[dict] = []
        self._edges:      list[dict] = []
        self._seen_nodes: set[str]   = set()
        self._seen_edges: set[str]   = set()

    # ═══════════════════════════════════════════════════════════════════════════
    async def build(self) -> dict:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=15,
            verify=False,
        ) as client:
            # שלב 1: dorking
            await self._multi_dork(client)

            # שלב 2: חילוץ ישויות
            self._extract_entities()

            # שלב 3: חקירה מקבילית
            await asyncio.gather(
                self._investigate_all_emails(client),
                self._investigate_all_phones(client),
                self._socmint_scan(),
                self._israeli_search(),
                self._b144_search(),
                self._find_emails(client),
                return_exceptions=True,
            )

        # שלב 4: גרף
        self._build_graph()

        return {
            "name":  self.name,
            "seeds": {
                "email":    self.email,
                "phone":    self.phone,
                "username": self.username,
                "company":  self.company,
            },
            "found": {
                "emails":    sorted(self._emails),
                "phones":    sorted(self._phones),
                "companies": sorted(self._companies),
                "usernames": sorted(self._usernames),
                "domains":   sorted(self._domains)[:30],
            },
            "web_results":    self.dork_results,
            "email_profiles": self.email_profiles,
            "phone_profiles": self.phone_profiles,
            "accounts":       self.accounts,
            "israeli":        self.israeli,
            "b144":           self.b144_results,
            "found_emails":   self.found_emails,
            "graph": {
                "nodes": self._nodes,
                "edges": self._edges,
            },
            "stats": {
                "web_results":    len(self.dork_results),
                "emails_found":   len(self._emails),
                "phones_found":   len(self._phones),
                "accounts_found": len(self.accounts),
                "companies_found":len(self._companies),
                "b144_records":   len(self.b144_results),
            },
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 1 — Multi-query search via duckduckgo_search library
    # ═══════════════════════════════════════════════════════════════════════════
    async def _multi_dork(self, client: httpx.AsyncClient) -> None:
        n = self.name
        queries = [
            f'"{n}"',
            f'"{n}" site:linkedin.com',
            f'"{n}" site:facebook.com',
            f'"{n}" מנהל OR מנכ"ל OR CEO OR מייסד OR יועץ OR עורך דין OR רואה חשבון',
            f'"{n}" חברה OR עמותה OR "בע"מ" OR ארגון',
            f'"{n}" site:guidestar.org.il OR site:data.gov.il OR site:opendata.gov.il',
            f'"{n}" site:ynet.co.il OR site:haaretz.co.il OR site:mako.co.il OR site:walla.co.il',
            f'"{n}" טלפון OR נייד OR כתובת OR עיר',
            f'"{n}" site:youtube.com OR site:instagram.com OR site:twitter.com',
        ]
        if self.company:
            queries.append(f'"{n}" "{self.company}"')
        if self.email:
            queries.append(f'"{self.email}"')
        if self.phone:
            queries.append(f'"{n}" "{self.phone}"')

        # הרץ את כל השאילתות במקביל
        batches = await asyncio.gather(
            *[self._search(q) for q in queries],
            return_exceptions=True,
        )

        seen: set[str] = set()
        for batch in batches:
            if not isinstance(batch, list):
                continue
            for r in batch:
                url = r.get("url", "")
                if url and url not in seen and not _is_login_page(url):
                    seen.add(url)
                    self.dork_results.append(r)

    async def _search(self, query: str) -> list[dict]:
        """חיפוש דרך duckduckgo_search — הרבה יותר אמין מגרידת HTML ישירה."""
        loop = asyncio.get_event_loop()

        def _run() -> list[dict]:
            try:
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=10, region="il-he"))
                return [
                    {
                        "url":     r.get("href", ""),
                        "title":   r.get("title", ""),
                        "snippet": r.get("body", ""),
                        "query":   query,
                    }
                    for r in results
                    if r.get("href", "").startswith("http")
                ]
            except Exception:
                return []

        return await loop.run_in_executor(_executor, _run)

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 2 — חילוץ ישויות
    # ═══════════════════════════════════════════════════════════════════════════
    def _extract_entities(self) -> None:
        all_text = " ".join(
            f"{r.get('title','')} {r.get('snippet','')}"
            for r in self.dork_results
        )

        for m in _EMAIL_RE.findall(all_text):
            em = m.lower()
            dom = em.split("@")[-1]
            if dom not in _SKIP_EMAIL_DOMAINS and len(em) < 80:
                self._emails.add(em)

        for m in _PHONE_IL_RE.findall(all_text):
            self._phones.add(re.sub(r'[\s\-]', '', m))

        for m in _CO_BVM_RE.findall(all_text):
            if 2 < len(m) < 50:
                self._companies.add(m.strip())

        for r in self.dork_results:
            try:
                d = urlparse(r["url"]).netloc.lower().replace("www.", "")
                if d and "." in d:
                    self._domains.add(d)
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3a — Email cascade
    # ═══════════════════════════════════════════════════════════════════════════
    async def _investigate_all_emails(self, client: httpx.AsyncClient) -> None:
        tasks = [self._investigate_email(client, em) for em in list(self._emails)[:5]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for em, res in zip(list(self._emails)[:5], results):
            self.email_profiles[em] = res if not isinstance(res, Exception) else {"error": str(res)}

    async def _investigate_email(self, client: httpx.AsyncClient, email: str) -> dict:
        h = hashlib.md5(email.lower().encode()).hexdigest()

        async def _gravatar() -> dict:
            r = await client.get(f"https://www.gravatar.com/{h}.json", timeout=8)
            if r.status_code == 200:
                e = r.json().get("entry", [{}])[0]
                uname = e.get("preferredUsername")
                if uname:
                    self._usernames.add(uname)
                return {
                    "found":        True,
                    "display_name": e.get("displayName"),
                    "username":     uname,
                    "location":     e.get("currentLocation"),
                    "avatar":       f"https://www.gravatar.com/avatar/{h}?s=200",
                    "urls":         [u.get("value") for u in e.get("urls", [])],
                }
            return {"found": False}

        async def _github() -> dict:
            r = await client.get(
                f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email&per_page=1",
                headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                if items:
                    r2 = await client.get(items[0]["url"], timeout=8)
                    if r2.status_code == 200:
                        ud = r2.json()
                        if ud.get("login"):
                            self._usernames.add(ud["login"])
                        return {
                            "found":        True,
                            "username":     ud.get("login"),
                            "name":         ud.get("name"),
                            "profile":      ud.get("html_url"),
                            "avatar":       ud.get("avatar_url"),
                            "company":      ud.get("company"),
                            "location":     ud.get("location"),
                            "bio":          ud.get("bio"),
                            "public_repos": ud.get("public_repos"),
                            "followers":    ud.get("followers"),
                        }
            return {"found": False}

        async def _crtsh() -> dict:
            r = await client.get(
                f"https://crt.sh/?q={urllib.parse.quote(email)}&output=json",
                timeout=12,
            )
            if r.status_code == 200:
                try:
                    certs = r.json()
                    domains: set[str] = set()
                    for cert in certs[:100]:
                        for name in cert.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if "." in name and len(name) < 100:
                                domains.add(name)
                                self._domains.add(name)
                    return {
                        "cert_count": len(certs),
                        "domains":    sorted(domains)[:20],
                    }
                except Exception:
                    pass
            return {"cert_count": 0, "domains": []}

        async def _holehe() -> list[dict]:
            try:
                from core.email_finder import holehe_check
                return await holehe_check(email)
            except Exception:
                return []

        gr, gh, cr, hl = await asyncio.gather(
            _gravatar(), _github(), _crtsh(), _holehe(),
            return_exceptions=True,
        )
        return {
            "email":    email,
            "gravatar": gr if not isinstance(gr, Exception) else {"found": False},
            "github":   gh if not isinstance(gh, Exception) else {"found": False},
            "crtsh":    cr if not isinstance(cr, Exception) else {"cert_count": 0, "domains": []},
            "registered_services": hl if not isinstance(hl, Exception) else [],
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3b — Phone cascade
    # ═══════════════════════════════════════════════════════════════════════════
    async def _investigate_all_phones(self, client: httpx.AsyncClient) -> None:
        for phone in list(self._phones)[:3]:
            self.phone_profiles[phone] = self._parse_phone(phone)

    def _parse_phone(self, phone: str) -> dict:
        digits = re.sub(r'\D', '', phone)
        if not digits.startswith("972") and digits.startswith("0"):
            digits = "972" + digits[1:]

        base: dict[str, Any] = {
            "raw": phone,
            "whatsapp": f"https://wa.me/{digits}",
            "telegram": f"https://t.me/+{digits}",
        }
        if not _PH:
            return base
        try:
            parsed = phonenumbers.parse(phone, "IL")
            if phonenumbers.is_valid_number(parsed):
                base.update({
                    "valid":         True,
                    "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    "country":       geocoder.description_for_number(parsed, "en"),
                    "carrier":       carrier.name_for_number(parsed, "en"),
                    "line_type":     str(phonenumbers.number_type(parsed)),
                })
        except Exception:
            pass
        return base

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3c — SOCMINT cascade
    # ═══════════════════════════════════════════════════════════════════════════
    async def _socmint_scan(self) -> None:
        if not self._usernames:
            return
        from core.socmint import UsernameScanner
        tasks = [UsernameScanner(u).scan() for u in list(self._usernames)[:3]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        seen_urls: set[str] = set()
        for res in results:
            if isinstance(res, Exception):
                continue
            for acc in res.get("found", []):
                if acc["url"] not in seen_urls:
                    seen_urls.add(acc["url"])
                    self.accounts.append(acc)

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3d — Israeli records
    # ═══════════════════════════════════════════════════════════════════════════
    async def _israeli_search(self) -> None:
        from core.israeli_intel import IsraeliIntelligence
        try:
            result = await IsraeliIntelligence(self.name).full_search()
            self.israeli = result
            datagov = result.get("datagov", {})
            for rec in datagov.get("companies", {}).get("records", []):
                for field in ("company_name", "שם חברה", "CompanyName"):
                    if rec.get(field):
                        self._companies.add(str(rec[field]).strip())
            for rec in datagov.get("associations", {}).get("records", []):
                for field in ("association_name", "שם עמותה", "Name"):
                    if rec.get(field):
                        self._companies.add(str(rec[field]).strip())
        except Exception:
            self.israeli = {}

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3e — b144 Israeli phone directory
    # ═══════════════════════════════════════════════════════════════════════════
    async def _b144_search(self) -> None:
        try:
            from core.b144 import B144Search
            results = await B144Search(self.name).search()
            self.b144_results = results
            for rec in results:
                phone = rec.get("phone", "")
                if phone:
                    self._phones.add(re.sub(r'[\s\-]', '', phone))
        except Exception:
            self.b144_results = []

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 3f — Email finder (permutations + Hunter.io)
    # ═══════════════════════════════════════════════════════════════════════════
    async def _find_emails(self, client: httpx.AsyncClient) -> None:
        """
        Try to discover email addresses via permutations + Hunter.io.
        Uses company domains found in web results or provided company name.
        """
        try:
            from core.email_finder import EmailFinder

            # Collect candidate domains from already-found companies and domains
            candidate_domains: list[str] = []

            # Explicitly provided company domain
            if self.company:
                # If company looks like a domain use it directly, otherwise derive
                if "." in self.company and " " not in self.company:
                    candidate_domains.append(self.company.lower())

            # Domains found in search results (filter out social/news sites)
            _SKIP_DOMAIN_PREFIXES = {
                "google", "facebook", "linkedin", "twitter", "instagram",
                "youtube", "ynet", "haaretz", "mako", "walla", "nana10",
                "wikipedia", "amazon", "apple", "microsoft",
            }
            for domain in list(self._domains)[:10]:
                base = domain.split(".")[-2] if domain.count(".") >= 1 else domain
                if base not in _SKIP_DOMAIN_PREFIXES and len(domain) < 40:
                    candidate_domains.append(domain)

            if not candidate_domains:
                return

            # Split name into first/last (best effort)
            parts = self.name.split()
            first = parts[0] if parts else self.name
            last = parts[-1] if len(parts) > 1 else ""

            all_found: list[dict] = []
            for domain in candidate_domains[:3]:  # check top 3 domains
                finder = EmailFinder(
                    first=first,
                    last=last,
                    domain=domain,
                    username=self.username,
                    verify=True,
                )
                results = await finder.find()
                for r in results:
                    email = r.get("email", "")
                    if email:
                        self._emails.add(email.lower())
                    all_found.append(r)

            self.found_emails = all_found

        except Exception:
            self.found_emails = []

    # ═══════════════════════════════════════════════════════════════════════════
    # שלב 4 — בניית גרף
    # ═══════════════════════════════════════════════════════════════════════════
    def _add_node(self, nid: str, label: str, group: str) -> None:
        if nid not in self._seen_nodes:
            self._nodes.append({"id": nid, "label": label[:45], "group": group})
            self._seen_nodes.add(nid)

    def _add_edge(self, src: str, tgt: str, label: str = "") -> None:
        eid = f"{src}→{tgt}"
        if eid not in self._seen_edges and src in self._seen_nodes and tgt in self._seen_nodes:
            self._edges.append({"from": src, "to": tgt, "label": label})
            self._seen_edges.add(eid)

    def _build_graph(self) -> None:
        # מרכז — האדם
        self._add_node(self.name, self.name, "person")

        # אימיילים
        for em in self._emails:
            self._add_node(em, em, "email")
            self._add_edge(self.name, em, "email")
            prof = self.email_profiles.get(em, {})
            if prof.get("gravatar", {}).get("found"):
                g = prof["gravatar"]
                gid = f"gravatar:{g.get('username', em)}"
                self._add_node(gid, f"Gravatar: {g.get('display_name','')}", "gravatar")
                self._add_edge(em, gid)
            if prof.get("github", {}).get("found"):
                g = prof["github"]
                gid = f"github:{g['username']}"
                self._add_node(gid, f"GitHub: {g['username']}", "github")
                self._add_edge(em, gid)
            for dom in prof.get("crtsh", {}).get("domains", [])[:5]:
                did = f"domain:{dom}"
                self._add_node(did, dom, "domain")
                self._add_edge(em, did, "ssl_cert")

        # טלפונים
        for ph in self._phones:
            self._add_node(ph, ph, "phone")
            self._add_edge(self.name, ph, "phone")

        # חברות / עמותות
        for co in self._companies:
            cid = f"co:{co}"
            self._add_node(cid, co, "company")
            self._add_edge(self.name, cid, "affiliated")

        # b144 — רשומות ספר טלפונים ישראלי
        for rec in self.b144_results[:10]:
            phone = rec.get("phone", "")
            addr = rec.get("address", "")
            city = rec.get("city", "")
            if phone:
                pid = f"phone:{phone}"
                self._add_node(pid, phone, "phone")
                self._add_edge(self.name, pid, "b144")
            if addr or city:
                loc = f"{addr} {city}".strip()
                lid = f"location:{loc}"
                self._add_node(lid, loc[:45], "location")
                if phone:
                    self._add_edge(f"phone:{phone}", lid, "address")
                else:
                    self._add_edge(self.name, lid, "address")

        # חשבונות רשתות חברתיות
        by_cat: dict[str, list] = {}
        for acc in self.accounts[:40]:
            cat = acc.get("category", "social")
            by_cat.setdefault(cat, []).append(acc)
        for cat, accs in by_cat.items():
            for acc in accs[:5]:
                aid = f"acc:{acc['platform']}"
                self._add_node(aid, acc["platform"], "social")
                self._add_edge(self.name, aid, "account")
