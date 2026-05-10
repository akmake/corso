"""
Site Name Search — מנוע חיפוש שם עמוק על פני אתר שלם
========================================================
מקבל URL של אתר + שם לחיפוש.
שלב 1: DDG site: search — מוצא דפים אינדקסיים תוך שניות
שלב 2: BFS crawl — סורק לינקים שלא אינדקסיה מנוע חיפוש
שלב 3: מחלץ כל הופעה של השם עם הקשר (excerpt)
מחזיר ממצאים ממוינים לפי רלוונטיות.
"""

import asyncio
import re
import urllib.parse
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
import httpx

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "he,en-US;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

MAX_PAGES   = 120   # מקסימום דפים לסריקה
MAX_DEPTH   = 5     # עומק קישורים מקסימלי
MAX_WORKERS = 8     # בקשות מקבילות


class SiteNameSearch:
    def __init__(self, site_url: str, name: str):
        self.name = name.strip()
        if not site_url.startswith("http"):
            site_url = "https://" + site_url
        self.site_url = site_url.rstrip("/")
        parsed = urlparse(self.site_url)
        self.domain  = parsed.netloc
        self.scheme  = parsed.scheme
        self._visited:  set[str] = set()
        self._findings: list[dict] = []
        self._queue:    list[tuple[str, int]] = []

    async def search(self) -> dict:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=12,
            verify=False,
        ) as client:
            # שלב 1: DDG site: search — מוצא דפים ממנוע חיפוש מיידית
            dgg_urls = await self._dgg_site_search(client)

            # שלב 2: מוסיף את הדף הראשי + כל שנמצא ב-DDG לתור
            seed_urls = [self.site_url] + dgg_urls
            for url in seed_urls:
                norm, _ = urldefrag(url)
                if norm not in self._visited:
                    self._queue.append((norm, 0))

            # שלב 3: BFS crawl מקבילי
            pages_crawled = await self._bfs_crawl(client)

        return {
            "site":          self.site_url,
            "name":          self.name,
            "pages_crawled": pages_crawled,
            "pages_found":   len(self._findings),
            "total_hits":    sum(f["count"] for f in self._findings),
            "findings":      sorted(self._findings, key=lambda x: -x["count"]),
        }

    # ── DDG site: search ─────────────────────────────────────────────────────
    async def _dgg_site_search(self, client: httpx.AsyncClient) -> list[str]:
        """
        site:example.com "שם" — מחזיר דפים שמנוע חיפוש כבר יודע שמכילים את השם.
        הרבה יותר מהיר מלזחול את כל האתר בעצמנו.
        """
        urls: list[str] = []
        query = f'site:{self.domain} "{self.name}"'
        encoded = urllib.parse.quote(query)

        # נסה DDG HTML
        try:
            r = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query},
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for result in soup.find_all("div", class_="result"):
                    link_tag = result.find("a", class_="result__a")
                    if not link_tag:
                        continue
                    link = link_tag.get("href", "")
                    if "duckduckgo.com/l/?" in link:
                        try:
                            link = urllib.parse.unquote(link.split("uddg=")[1].split("&")[0])
                        except Exception:
                            continue
                    if link.startswith("http") and self.domain in link:
                        urls.append(link)
        except Exception:
            pass

        # Bing fallback
        if not urls:
            try:
                r = await client.get(
                    f"https://www.bing.com/search?q={encoded}&count=20",
                    timeout=15,
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for li in soup.find_all("li", class_="b_algo"):
                        h2 = li.find("h2")
                        a  = h2.find("a") if h2 else None
                        if a and a.get("href", "").startswith("http") and self.domain in a.get("href", ""):
                            urls.append(a.get("href"))
            except Exception:
                pass

        return urls[:30]

    # ── BFS crawl מקבילי ─────────────────────────────────────────────────────
    async def _bfs_crawl(self, client: httpx.AsyncClient) -> int:
        sem = asyncio.Semaphore(MAX_WORKERS)
        pages_crawled = 0

        while self._queue and pages_crawled < MAX_PAGES:
            # קח batch של עד MAX_WORKERS דפים
            batch = []
            while self._queue and len(batch) < MAX_WORKERS:
                url, depth = self._queue.pop(0)
                if url in self._visited:
                    continue
                self._visited.add(url)
                batch.append((url, depth))

            if not batch:
                break

            tasks = [self._crawl_page(client, url, depth, sem) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            pages_crawled += len(batch)

        return pages_crawled

    async def _crawl_page(
        self,
        client:  httpx.AsyncClient,
        url:     str,
        depth:   int,
        sem:     asyncio.Semaphore,
    ) -> None:
        async with sem:
            try:
                r = await client.get(url, timeout=10)
                if r.status_code != 200:
                    return
                ct = r.headers.get("content-type", "")
                if "html" not in ct:
                    return

                soup  = BeautifulSoup(r.text, "lxml")
                # מנקה script/style לפני חילוץ טקסט
                for tag in soup(["script", "style", "noscript", "svg"]):
                    tag.decompose()

                title_tag = soup.find("title")
                page_title = title_tag.get_text(strip=True) if title_tag else url

                text        = soup.get_text(separator=" ", strip=True)
                occurrences = self._find_occurrences(text)

                if occurrences:
                    self._findings.append({
                        "url":         url,
                        "title":       page_title,
                        "depth":       depth,
                        "count":       len(occurrences),
                        "occurrences": occurrences[:6],
                    })

                # גילוי קישורים לרמה הבאה
                if depth < MAX_DEPTH:
                    self._extract_links(soup, url, depth)

            except Exception:
                pass

    def _extract_links(self, soup: BeautifulSoup, base_url: str, depth: int) -> None:
        seen_queue = {url for url, _ in self._queue}
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            abs_url, _ = urldefrag(urljoin(base_url, href))
            parsed = urlparse(abs_url)
            if (
                parsed.netloc == self.domain
                and abs_url not in self._visited
                and abs_url not in seen_queue
                and parsed.scheme in ("http", "https")
            ):
                # מסנן סיומות שאינן HTML
                lower = abs_url.lower()
                if any(lower.endswith(ext) for ext in (
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                    ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".zip", ".rar", ".mp4", ".mp3",
                )):
                    continue
                self._queue.append((abs_url, depth + 1))
                seen_queue.add(abs_url)

    # ── חיפוש הופעות השם בטקסט ──────────────────────────────────────────────
    def _find_occurrences(self, text: str) -> list[dict]:
        name_lower = self.name.lower()
        text_lower = text.lower()
        occurrences: list[dict] = []
        start = 0
        while True:
            idx = text_lower.find(name_lower, start)
            if idx == -1:
                break
            # 150 תווים לפני ואחרי
            ctx_start = max(0, idx - 150)
            ctx_end   = min(len(text), idx + len(self.name) + 150)
            excerpt   = text[ctx_start:ctx_end].strip()
            if ctx_start > 0:
                excerpt = "…" + excerpt
            if ctx_end < len(text):
                excerpt = excerpt + "…"
            occurrences.append({"position": idx, "excerpt": excerpt})
            start = idx + len(self.name)
        return occurrences
