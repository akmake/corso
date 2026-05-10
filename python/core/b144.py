"""
b144.py — Israeli phone directory search via b144.co.il
Returns: list of {name, phone, address, city, source}
Uses httpx first (JSON API endpoint), Playwright fallback for JS-rendered results.
"""
from __future__ import annotations

import asyncio
import re
import logging
from typing import Optional

import httpx

log = logging.getLogger(__name__)

_API_URL = "https://www.b144.co.il/api/search"
_SITE_URL = "https://www.b144.co.il/Numbers/?name={name}&city="

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "Referer": "https://www.b144.co.il/",
    "Origin": "https://www.b144.co.il",
}

_PHONE_RE = re.compile(r'(?:0(?:[23489]|5[0-9]|7[2-9]))-?\d{7}')


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r'\D', '', raw)
    if len(digits) == 9 and digits.startswith('0'):
        return f"{digits[:2]}-{digits[2:]}"
    if len(digits) == 10 and digits.startswith('0'):
        return f"{digits[:3]}-{digits[3:]}"
    return digits


def _parse_api_results(data: dict | list) -> list[dict]:
    results = []
    items = data if isinstance(data, list) else data.get("results", data.get("items", []))
    for item in items:
        if not isinstance(item, dict):
            continue
        name = (
            item.get("name") or
            item.get("fullName") or
            item.get("businessName") or
            f"{item.get('firstName', '')} {item.get('lastName', '')}".strip()
        )
        phones = []
        for key in ("phone", "phoneNumber", "phones", "tel", "mobile"):
            val = item.get(key)
            if isinstance(val, list):
                phones.extend(val)
            elif val:
                phones.append(str(val))

        address_parts = []
        for key in ("street", "streetName", "houseNumber", "address"):
            v = item.get(key)
            if v:
                address_parts.append(str(v))
        city = item.get("city") or item.get("cityName") or item.get("settlementName") or ""
        address = " ".join(address_parts)

        for phone in phones:
            normalized = _normalize_phone(phone)
            if normalized and name:
                results.append({
                    "name": name,
                    "phone": normalized,
                    "address": address,
                    "city": city,
                    "source": "b144.co.il",
                })
    return results


async def _search_api(name: str, city: str = "") -> list[dict]:
    """Try the b144 JSON API endpoint."""
    params = {
        "name": name,
        "city": city,
        "type": "private",
        "pageNumber": 1,
        "pageSize": 20,
    }
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=15, follow_redirects=True) as client:
            r = await client.get(_API_URL, params=params)
            if r.status_code == 200:
                data = r.json()
                results = _parse_api_results(data)
                if results:
                    return results
    except Exception as exc:
        log.debug("b144 API error: %s", exc)
    return []


async def _search_api_post(name: str, city: str = "") -> list[dict]:
    """Try POST variant of b144 API."""
    payload = {
        "name": name,
        "city": city,
        "type": "private",
        "page": 1,
        "pageSize": 20,
    }
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=15, follow_redirects=True) as client:
            r = await client.post(_API_URL, json=payload)
            if r.status_code == 200:
                data = r.json()
                results = _parse_api_results(data)
                if results:
                    return results
    except Exception as exc:
        log.debug("b144 POST API error: %s", exc)
    return []


def _parse_html_results(html: str) -> list[dict]:
    """Parse phone/address from b144 HTML page."""
    results = []
    # Look for structured data blocks
    # Pattern: name + phone + address in proximity
    phone_pattern = re.compile(r'(\d{2,3}-\d{7,8})')
    # Find all phone numbers
    phones_found = phone_pattern.findall(html)

    # Try to find person-like blocks: Hebrew name + phone
    # b144 HTML contains spans with class names like "name", "phone", "address"
    block_re = re.compile(
        r'<[^>]*class="[^"]*(?:name|subscriber)[^"]*"[^>]*>([^<]{2,50})</[^>]+>.*?'
        r'<[^>]*class="[^"]*(?:phone|tel)[^"]*"[^>]*>([^<]{7,15})</[^>]+>',
        re.DOTALL
    )
    for m in block_re.finditer(html):
        name_raw = re.sub(r'\s+', ' ', m.group(1)).strip()
        phone_raw = re.sub(r'\s+', '', m.group(2)).strip()
        normalized = _normalize_phone(phone_raw)
        if name_raw and normalized:
            results.append({
                "name": name_raw,
                "phone": normalized,
                "address": "",
                "city": "",
                "source": "b144.co.il",
            })

    # Fallback: if no structured blocks, just list phones found
    if not results and phones_found:
        for phone in phones_found[:10]:
            results.append({
                "name": "",
                "phone": phone,
                "address": "",
                "city": "",
                "source": "b144.co.il (unstructured)",
            })

    return results


def _playwright_sync(name: str) -> list[dict]:
    """
    Run Playwright synchronously inside a dedicated thread.
    This avoids the Windows SelectorEventLoop subprocess limitation.
    """
    import asyncio as _asyncio

    async def _inner():
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except ImportError:
            return []

        url = _SITE_URL.format(name=name)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--lang=he-IL,he",
                    ],
                )
                context = await browser.new_context(
                    user_agent=_HEADERS["User-Agent"],
                    locale="he-IL",
                    viewport={"width": 1280, "height": 800},
                )
                page = await context.new_page()
                await page.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
                )
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(3000)

                try:
                    entries = await page.evaluate("""() => {
                        const results = [];
                        const cards = document.querySelectorAll(
                            '.result-item, .subscriber-card, [class*="result"], [class*="subscriber"]'
                        );
                        cards.forEach(card => {
                            const n = (card.querySelector('[class*="name"]') || {}).innerText || '';
                            const ph = (card.querySelector('[class*="phone"], [class*="tel"]') || {}).innerText || '';
                            const addr = (card.querySelector('[class*="address"], [class*="street"]') || {}).innerText || '';
                            const city = (card.querySelector('[class*="city"]') || {}).innerText || '';
                            if (n || ph) results.push({name: n.trim(), phone: ph.trim(), address: addr.trim(), city: city.trim()});
                        });
                        return results;
                    }""")
                    results = []
                    for entry in entries:
                        phone = _normalize_phone(entry.get("phone", ""))
                        if phone or entry.get("name"):
                            results.append({
                                "name": entry.get("name", ""),
                                "phone": phone,
                                "address": entry.get("address", ""),
                                "city": entry.get("city", ""),
                                "source": "b144.co.il",
                            })
                    if results:
                        await browser.close()
                        return results
                except Exception:
                    pass

                html = await page.content()
                await browser.close()
                return _parse_html_results(html)

        except Exception as exc:
            log.warning("b144 Playwright inner error: %s", exc)
            return []

    # Use ProactorEventLoop on Windows so subprocess_exec works
    if hasattr(_asyncio, "WindowsProactorEventLoopPolicy"):
        _asyncio.set_event_loop_policy(_asyncio.WindowsProactorEventLoopPolicy())
    loop = _asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_inner())
    finally:
        loop.close()


async def _search_playwright(name: str) -> list[dict]:
    """
    Playwright fallback — runs in a thread with ProactorEventLoop (Windows safe).
    """
    try:
        import concurrent.futures
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return await loop.run_in_executor(pool, _playwright_sync, name)
    except Exception as exc:
        log.warning("b144 Playwright error: %s", exc)
        return []


async def _search_duckduckgo_fallback(name: str) -> list[dict]:
    """
    Use DuckDuckGo site:b144.co.il search to find relevant pages,
    then extract phone numbers from snippets.
    """
    try:
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        try:
            from ddgs import DDGS  # type: ignore
        except ImportError:
            from duckduckgo_search import DDGS  # type: ignore

        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=1)

        def _run():
            with DDGS() as ddgs:
                query = f'site:b144.co.il "{name}"'
                return list(ddgs.text(query, max_results=5, region="il-he"))

        raw = await loop.run_in_executor(executor, _run)
        results = []
        for r in raw:
            snippet = r.get("body", "")
            phones = _PHONE_RE.findall(snippet)
            for phone in phones:
                results.append({
                    "name": name,
                    "phone": _normalize_phone(phone),
                    "address": "",
                    "city": "",
                    "source": "b144.co.il (DDG snippet)",
                })
        return results
    except Exception as exc:
        log.debug("b144 DDG fallback error: %s", exc)
        return []


class B144Search:
    """
    Search Israeli phone directory b144.co.il for a person by name.

    Usage:
        results = await B144Search("משה קהן").search()
        # returns list of {name, phone, address, city, source}
    """

    def __init__(self, name: str, city: str = ""):
        self.name = name.strip()
        self.city = city.strip()

    async def search(self) -> list[dict]:
        if not self.name:
            return []

        # 1. Try JSON API (GET)
        results = await _search_api(self.name, self.city)
        if results:
            log.info("b144 API returned %d results for '%s'", len(results), self.name)
            return results

        # 2. Try JSON API (POST)
        results = await _search_api_post(self.name, self.city)
        if results:
            log.info("b144 POST API returned %d results for '%s'", len(results), self.name)
            return results

        # 3. Try Playwright (JS rendering)
        log.info("b144 API failed, trying Playwright for '%s'", self.name)
        results = await _search_playwright(self.name)
        if results:
            log.info("b144 Playwright returned %d results for '%s'", len(results), self.name)
            return results

        # 4. DuckDuckGo site: search as last resort
        log.info("b144 Playwright failed, trying DDG fallback for '%s'", self.name)
        results = await _search_duckduckgo_fallback(self.name)
        if results:
            log.info("b144 DDG fallback returned %d results for '%s'", len(results), self.name)

        return results


# Convenience wrapper
async def search_b144(name: str, city: str = "") -> list[dict]:
    return await B144Search(name, city).search()
