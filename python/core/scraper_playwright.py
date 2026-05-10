import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

EMAIL_RE = re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]{2,}')
PHONE_RE = re.compile(r'(?<!\d)[\+]?[\d][\d\s\-\(\)\.]{7,14}\d(?!\d)')

_executor = ThreadPoolExecutor(max_workers=2)

# Chromium launch args that reduce bot-detection fingerprints
_STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-infobars",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--window-size=1920,1080",
    "--lang=en-US,en;q=0.9",
]

class PlaywrightExtractor:
    def __init__(self, url: str, proxy_url: str = None):
        """
        proxy_url: optional SOCKS5/HTTP proxy, e.g. "socks5://127.0.0.1:9050" for Tor.
        """
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url = url
        self.domain = urlparse(url).netloc
        self.proxy_url = proxy_url

    def _run_sync(self) -> dict:
        proxy_config = {"server": self.proxy_url} if self.proxy_url else None
        js_bodies: list[str] = []
        intercepted_requests: list[dict] = []  # network-level intel

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=_STEALTH_ARGS)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                ignore_https_errors=True,
                proxy=proxy_config,
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                },
            )
            page = context.new_page()
            page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

            def _on_request(request):
                """Capture every outgoing request — API keys live in headers."""
                url = request.url
                headers = request.headers
                entry = {"url": url, "headers": {}}
                for h in ("apikey", "x-api-key", "authorization", "x-supabase-api-key"):
                    if h in headers:
                        entry["headers"][h] = headers[h]
                if any(v for v in entry["headers"].values()) or "supabase" in url or "firebase" in url:
                    intercepted_requests.append(entry)

            def _on_response(response):
                """Capture JS bundle bodies AND look for BaaS config in JSON responses."""
                url = response.url
                ct = response.headers.get("content-type", "")
                if response.status == 200:
                    if ".js" in url or "javascript" in ct:
                        try:
                            body = response.body()
                            js_bodies.append(body.decode("utf-8", errors="ignore")[:1_200_000])
                        except Exception:
                            pass

            page.on("request", _on_request)
            page.on("response", _on_response)

            try:
                response = page.goto(self.url, wait_until="domcontentloaded", timeout=30000)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(3000)

                html_content = page.content()
                title = page.title()

                # ── נאסוף לינקים פנימיים ונבקר בהם כדי לטעון JS chunks ──
                from urllib.parse import urlparse, urljoin
                base_origin = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
                raw_links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                internal_links = list(dict.fromkeys([
                    l for l in raw_links
                    if l.startswith(base_origin) and l != self.url and "#" not in l
                ]))[:8]  # מקסימום 8 דפים פנימיים

                for link in internal_links:
                    try:
                        page.goto(link, wait_until="domcontentloaded", timeout=12000)
                        page.wait_for_timeout(1500)
                    except Exception:
                        pass

                emails_all = sorted(set(EMAIL_RE.findall(html_content)))
                phones = sorted(set(PHONE_RE.findall(html_content)))
                browser.close()
                return {
                    "url": self.url,
                    "status_code": response.status if response else None,
                    "title": title,
                    "emails_found": emails_all,
                    "phones_found": phones,
                    "html_content": html_content,
                    "js_content": "\n".join(js_bodies),
                    "intercepted_requests": intercepted_requests,
                    "screenshot_captured": False,
                    "via_proxy": self.proxy_url is not None,
                }
            except Exception as e:
                browser.close()
                return {"url": self.url, "error": str(e), "html_content": "", "js_content": "", "intercepted_requests": []}

    async def extract_deep_data(self) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, self._run_sync)
