"""
Tor Client Module
-----------------
Routes HTTP requests through the Tor network via SOCKS5 proxy.

Requirements:
  - Tor daemon running locally (default: SOCKS5 on 127.0.0.1:9050)
  - pip install httpx[socks]   (or PySocks + requests)

Usage:
  client = TorClient()
  result = await client.fetch("http://example.onion")
  result = await client.fetch("https://check.torproject.org")
"""

import asyncio
import socket
from typing import Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

TOR_PROXY  = "socks5://127.0.0.1:9050"
TOR_CHECK  = "https://check.torproject.org/api/ip"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
}


def _is_tor_running(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Check if the Tor SOCKS5 proxy port is open and listening."""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


class TorClient:

    def __init__(self, proxy: str = TOR_PROXY):
        self.proxy = proxy

    # ── Status check ─────────────────────────────────────────────────────────
    async def status(self) -> dict:
        """Check Tor daemon status and current exit node IP."""
        if not _is_tor_running():
            return {
                "tor_running": False,
                "error": (
                    "Tor daemon is not running. "
                    "Install Tor Browser or run: tor (from Tor binary)"
                ),
            }

        try:
            async with httpx.AsyncClient(
                proxy=self.proxy,
                headers=HEADERS,
                timeout=15,
                verify=False,
            ) as client:
                r = await client.get(TOR_CHECK)
                data = r.json()
                return {
                    "tor_running": True,
                    "is_tor":      data.get("IsTor", False),
                    "exit_ip":     data.get("IP", "unknown"),
                }
        except Exception as e:
            return {"tor_running": True, "error": str(e)}

    # ── Fetch any URL through Tor ─────────────────────────────────────────────
    async def fetch(self, url: str) -> dict:
        """
        Fetch a URL (clearnet or .onion) through Tor.
        Returns: status_code, url, text (first 50KB), headers
        """
        if not _is_tor_running():
            return {"error": "Tor daemon is not running on 127.0.0.1:9050"}

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            async with httpx.AsyncClient(
                proxy=self.proxy,
                headers=HEADERS,
                follow_redirects=True,
                timeout=30,
                verify=False,
            ) as client:
                r = await client.get(url)
                return {
                    "url":         str(r.url),
                    "status_code": r.status_code,
                    "headers":     dict(r.headers),
                    "text":        r.text[:50_000],   # cap at 50 KB
                    "via_tor":     True,
                }
        except Exception as e:
            return {"error": str(e), "url": url}

    # ── Search across known .onion indexes ───────────────────────────────────
    async def search_onion(self, query: str) -> dict:
        """
        Search for a query on Ahmia (the clearnet Tor search engine index).
        Does NOT require Tor — Ahmia has a clearnet mirror.
        For actual .onion results, set use_onion=True (requires Tor running).
        """
        # Ahmia clearnet search (no Tor needed)
        ahmia_url = f"https://ahmia.fi/search/?q={query.replace(' ', '+')}"

        try:
            async with httpx.AsyncClient(headers=HEADERS, timeout=15) as client:
                r = await client.get(ahmia_url)

            # Extract .onion links from results page
            import re
            onion_links = list(set(
                re.findall(r'[a-z2-7]{16,56}\.onion', r.text)
            ))

            return {
                "query":       query,
                "source":      "ahmia.fi",
                "onion_links": onion_links[:30],
                "total":       len(onion_links),
                "note":        "Results from Ahmia clearnet index. Use fetch() to visit .onion links via Tor.",
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Playwright (browser) fetch via Tor proxy ─────────────────────────────
    async def fetch_with_browser(self, url: str) -> dict:
        """
        Fetches a JavaScript-heavy URL using the Playwright browser,
        routed through the Tor SOCKS5 proxy so the real IP is never exposed.
        Requires Playwright + Chromium to be installed.
        """
        if not _is_tor_running():
            return {"error": "Tor daemon is not running on 127.0.0.1:9050"}

        try:
            from core.scraper_playwright import PlaywrightExtractor
            extractor = PlaywrightExtractor(url, proxy_url=self.proxy)
            result = await extractor.extract_deep_data()
            return result
        except ImportError:
            return {"error": "Playwright not installed: pip install playwright && playwright install chromium"}
        except Exception as e:
            return {"error": str(e), "url": url}

    # ── Get a new Tor circuit (rotate exit IP) ───────────────────────────────
    async def new_circuit(self) -> dict:
        """
        Signal Tor to build a new circuit (new exit IP).
        Requires stem library and Tor control port (9051) to be enabled.
        """
        try:
            import stem
            from stem import Signal
            from stem.control import Controller

            loop = asyncio.get_event_loop()

            def _signal():
                with Controller.from_port(port=9051) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)

            await loop.run_in_executor(None, _signal)
            return {"success": True, "message": "New Tor circuit requested — wait ~10s for new IP"}

        except ImportError:
            return {"error": "stem library not installed: pip install stem"}
        except Exception as e:
            return {"error": str(e)}
