"""
Web Extractor Module
--------------------
Scrapes a URL and extracts structured intelligence:
  - Page metadata (title, description, OG tags)
  - Emails, phone numbers, crypto wallet addresses
  - Internal / external links
  - Social media profile links
  - Technology fingerprinting (server, frameworks, analytics)
  - EXIF metadata from images found on the page
"""

import re
import asyncio
from urllib.parse import urljoin, urlparse
from typing import Any

import httpx
from bs4 import BeautifulSoup

# ── Regex patterns ──────────────────────────────────────────────────────────
EMAIL_RE    = re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]{2,}')
PHONE_RE    = re.compile(r'(?<!\d)[\+]?[\d][\d\s\-\(\)\.]{7,14}\d(?!\d)')
BTC_RE      = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
ETH_RE      = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

SOCIAL_PLATFORMS = {
    "facebook":  "facebook.com",
    "twitter":   "twitter.com",
    "instagram": "instagram.com",
    "linkedin":  "linkedin.com",
    "youtube":   "youtube.com",
    "tiktok":    "tiktok.com",
    "telegram":  "t.me",
    "github":    "github.com",
    "reddit":    "reddit.com",
    "pinterest": "pinterest.com",
}

TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress":         ["wp-content/", "wp-includes/", "wp-json/"],
    "Shopify":           ["cdn.shopify.com", "Shopify.theme"],
    "Wix":               ["wix.com/", "wixstatic.com"],
    "Squarespace":       ["squarespace.com", "static.squarespace.com"],
    "React":             ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "_reactFiber", "react.production.min.js"],
    "Vue.js":            ["__vue__", "vue.runtime.min.js", "Vue.version"],
    "Angular":           ["ng-version=", "angular.min.js", "ng-app"],
    "Next.js":           ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js":           ["__nuxt", "_nuxt/"],
    "jQuery":            ["jquery.min.js", "jquery-"],
    "Bootstrap":         ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind CSS":      ["tailwindcss", "tw-"],
    "Google Analytics":  ["google-analytics.com/analytics.js", "gtag(", "UA-"],
    "Google Tag Manager":["googletagmanager.com/gtm.js", "GTM-"],
    "Cloudflare":        ["__cf_bm", "cloudflare-static", "cf-ray"],
    "Nginx":             [],   # detected via headers
    "Apache":            [],   # detected via headers
    "PHP":               ["<?php", ".php"],
}


class WebExtractor:
    def __init__(self, url: str):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url = url
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    async def extract_data(self) -> dict:
        """Fetch the URL and return all extracted intelligence."""
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=20,
            verify=False,       # some targets have self-signed certs
        ) as client:
            response = await client.get(self.url)

        html = response.text
        soup = BeautifulSoup(html, "lxml")

        return {
            "url":           self.url,
            "final_url":     str(response.url),
            "status_code":   response.status_code,
            "title":         self._title(soup),
            "description":   self._meta_description(soup),
            "meta_tags":     self._meta_tags(soup),
            "emails":        self._emails(html),
            "phones":        self._phones(html),
            "crypto_wallets": self._crypto_wallets(html),
            "links":         self._links(soup),
            "social_media":  self._social_links(soup),
            "technologies":  self._detect_tech(response.headers, html),
            "images":        self._images(soup),
            "response_headers": dict(response.headers),
        }

    # ── Metadata ────────────────────────────────────────────────────────────
    def _title(self, soup: BeautifulSoup) -> str:
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag else ""

    def _meta_description(self, soup: BeautifulSoup) -> str:
        tag = soup.find("meta", attrs={"name": "description"})
        return tag.get("content", "") if tag else ""

    def _meta_tags(self, soup: BeautifulSoup) -> dict:
        meta: dict[str, str] = {}
        for tag in soup.find_all("meta"):
            name    = tag.get("name") or tag.get("property") or tag.get("http-equiv")
            content = tag.get("content")
            if name and content:
                meta[name] = content
        return meta

    # ── Entity Extraction ────────────────────────────────────────────────────
    def _emails(self, html: str) -> list[str]:
        raw = EMAIL_RE.findall(html)
        # Filter out false positives (image extensions, etc.)
        return sorted(set(
            e for e in raw
            if not e.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js"))
        ))

    def _phones(self, html: str) -> list[str]:
        raw = PHONE_RE.findall(html)
        # Keep only those with >= 7 actual digits
        return sorted(set(
            p.strip() for p in raw
            if len(re.sub(r'\D', '', p)) >= 7
        ))

    def _crypto_wallets(self, html: str) -> dict:
        return {
            "bitcoin":  sorted(set(BTC_RE.findall(html))),
            "ethereum": sorted(set(ETH_RE.findall(html))),
        }

    # ── Links ────────────────────────────────────────────────────────────────
    def _links(self, soup: BeautifulSoup) -> dict:
        internal: set[str] = set()
        external: set[str] = set()

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            if href.startswith("http"):
                if self.base_url in href:
                    internal.add(href)
                else:
                    external.add(href)
            elif href.startswith("/"):
                internal.add(urljoin(self.base_url, href))

        return {
            "internal": sorted(internal)[:100],
            "external": sorted(external)[:100],
            "total_internal": len(internal),
            "total_external": len(external),
        }

    def _social_links(self, soup: BeautifulSoup) -> dict:
        found: dict[str, str] = {}
        for a in soup.find_all("a", href=True):
            href = a["href"]
            for name, domain in SOCIAL_PLATFORMS.items():
                if domain in href and name not in found:
                    found[name] = href
        return found

    def _images(self, soup: BeautifulSoup) -> list[str]:
        srcs: list[str] = []
        for img in soup.find_all("img", src=True):
            src = img["src"]
            if src.startswith("http"):
                srcs.append(src)
            elif src.startswith("/"):
                srcs.append(urljoin(self.base_url, src))
        return srcs[:50]

    # ── Technology Fingerprinting ────────────────────────────────────────────
    def _detect_tech(self, headers: httpx.Headers, html: str) -> list[str]:
        tech: list[str] = []

        # From HTTP response headers
        server = headers.get("server", "")
        if server:
            tech.append(f"Server: {server}")
            for name in ("Nginx", "Apache"):
                if name.lower() in server.lower():
                    tech.append(name)

        powered = headers.get("x-powered-by", "")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
            if "php" in powered.lower():
                tech.append("PHP")

        # From HTML body
        for name, signatures in TECH_SIGNATURES.items():
            if signatures and any(s in html for s in signatures):
                if name not in tech:
                    tech.append(name)

        return tech
