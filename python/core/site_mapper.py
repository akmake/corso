"""
Site Page Mapper
----------------
Discovers every reachable page on a domain by combining:
  1. BFS link crawl          — follow <a href> links
  2. Sitemap parsing         — sitemap.xml / sitemap_index.xml (recursive)
  3. robots.txt              — Disallow/Allow/Sitemap directives
  4. Wayback Machine CDX API — all URLs ever archived for this domain
  5. JS route extraction     — React Router / Vue / Angular / Express paths in JS bundles
  6. Wordlist fuzzing        — ~600 common paths probed with HEAD requests
  7. Status verification     — concurrent HEAD check on all discovered URLs
"""

import asyncio
import re
from collections import deque
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse, unquote

import httpx
from bs4 import BeautifulSoup

# ── Wordlist ──────────────────────────────────────────────────────────────────

WORDLIST: list[str] = [
    # Auth / User
    "/login", "/signin", "/sign-in", "/logout", "/register", "/signup", "/sign-up",
    "/auth", "/auth/login", "/auth/register", "/auth/logout",
    "/user", "/users", "/account", "/accounts", "/profile", "/profiles",
    "/me", "/my", "/dashboard", "/home", "/portal",
    "/forgot-password", "/reset-password", "/change-password",
    "/verify", "/verify-email", "/confirm", "/activate",
    "/settings", "/preferences", "/notifications",
    # Admin panels
    "/admin", "/admin/", "/administrator", "/administration",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-register.php",
    "/panel", "/cp", "/cpanel", "/controlpanel", "/control-panel",
    "/manage", "/management", "/manager", "/backend",
    "/cms", "/cms/admin", "/siteadmin", "/moderator",
    "/console", "/superadmin", "/root",
    # API / docs
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql", "/gql",
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui",
    "/swagger-ui.html", "/swagger-ui/",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/api/docs", "/api/swagger", "/api/schema", "/api/spec",
    "/docs", "/documentation", "/doc", "/developer",
    "/redoc", "/api-docs", "/api-explorer",
    # Config & secrets
    "/.env", "/.env.local", "/.env.development", "/.env.production", "/.env.staging",
    "/.env.example", "/.env.sample", "/.env.backup", "/.env.bak",
    "/config.json", "/config.yaml", "/config.yml", "/config.xml",
    "/configuration.json", "/settings.json", "/app.json",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile",
    "/.htaccess", "/.htpasswd", "/web.config", "/nginx.conf",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/server.js", "/app.js", "/index.js", "/main.js",
    # Health / monitoring
    "/health", "/healthcheck", "/health-check", "/health/check",
    "/ping", "/status", "/alive", "/ready", "/readiness", "/liveness",
    "/metrics", "/stats", "/statistics", "/monitor", "/monitoring",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/metrics",
    # Site info
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap.html",
    "/sitemap/", "/news-sitemap.xml", "/video-sitemap.xml", "/image-sitemap.xml",
    "/humans.txt", "/security.txt", "/.well-known/security.txt",
    "/.well-known/", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/manifest.json", "/manifest.webmanifest", "/browserconfig.xml",
    "/apple-app-site-association", "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    # CMS / WordPress
    "/wp-json", "/wp-json/wp/v2/pages", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/users",
    "/wp-content", "/wp-content/uploads", "/wp-includes",
    "/xmlrpc.php", "/wp-cron.php", "/wp-config.php.bak",
    "/wp-sitemap.xml",
    # Feeds
    "/feed", "/feed/", "/rss", "/rss.xml", "/rss2", "/rss2.xml",
    "/atom.xml", "/atom", "/feed.xml", "/feeds",
    # Common pages
    "/about", "/about-us", "/about_us", "/about/", "/our-story",
    "/contact", "/contact-us", "/contact_us", "/reach-us", "/get-in-touch",
    "/team", "/our-team", "/staff", "/people",
    "/help", "/faq", "/faqs", "/support", "/support/",
    "/privacy", "/privacy-policy", "/privacy_policy",
    "/terms", "/terms-of-service", "/terms-and-conditions", "/tos", "/eula", "/legal",
    "/cookies", "/cookie-policy",
    "/accessibility", "/sitemap",
    # Content
    "/blog", "/blog/", "/news", "/news/", "/articles", "/posts",
    "/press", "/press-room", "/media", "/media-kit",
    "/portfolio", "/work", "/projects", "/case-studies",
    "/gallery", "/photos", "/images",
    "/events", "/webinars", "/workshops",
    # Commercial
    "/products", "/product", "/shop", "/store", "/catalog", "/catalogue",
    "/services", "/service", "/solutions", "/offerings",
    "/pricing", "/plans", "/price", "/prices",
    "/cart", "/basket", "/checkout", "/order", "/orders", "/payment",
    "/subscriptions", "/subscribe", "/membership",
    # Careers
    "/careers", "/jobs", "/job", "/vacancies", "/hiring", "/work-with-us",
    "/join-us", "/join", "/apply",
    # Social / sharing
    "/share", "/sharing", "/social",
    # Dev / Debug
    "/test", "/tests", "/testing",
    "/dev", "/development", "/staging", "/beta", "/demo",
    "/debug", "/trace", "/logs", "/log",
    "/phpinfo.php", "/info.php", "/phpinfo", "/server-info", "/server-status",
    "/wp-config.php", "/php.ini",
    # Backups / old
    "/backup", "/backups", "/backup.zip", "/backup.sql", "/backup.tar.gz",
    "/database", "/db", "/db.sql", "/dump.sql",
    "/old", "/bak", "/tmp", "/temp", "/cache",
    "/archive", "/archives", "/history", "/changelog", "/CHANGELOG",
    # Static
    "/static", "/static/", "/assets", "/assets/", "/public", "/public/",
    "/uploads", "/uploads/", "/files", "/files/", "/media",
    "/css", "/js", "/scripts", "/fonts",
    # Search
    "/search", "/search/", "/find", "/query",
    # Maps / locations
    "/locations", "/stores", "/offices", "/map",
    # Mobile
    "/app", "/apps", "/mobile", "/download", "/downloads",
    # Misc
    "/error", "/404", "/500", "/403", "/maintenance", "/offline",
    "/launch", "/coming-soon", "/soon",
    "/partners", "/partnerships", "/affiliates", "/resellers",
    "/investors", "/investor-relations",
    "/community", "/forum", "/forums", "/board", "/discuss",
    "/wiki", "/kb", "/knowledge-base", "/knowledgebase",
    "/tutorials", "/guides", "/howto", "/how-to",
    "/newsletter", "/unsubscribe",
    "/sdk", "/api-keys", "/webhooks", "/integrations",
    "/report", "/reports", "/analytics", "/insights",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "he,en;q=0.9",
}

_JS_ROUTE_PATTERNS = [
    re.compile(r'(?:path|route|to|href|url)\s*[=:]\s*["\`](/[a-zA-Z0-9_/:\-.*?[\]{}]+)["\`]', re.I),
    re.compile(r'["\`](/(?:[a-zA-Z0-9_\-]+/)*[a-zA-Z0-9_\-]+)["\`]'),
    re.compile(r'Route[^>]*?path=["\`]([^"\'`]+)["\`]'),
    re.compile(r'children:\s*\[\s*\{[^}]*path:\s*["\`]([^"\'`]+)["\`]'),
    re.compile(r'router\.(?:get|post|put|delete|patch|use)\s*\(\s*["\`]([^"\'`]+)["\`]'),
    re.compile(r'app\.(?:get|post|put|delete|patch|use)\s*\(\s*["\`]([^"\'`]+)["\`]'),
    re.compile(r'@(?:Get|Post|Put|Delete|Patch)\s*\(\s*["\`]([^"\'`]+)["\`]'),  # NestJS
]

def _strip_frag(url: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))

def _normalize(url: str) -> str:
    return _strip_frag(url).rstrip("/") or url

def _is_same_origin(url: str, netloc: str) -> bool:
    return urlparse(url).netloc == netloc

def _is_html_url(url: str) -> bool:
    path = unquote(urlparse(url).path).lower().split("?")[0]
    skip_exts = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
        ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".flac",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".tar", ".gz", ".7z",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
        ".json", ".xml", ".txt",
    }
    ext = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    return ext not in skip_exts


# ── Discovery methods ─────────────────────────────────────────────────────────

async def _method_crawl(
    client: httpx.AsyncClient,
    origin: str,
    base_url: str,
    netloc: str,
    max_pages: int,
    log: Callable,
) -> set[str]:
    found: set[str] = set()
    visited: set[str] = set()
    queue: deque[str] = deque([base_url])

    while queue and len(visited) < max_pages:
        url = _normalize(queue.popleft())
        if url in visited:
            continue
        visited.add(url)
        if not _is_html_url(url):
            continue
        try:
            r = await client.get(url, timeout=12)
            ct = r.headers.get("content-type", "")
            if "text/html" not in ct:
                continue
            found.add(url)
            soup = BeautifulSoup(r.text, "lxml")
            for a in soup.find_all("a", href=True):
                raw = str(a["href"]).strip()
                if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                try:
                    full = _strip_frag(urljoin(url, raw))
                except Exception:
                    continue
                if full.startswith(("http://", "https://")) and _is_same_origin(full, netloc):
                    if _normalize(full) not in visited:
                        queue.append(full)
        except Exception:
            pass

        if len(visited) % 30 == 0:
            log(f"  [crawl] {len(visited)} דפים סרוקו | {len(found)} נמצאו")

    log(f"  [crawl] הושלם: {len(found)} דפים")
    return found


async def _method_sitemaps(
    client: httpx.AsyncClient,
    origin: str,
    log: Callable,
    extra_urls: list[str] | None = None,
) -> set[str]:
    found: set[str] = set()
    visited_sms: set[str] = set()
    queue: deque[str] = deque()

    seed_paths = [
        "/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml",
        "/sitemap1.xml", "/wp-sitemap.xml", "/news-sitemap.xml",
        "/post-sitemap.xml", "/page-sitemap.xml", "/video-sitemap.xml",
        "/image-sitemap.xml", "/sitemap-pages.xml", "/sitemap-posts.xml",
        "/sitemap.xml.gz",
    ]
    for p in seed_paths:
        queue.append(origin + p)
    if extra_urls:
        for u in extra_urls:
            queue.append(u)

    while queue:
        sm_url = queue.popleft()
        if sm_url in visited_sms:
            continue
        visited_sms.add(sm_url)
        try:
            r = await client.get(sm_url, timeout=10)
            if r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "")
            if "xml" not in ct and "text" not in ct:
                continue
            text = r.text
            # Sub-sitemaps
            for loc in re.findall(r"<sitemap>\s*<loc>([^<]+)</loc>", text, re.I):
                if loc.strip() not in visited_sms:
                    queue.append(loc.strip())
            # Page URLs
            for loc in re.findall(r"<url>\s*<loc>([^<]+)</loc>", text, re.I):
                found.add(_normalize(loc.strip()))
            # Plain <loc> (some sitemaps don't wrap in <url>)
            if not found:
                for loc in re.findall(r"<loc>([^<]+)</loc>", text):
                    found.add(_normalize(loc.strip()))
        except Exception:
            pass

    log(f"  [sitemap] {len(found)} URLs")
    return found


async def _method_robots(
    client: httpx.AsyncClient,
    origin: str,
    log: Callable,
) -> tuple[set[str], list[str]]:
    """Returns (paths_set, sitemap_urls)"""
    paths: set[str] = set()
    sitemaps: list[str] = []
    try:
        r = await client.get(f"{origin}/robots.txt", timeout=8)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("disallow:") or low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path not in ("*", "/") and not path.startswith("*"):
                        # Remove wildcards for discovery purposes
                        clean = path.split("*")[0].rstrip("$").strip()
                        if clean and clean.startswith("/"):
                            paths.add(origin + clean)
                elif low.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm.startswith("http"):
                        sitemaps.append(sm)
            log(f"  [robots.txt] {len(paths)} paths, {len(sitemaps)} sitemaps")
    except Exception:
        pass
    return paths, sitemaps


async def _method_wayback(
    client: httpx.AsyncClient,
    netloc: str,
    log: Callable,
    limit: int = 50000,
) -> set[str]:
    found: set[str] = set()
    try:
        log(f"  [wayback] שולח בקשה ל-Wayback Machine CDX API...")
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={netloc}/*"
            f"&output=json"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&limit={limit}"
            f"&filter=statuscode:200"
            f"&matchType=domain"
        )
        r = await client.get(url, timeout=60)
        if r.status_code == 200:
            rows = r.json()
            # First row is header ["original"]
            for row in rows[1:]:
                if row and isinstance(row[0], str):
                    u = _normalize(row[0])
                    if u.startswith(("http://", "https://")):
                        found.add(u)
            log(f"  [wayback] {len(found)} URLs מהארכיון")
    except Exception as e:
        log(f"  [wayback] שגיאה: {e}")
    return found


async def _method_js_routes(
    client: httpx.AsyncClient,
    origin: str,
    netloc: str,
    base_url: str,
    log: Callable,
) -> set[str]:
    found: set[str] = set()
    js_urls: set[str] = set()

    # Get homepage and collect JS file references
    try:
        r = await client.get(base_url, timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "lxml")
            for tag in soup.find_all("script", src=True):
                src = urljoin(base_url, str(tag["src"]))
                if _is_same_origin(src, netloc) or any(cdn in src for cdn in []):
                    js_urls.add(src)
    except Exception:
        pass

    # Download and parse each JS file
    tasks = []
    for js_url in list(js_urls)[:30]:  # limit to first 30 JS files
        tasks.append(_extract_routes_from_js(client, js_url, origin))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, set):
            found |= res

    log(f"  [js-routes] {len(js_urls)} JS files → {len(found)} routes")
    return found


async def _extract_routes_from_js(
    client: httpx.AsyncClient,
    js_url: str,
    origin: str,
) -> set[str]:
    found: set[str] = set()
    try:
        r = await client.get(js_url, timeout=15)
        if r.status_code != 200:
            return found
        text = r.text

        for pattern in _JS_ROUTE_PATTERNS:
            for m in pattern.finditer(text):
                path = m.group(1).strip()
                # Filter: must look like a real path
                if not path.startswith("/"):
                    continue
                if len(path) > 200:
                    continue
                # Skip obvious non-routes
                if any(c in path for c in [" ", "\n", "{{"]):
                    continue
                # Remove dynamic segments for static probing
                static = re.sub(r"[/:][a-zA-Z_$][a-zA-Z0-9_$]*(?=(/|$))", "", path)
                static = re.sub(r"\?.*$", "", static).rstrip("/*")
                if static and static.startswith("/") and len(static) > 1:
                    found.add(origin + static)
                # Also add the raw path as-is if no params
                if ":" not in path and "*" not in path and "?" not in path:
                    found.add(origin + path.rstrip("/"))
    except Exception:
        pass
    return found


async def _method_wordlist(
    client: httpx.AsyncClient,
    origin: str,
    log: Callable,
    concurrency: int = 30,
) -> set[str]:
    found: set[str] = set()
    sem = asyncio.Semaphore(concurrency)

    async def probe(path: str):
        async with sem:
            url = origin + path
            try:
                r = await client.head(url, timeout=6)
                if r.status_code in (200, 201, 301, 302, 307, 308, 403):
                    found.add(url)
            except Exception:
                pass

    await asyncio.gather(*[probe(p) for p in WORDLIST])
    log(f"  [wordlist] {len(found)} hits מתוך {len(WORDLIST)} paths")
    return found


async def _verify_status(
    client: httpx.AsyncClient,
    urls: set[str],
    log: Callable,
    concurrency: int = 40,
) -> list[dict]:
    results: list[dict] = []
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def check(url: str):
        nonlocal done
        async with sem:
            status = 0
            try:
                r = await client.head(url, timeout=8, follow_redirects=True)
                status = r.status_code
            except Exception:
                pass
            done += 1
            if done % 100 == 0:
                log(f"  [verify] {done}/{len(urls)} בדוקות...")
            return {"url": url, "status": status}

    tasks = [check(u) for u in urls]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    for item in raw:
        if isinstance(item, dict):
            results.append(item)

    return results


# ── Main entry point ──────────────────────────────────────────────────────────

async def map_site(
    base_url: str,
    log: Callable[[str], None],
    max_crawl_pages: int = 200,
    use_wayback: bool = True,
    use_wordlist: bool = True,
    use_js_routes: bool = True,
    verify_all: bool = True,
) -> dict:
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    netloc = parsed.netloc

    log(f"מתחיל מיפוי: {base_url}")

    all_urls: set[str] = set()
    sources: dict[str, set[str]] = {
        "crawl": set(),
        "sitemap": set(),
        "robots": set(),
        "wayback": set(),
        "js_routes": set(),
        "wordlist": set(),
    }

    async with httpx.AsyncClient(
        headers=HEADERS,
        follow_redirects=True,
        timeout=20,
        verify=False,
    ) as client:

        # 1. robots.txt (fast, run first to get sitemap URLs)
        log("שלב 1/6: robots.txt...")
        robots_paths, sitemap_urls = await _method_robots(client, origin, log)
        sources["robots"] = robots_paths
        all_urls |= robots_paths

        # 2. Sitemaps
        log("שלב 2/6: Sitemaps...")
        sitemap_urls_found = await _method_sitemaps(client, origin, log, sitemap_urls)
        # Filter to same domain
        sitemap_filtered = {u for u in sitemap_urls_found if _is_same_origin(u, netloc)}
        sources["sitemap"] = sitemap_filtered
        all_urls |= sitemap_filtered

        # 3. Wayback Machine
        if use_wayback:
            log("שלב 3/6: Wayback Machine CDX (עשוי לקחת זמן)...")
            wb = await _method_wayback(client, netloc, log)
            wb_filtered = {u for u in wb if _is_same_origin(u, netloc)}
            sources["wayback"] = wb_filtered
            all_urls |= wb_filtered
        else:
            log("שלב 3/6: Wayback Machine — מדולג")

        # 4. BFS crawl
        log(f"שלב 4/6: BFS Crawl (עד {max_crawl_pages} דפים)...")
        crawled = await _method_crawl(client, origin, base_url, netloc, max_crawl_pages, log)
        sources["crawl"] = crawled
        all_urls |= crawled

        # 5. JS route extraction
        if use_js_routes:
            log("שלב 5/6: JS Routes...")
            js = await _method_js_routes(client, origin, netloc, base_url, log)
            js_filtered = {u for u in js if _is_same_origin(u, netloc)}
            sources["js_routes"] = js_filtered
            all_urls |= js_filtered
        else:
            log("שלב 5/6: JS Routes — מדולג")

        # 6. Wordlist fuzzing
        if use_wordlist:
            log(f"שלב 6/6: Wordlist fuzzing ({len(WORDLIST)} paths)...")
            wl = await _method_wordlist(client, origin, log)
            sources["wordlist"] = wl
            all_urls |= wl
        else:
            log("שלב 6/6: Wordlist — מדולג")

        log(f"סה\"כ לפני בדיקה: {len(all_urls)} URLs ייחודיים")

        # 7. Verify status
        if verify_all and all_urls:
            log(f"בודק סטטוס {len(all_urls)} URLs...")
            verified = await _verify_status(client, all_urls, log)
        else:
            verified = [{"url": u, "status": 0} for u in all_urls]

    # Build final result with per-URL source tags
    url_to_sources: dict[str, list[str]] = {}
    for src_name, url_set in sources.items():
        for u in url_set:
            url_to_sources.setdefault(_normalize(u), []).append(src_name)

    pages: list[dict] = []
    for item in verified:
        url = _normalize(item["url"])
        status = item["status"]
        srcs = url_to_sources.get(url, ["unknown"])
        pages.append({"url": url, "status": status, "sources": srcs})

    # Sort: alive first, then alphabetically
    pages.sort(key=lambda x: (0 if x["status"] in (200, 201, 301, 302, 403) else 1, x["url"]))

    alive = [p for p in pages if p["status"] in (200, 201, 301, 302, 307, 308, 403)]
    dead  = [p for p in pages if p not in alive]

    log(f"הושלם! {len(alive)} דפים חיים, {len(dead)} לא מגיבים")

    return {
        "site":    base_url,
        "total":   len(pages),
        "alive":   len(alive),
        "pages":   pages,
        "by_source": {k: len(v) for k, v in sources.items()},
    }
