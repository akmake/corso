"""
Site Asset Downloader
---------------------
Crawls an entire website and downloads every discoverable file.

Phase 1 — Discovery: BFS crawl, extract file URLs from:
  <a>, <img>, <source>, <video>, <audio>, <link>, <script>,
  srcset, data-src, data-href, inline CSS url(), JS strings,
  Open Graph meta tags, sitemap.xml

Phase 2 — Download: stream each file to disk, yt-dlp for HLS/DASH

Categories:
  video:     mp4 webm mkv avi mov wmv flv m4v ts ogv
  streaming: m3u8 m3u mpd  (→ yt-dlp)
  audio:     mp3 wav ogg flac aac m4a wma opus
  document:  pdf doc docx xls xlsx ppt pptx odt ods csv txt rtf
  archive:   zip rar 7z tar gz bz2
  image:     jpg jpeg png gif webp bmp tiff svg ico
  data:      json xml sql sqlite yaml yml
"""

import asyncio
import re
import zipfile
from collections import deque
from io import BytesIO
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse, unquote

import httpx
from bs4 import BeautifulSoup
from bs4.element import Comment

CRAWL_DIR = Path(__file__).parent.parent / "downloads" / "crawl"
CRAWL_DIR.mkdir(parents=True, exist_ok=True)

# ── File type catalogue ──────────────────────────────────────────────────────

FILE_CATS: dict[str, set[str]] = {
    "video":     {".mp4", ".webm", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".m4v", ".ts", ".ogv", ".3gp"},
    "streaming": {".m3u8", ".m3u", ".mpd"},
    "audio":     {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma", ".opus"},
    "document":  {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                  ".odt", ".ods", ".odp", ".rtf", ".csv", ".txt"},
    "archive":   {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"},
    "image":     {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".ico"},
    "data":      {".json", ".xml", ".sql", ".sqlite", ".db", ".yaml", ".yml"},
}

_ALL_EXT = {ext for exts in FILE_CATS.values() for ext in exts}

_MIME_MAP = [
    ("video/",                   "video"),
    ("audio/",                   "audio"),
    ("image/",                   "image"),
    ("application/pdf",          "document"),
    ("application/msword",       "document"),
    ("application/vnd.openxmlformats", "document"),
    ("application/vnd.ms-",      "document"),
    ("application/zip",          "archive"),
    ("application/x-rar",        "archive"),
    ("application/x-7z",         "archive"),
    ("application/json",         "data"),
    ("application/xml",          "data"),
    ("text/xml",                 "data"),
    ("text/csv",                 "document"),
]

CAT_EMOJI = {
    "video": "🎬", "streaming": "📡", "audio": "🎵",
    "document": "📄", "archive": "📦", "image": "🖼️", "data": "🗂️",
}

# ── Intel helpers ────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}')
_PHONE_RE = re.compile(
    r'(?:(?:\+|00)972|0)[\s\-]?[1-9]\d[\s\-]?\d{3}[\s\-]?\d{4}'   # Israeli
    r'|\+[1-9]\d{5,13}'                                               # International E.164
)
_SOCIAL_DOMAINS = frozenset({
    "facebook.com", "fb.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "youtube.com", "youtu.be", "tiktok.com",
    "telegram.me", "t.me", "whatsapp.com", "wa.me",
    "github.com", "reddit.com", "pinterest.com", "snapchat.com",
})


def _valid_email(e: str) -> bool:
    if "@" not in e:
        return False
    ext = e.rsplit(".", 1)[-1].lower()
    return ext not in {"png", "jpg", "gif", "css", "js", "svg", "ico", "webp", "mp4", "pdf", "zip", "rar"}


HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "he,en;q=0.9",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _cat_by_ext(url: str) -> str | None:
    path = unquote(urlparse(url).path).split("?")[0]
    ext = Path(path).suffix.lower()
    for cat, exts in FILE_CATS.items():
        if ext in exts:
            return cat
    return None


def _cat_by_mime(mime: str) -> str | None:
    mime = mime.split(";")[0].strip().lower()
    for prefix, cat in _MIME_MAP:
        if mime.startswith(prefix):
            return cat
    return None


def _safe_name(url: str, index: int) -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name or f"file_{index}"
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    return name or f"file_{index}"


def _strip_frag(url: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))


# ── Main crawler + downloader ─────────────────────────────────────────────────

async def crawl_and_download(
    base_url: str,
    log: Callable[[str], None],
    max_pages: int = 300,
    categories: set[str] | None = None,
    include_images: bool = False,
    size_limit_mb: float = 500,
) -> dict:
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    base_url = _strip_frag(base_url)
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"

    if categories is None:
        categories = {"video", "streaming", "audio", "document", "archive", "data"}
    if include_images:
        categories.add("image")

    # Per-site output directory
    site_key = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.netloc)
    out_dir  = CRAWL_DIR / site_key
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"🌐 מתחיל סריקת {base_url}")

    page_visited: set[str] = set()
    file_found:   dict[str, str] = {}   # url → category
    queue: deque[str] = deque()

    # Intel collections
    emails_found:   set[str]   = set()
    phones_found:   set[str]   = set()
    links_internal: set[str]   = set()
    links_external: set[str]   = set()
    scripts_found:  set[str]   = set()
    comments_found: list[dict] = []
    social_found:   set[str]   = set()
    page_metadata:  list[dict] = []
    forms_found:    list[dict] = []
    api_endpoints:  set[str]   = set()

    async with httpx.AsyncClient(
        headers=HEADERS,
        follow_redirects=True,
        timeout=20,
        verify=False,
    ) as client:

        # ── Seed: sitemap.xml ────────────────────────────────────────────────
        for sm_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"]:
            try:
                r = await client.get(origin + sm_path, timeout=8)
                if r.status_code == 200 and "xml" in r.headers.get("content-type", ""):
                    locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
                    for loc in locs:
                        loc = loc.strip()
                        if loc.startswith(origin):
                            queue.append(loc)
                    if locs:
                        log(f"📋 sitemap.xml: {len(locs)} כתובות")
                        break
            except Exception:
                pass

        queue.appendleft(base_url)

        # ── BFS crawl ────────────────────────────────────────────────────────
        pages_done = 0

        def _enqueue(raw: str, context_url: str):
            if not raw or raw.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
                return
            try:
                full = _strip_frag(urljoin(context_url, raw.strip()))
            except Exception:
                return
            if not full.startswith(("http://", "https://")):
                return

            cat = _cat_by_ext(full)
            if cat:
                if full not in file_found:
                    file_found[full] = cat
                return

            # Only crawl same origin
            if urlparse(full).netloc == parsed.netloc and full not in page_visited:
                queue.append(full)

        while queue and pages_done < max_pages:
            url = _strip_frag(queue.popleft())
            if url in page_visited:
                continue
            page_visited.add(url)

            # Is this URL itself a file?
            cat = _cat_by_ext(url)
            if cat:
                file_found[url] = cat
                continue

            try:
                r = await client.get(url, timeout=15)
            except Exception:
                continue

            # File served at this URL?
            ct = r.headers.get("content-type", "").split(";")[0].strip()
            mime_cat = _cat_by_mime(ct)
            if mime_cat:
                file_found[url] = mime_cat
                continue

            if "text/html" not in ct:
                continue

            pages_done += 1
            if pages_done % 20 == 0 or pages_done <= 3:
                log(f"🔍 [{pages_done}/{max_pages}] {url[:70]}  |  קבצים: {len(file_found)}")

            html = r.text
            soup = BeautifulSoup(html, "lxml")

            # All tag attributes
            ASSET_ATTRS = ("href", "src", "data-src", "data-href", "data-url",
                           "data-original", "data-lazy", "data-lazy-src",
                           "poster", "action", "content", "data-file", "data-download")
            for tag in soup.find_all(True):
                for attr in ASSET_ATTRS:
                    val = tag.get(attr)
                    if isinstance(val, str):
                        _enqueue(val, url)
                    elif isinstance(val, list):
                        for v in val:
                            if isinstance(v, str):
                                _enqueue(v, url)

            # srcset="url1 1x, url2 2x"
            for tag in soup.find_all(srcset=True):
                for part in str(tag["srcset"]).split(","):
                    _enqueue(part.strip().split()[0], url)

            # CSS url() in inline styles and <style> blocks
            for m in re.finditer(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', html):
                _enqueue(m.group(1), url)

            # Open Graph / Twitter card
            for meta in soup.find_all("meta"):
                prop = (meta.get("property") or meta.get("name") or "").lower()
                if any(k in prop for k in ("image", "video", "audio", "url")):
                    _enqueue(meta.get("content", ""), url)

            # JS strings that look like file URLs
            for script in soup.find_all("script"):
                text = script.string or ""
                # Absolute URLs with known extension
                for m in re.finditer(r'["\`](https?://[^"\'`<>\s]{10,400})["\`]', text):
                    _enqueue(m.group(1), url)
                # Relative paths with extension
                for m in re.finditer(r'["\`](/[a-zA-Z0-9_./-]{3,200}\.[a-zA-Z0-9]{2,5})["\`]', text):
                    _enqueue(m.group(1), url)

            # ── Intel extraction ─────────────────────────────────────────────

            # Emails in full HTML text
            for em in _EMAIL_RE.findall(html):
                if _valid_email(em.lower()):
                    emails_found.add(em.lower())

            # Phone numbers
            for ph in _PHONE_RE.findall(html):
                ph_clean = re.sub(r'[^+\d]', '', ph)
                if 7 <= len(ph_clean) <= 16:
                    phones_found.add(ph_clean)

            # Links + mailto/tel + social detection
            for a_tag in soup.find_all("a", href=True):
                raw_href = str(a_tag["href"]).strip()
                if raw_href.startswith("mailto:"):
                    em = raw_href[7:].split("?")[0].strip().lower()
                    if em and _valid_email(em):
                        emails_found.add(em)
                    continue
                if raw_href.startswith("tel:"):
                    ph = re.sub(r'[^+\d]', '', raw_href[4:])
                    if 7 <= len(ph) <= 16:
                        phones_found.add(ph)
                    continue
                try:
                    full_link = _strip_frag(urljoin(url, raw_href))
                except Exception:
                    continue
                if not full_link.startswith(("http://", "https://")):
                    continue
                link_host = urlparse(full_link).netloc
                if link_host == parsed.netloc:
                    links_internal.add(full_link)
                else:
                    links_external.add(full_link)
                    for sd in _SOCIAL_DOMAINS:
                        if link_host == sd or link_host.endswith("." + sd):
                            social_found.add(full_link)
                            break

            # Scripts & stylesheets
            for tag in soup.find_all("script", src=True):
                try:
                    s = _strip_frag(urljoin(url, str(tag["src"])))
                    if s.startswith(("http://", "https://")):
                        scripts_found.add(s)
                except Exception:
                    pass
            for tag in soup.find_all("link", rel=True):
                if "stylesheet" in " ".join(tag.get("rel", [])).lower():
                    try:
                        s = _strip_frag(urljoin(url, str(tag.get("href", ""))))
                        if s.startswith(("http://", "https://")):
                            scripts_found.add(s)
                    except Exception:
                        pass

            # HTML comments
            if len(comments_found) < 200:
                for cmt in soup.find_all(string=lambda t: isinstance(t, Comment)):
                    c = str(cmt).strip()
                    if 10 < len(c) < 2000:
                        comments_found.append({"url": url, "text": c})
                        if len(comments_found) >= 200:
                            break

            # Forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                try:
                    action_full = _strip_frag(urljoin(url, action)) if action else url
                except Exception:
                    action_full = url
                method = str(form.get("method", "get")).upper()
                fields = [str(inp.get("name", "")) for inp in form.find_all("input") if inp.get("name")]
                forms_found.append({"page": url, "action": action_full, "method": method, "fields": fields[:20]})

            # API endpoints in inline scripts
            for script in soup.find_all("script"):
                stext = script.string or ""
                for m in re.finditer(r'["\`](/(?:api|v\d+|graphql|rest|endpoint|webhook)[^"\'`<>\s]{0,150})["\`]', stext, re.I):
                    try:
                        api_endpoints.add(_strip_frag(urljoin(url, m.group(1))))
                    except Exception:
                        pass
                for m in re.finditer(r'["\`](https?://[^"\'`<>\s]*(?:/api/|/v\d+/|/graphql|/rest/)[^"\'`<>\s]{0,150})["\`]', stext, re.I):
                    api_endpoints.add(m.group(1))

            # Page metadata
            if len(page_metadata) < 100:
                title = soup.title.string.strip() if soup.title and soup.title.string else ""
                desc = keywords = og_title = og_desc = og_img = ""
                for meta in soup.find_all("meta"):
                    n = (meta.get("name") or meta.get("property") or "").lower()
                    c = str(meta.get("content", ""))
                    if n == "description":      desc     = c
                    elif n == "keywords":       keywords = c
                    elif n == "og:title":       og_title = c
                    elif n == "og:description": og_desc  = c
                    elif n == "og:image":       og_img   = c
                if any([title, desc, keywords, og_title]):
                    page_metadata.append({
                        "url": url, "title": title, "description": desc,
                        "keywords": keywords, "og_title": og_title,
                        "og_description": og_desc, "og_image": og_img,
                    })

        log(f"✅ סריקה הושלמה: {pages_done} דפים | {len(file_found)} קבצים")

        # ── Phase 2: Download ─────────────────────────────────────────────────
        to_dl = {u: c for u, c in file_found.items() if c in categories}
        log(f"⬇️  מוריד {len(to_dl)} קבצים (מתוך {len(file_found)} שנמצאו)...")

        downloaded: list[dict] = []
        errors:     list[str]  = []
        names_used: set[str]   = set()

        def _unique_name(base: str) -> str:
            candidate = base
            stem = Path(base).stem
            ext  = Path(base).suffix
            n = 1
            while candidate in names_used:
                candidate = f"{stem}_{n}{ext}"
                n += 1
            names_used.add(candidate)
            return candidate

        for idx, (file_url, cat) in enumerate(to_dl.items(), 1):
            try:
                # HLS / DASH streaming — delegate to yt-dlp
                if cat == "streaming":
                    try:
                        from yt_dlp import YoutubeDL
                        fname = _unique_name(f"stream_{idx}.mp4")
                        fpath = out_dir / fname
                        opts  = {
                            "outtmpl":      str(fpath),
                            "quiet":        True,
                            "no_warnings":  True,
                            "merge_output_format": "mp4",
                        }
                        loop = asyncio.get_running_loop()
                        await asyncio.wait_for(
                            loop.run_in_executor(None, lambda o=opts, u=file_url: YoutubeDL(o).download([u])),
                            timeout=600,
                        )
                        if fpath.exists():
                            size_mb = round(fpath.stat().st_size / (1024 * 1024), 2)
                            log(f"  ✅ [{idx}/{len(to_dl)}] {fname} ({size_mb} MB) [stream]")
                            downloaded.append({"url": file_url, "type": cat, "filename": fname, "size_mb": size_mb})
                    except Exception as e:
                        errors.append(f"stream {file_url[:70]}: {e}")
                    continue

                # HEAD check for file size
                try:
                    head = await client.head(file_url, timeout=6)
                    size_b = int(head.headers.get("content-length", 0))
                except Exception:
                    size_b = 0

                if size_b and size_b / (1024 * 1024) > size_limit_mb:
                    log(f"  ⏩ [{idx}] SKIP גדול מדי ({size_b//(1024*1024)} MB): {file_url[:60]}")
                    continue

                fname = _unique_name(_safe_name(file_url, idx))
                fpath = out_dir / fname

                # Skip already downloaded
                if fpath.exists() and fpath.stat().st_size > 0:
                    size_mb = round(fpath.stat().st_size / (1024 * 1024), 2)
                    log(f"  ♻️  [{idx}] קיים: {fname}")
                    downloaded.append({"url": file_url, "type": cat, "filename": fname, "size_mb": size_mb})
                    continue

                # Stream to disk
                async with client.stream("GET", file_url, timeout=120) as resp:
                    if resp.status_code not in (200, 206):
                        continue
                    # Re-determine category from actual Content-Type
                    resp_ct  = resp.headers.get("content-type", "").split(";")[0].strip()
                    resp_cat = _cat_by_mime(resp_ct) or cat

                    total    = int(resp.headers.get("content-length", 0))
                    written  = 0
                    with open(fpath, "wb") as fp:
                        async for chunk in resp.aiter_bytes(65536):
                            fp.write(chunk)
                            written += len(chunk)
                            # Abort if exceeds limit mid-stream
                            if written > size_limit_mb * 1024 * 1024:
                                break

                size_mb = round(fpath.stat().st_size / (1024 * 1024), 2)
                emoji   = CAT_EMOJI.get(resp_cat, "📁")
                log(f"  {emoji} [{idx}/{len(to_dl)}] {fname}  ({size_mb} MB)  [{resp_cat}]")
                downloaded.append({"url": file_url, "type": resp_cat, "filename": fname, "size_mb": size_mb})

                await asyncio.sleep(0.05)   # polite delay

            except Exception as e:
                msg = f"{file_url[:80]}: {str(e)[:80]}"
                errors.append(msg)

        log(f"🎉 הושלם! {len(downloaded)}/{len(to_dl)} קבצים הורדו לתיקייה: {out_dir}")

        cat_summary = {}
        for f in downloaded:
            cat_summary[f["type"]] = cat_summary.get(f["type"], 0) + 1

        return {
            "site":             base_url,
            "pages_crawled":    pages_done,
            "files_found":      len(file_found),
            "files_downloaded": len(downloaded),
            "download_dir":     str(out_dir),
            "categories":       cat_summary,
            "files":            downloaded,
            "all_found": [
                {"url": u, "type": c, "filename": _safe_name(u, i)}
                for i, (u, c) in enumerate(file_found.items())
            ],
            "errors": errors[:30],
            "intel": {
                "emails":         sorted(emails_found),
                "phones":         sorted(phones_found),
                "links_internal": sorted(links_internal)[:1000],
                "links_external": sorted(links_external)[:500],
                "scripts":        sorted(scripts_found)[:300],
                "social":         sorted(social_found),
                "comments":       comments_found[:100],
                "metadata":       page_metadata,
                "forms":          forms_found[:50],
                "api_endpoints":  sorted(api_endpoints)[:200],
            },
        }


# ── ZIP builder ───────────────────────────────────────────────────────────────

def build_zip(site_key: str) -> bytes | None:
    """Pack all downloaded files for a site into a ZIP in memory."""
    out_dir = CRAWL_DIR / re.sub(r"[^a-zA-Z0-9._-]", "_", site_key)
    if not out_dir.exists():
        return None
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in out_dir.iterdir():
            if f.is_file():
                zf.write(f, f.name)
    buf.seek(0)
    return buf.read()
