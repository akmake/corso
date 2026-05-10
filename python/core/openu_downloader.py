"""
Open University (OPAL) PDF Downloader
--------------------------------------
Step 1  login_and_get_courses:
    Logs in via SSO (username / password / id_number),
    returns the course list + full Playwright cookies.

Step 2  download_course_pdfs:
    Uses httpx (with the saved session cookies) to:
      1. Fetch the course page HTML (all content is server-rendered, no JS needed)
      2. Find every  bookview.php?bookid=XXXX  link  →  those are the PDFs
         URL pattern:  /mod/combopage/item/book/bookview.php?bookid=<ID>&combopage=bookNewTab
      3. Download each URL  →  the server returns application/pdf directly
      4. Name each file from the Content-Disposition header (or the link text)
      5. Save to  downloads/openu/<course_number>/
"""

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable


OPENU_DOWNLOADS_DIR = Path(__file__).parent.parent / "downloads" / "openu"
OPENU_DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

_executor = ThreadPoolExecutor(max_workers=1)

SSO_URL   = "https://sso.apps.openu.ac.il/login"
OPAL_BASE = "https://opal.openu.ac.il"

_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox", "--disable-setuid-sandbox",
    "--disable-dev-shm-usage", "--disable-gpu",
    "--window-size=1920,1080",
]

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36")


def _safe_filename(text: str, max_len: int = 80) -> str:
    """Strip illegal chars, limit length — result is safe on Windows."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text).strip(". ")
    return name[:max_len] if name else "file"


# ─────────────────────────────────────────────────────────────────────────────
# Step 1  Login + course list
# ─────────────────────────────────────────────────────────────────────────────

def _run_login_sync(username: str, password: str, id_number: str, log: Callable) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    log("פותח דפדפן...")
    login_url = (
        f"{SSO_URL}?T_PLACE={OPAL_BASE}/auth/ouilsso/redirect2.php"
        f"?urltogo={OPAL_BASE}/"
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx  = browser.new_context(user_agent=_UA, ignore_https_errors=True,
                                   viewport={"width": 1920, "height": 1080})
        page = ctx.new_page()

        try:
            page.goto(login_url, timeout=30_000, wait_until="domcontentloaded")
        except Exception as e:
            browser.close()
            return {"error": f"לא ניתן לפתוח דף כניסה: {e}"}

        log(f"דף כניסה: {page.url}")

        # Collect all visible non-hidden inputs
        try:
            all_inputs = page.locator(
                'input:not([type="hidden"]):not([type="submit"]):not([type="button"])'
            ).all()
            visible = [i for i in all_inputs if i.is_visible()]

            if len(visible) < 2:
                browser.close()
                return {"error": "לא נמצאו שדות כניסה"}

            # username = first text input
            visible[0].fill(username)
            log("מילא שם משתמש")

            # password = first type=password input
            pw = next((i for i in visible if i.get_attribute("type") == "password"), visible[1])
            pw.fill(password)
            log("מילא סיסמה")

            # id_number = second text input (not password)
            text_inputs = [i for i in visible if i.get_attribute("type") != "password"]
            if len(text_inputs) >= 2:
                text_inputs[1].fill(id_number)
                log("מילא מספר זהות")
        except Exception as e:
            browser.close()
            return {"error": f"שגיאה במילוי טופס: {e}"}

        try:
            page.locator('button[type="submit"], input[type="submit"]').first.click()
            log("לחץ על כניסה")
        except Exception as e:
            browser.close()
            return {"error": f"לא נמצא כפתור כניסה: {e}"}

        try:
            page.wait_for_url(f"{OPAL_BASE}/**", timeout=25_000)
        except PWTimeout:
            if "login" in page.url or "sso" in page.url:
                err = ""
                for sel in ['[class*="error"]', ".alert", "#error"]:
                    try:
                        t = page.locator(sel).first.text_content(timeout=1500) or ""
                        if t.strip():
                            err = t.strip(); break
                    except Exception:
                        pass
                browser.close()
                return {"error": f"כניסה נכשלה. {err}"}

        log(f"הכניסה הצליחה: {page.url}")

        try:
            page.goto(f"{OPAL_BASE}/my/", timeout=20_000, wait_until="domcontentloaded")
        except Exception:
            pass

        log("מחלץ קורסים...")
        courses, seen = [], set()
        try:
            links = page.eval_on_selector_all(
                "a[href*='/course/view.php']",
                "els => els.map(e => ({href: e.href, text: e.textContent.trim()}))"
            )
            for lnk in links:
                href, text = lnk.get("href", ""), lnk.get("text", "").strip()
                m = re.search(r"id=(\d+)", href)
                if not m or not text or m.group(1) in seen:
                    continue
                cid = m.group(1)
                seen.add(cid)
                num = re.search(r"\((\d{4,6})\)", text) or re.search(r"(\d{4,6})", text)
                courses.append({"id": cid, "number": num.group(1) if num else cid,
                                "name": text, "url": href})
        except Exception as e:
            log(f"שגיאת חילוץ קורסים: {e}")

        log(f"נמצאו {len(courses)} קורסים")
        cookies_list = ctx.cookies()
        browser.close()

    if not courses:
        return {"error": "לא נמצאו קורסים — בדוק פרטי כניסה"}
    return {"courses": courses, "cookies_list": cookies_list}


async def login_and_get_courses(username: str, password: str, id_number: str, log: Callable) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_login_sync, username, password, id_number, log)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2  Download PDFs for one course
# ─────────────────────────────────────────────────────────────────────────────

def _run_course_download_sync(
    course_url: str, course_name: str, course_number: str,
    cookies_list: list, log: Callable,
) -> dict:
    from bs4 import BeautifulSoup
    import httpx

    # Folder = course number only (ASCII, short, no Windows path issues)
    folder_name = course_number if course_number else re.sub(r"\D", "", course_url)[-6:] or "course"
    out_dir = OPENU_DOWNLOADS_DIR / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"קורס: {course_name}  |  תיקייה: {out_dir}")

    cookies_dict = {c["name"]: c["value"] for c in cookies_list}
    headers = {"User-Agent": _UA, "Referer": OPAL_BASE}

    # ── 1. Use Playwright to render the course page (JS-heavy Moodle) ──────────
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    log("פותח דפדפן לרינדור דף הקורס...")
    all_html_pages: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = browser.new_context(user_agent=_UA, ignore_https_errors=True,
                                  viewport={"width": 1920, "height": 1080})
        ctx.add_cookies(cookies_list)
        page = ctx.new_page()

        visited_pages: set[str] = set()
        page_queue: list[str] = [course_url]

        while page_queue:
            purl = page_queue.pop(0)
            if purl in visited_pages:
                continue
            visited_pages.add(purl)

            try:
                page.goto(purl, timeout=25_000, wait_until="networkidle")
            except PWTimeout:
                try:
                    page.wait_for_timeout(2000)
                except Exception:
                    pass
            except Exception as e:
                log(f"  שגיאה: {e}")
                continue

            # Expand any collapsed sections (Moodle accordion)
            try:
                toggles = page.locator(
                    "[data-toggle='collapse'], .section-toggle, "
                    "a[aria-expanded='false'], button[aria-expanded='false']"
                ).all()
                for t in toggles:
                    try:
                        t.click(timeout=800)
                    except Exception:
                        pass
                if toggles:
                    page.wait_for_timeout(600)
            except Exception:
                pass

            html = page.content()
            all_html_pages.append(html)
            log(f"  נסרק: {purl[:70]}")

            # Follow section sub-pages  /course/view.php?id=X&section=N
            for m in re.finditer(
                r'href=["\'](' + re.escape(OPAL_BASE) +
                r'/course/view\.php\?[^"\']*)["\']', html
            ):
                link = m.group(1).split("#")[0]
                if link not in visited_pages and link != course_url:
                    page_queue.append(link)

        browser.close()

    log(f"נסרקו {len(all_html_pages)} דפי קורס — מחפש חוברות PDF...")

    with httpx.Client(cookies=cookies_dict, headers=headers,
                      follow_redirects=True, timeout=30, verify=False) as client:

        # ── 2. Find all bookview links ────────────────────────────────────────
        # key = bookid, value = title from link text
        books: dict[str, str] = {}

        for html in all_html_pages:
            soup = BeautifulSoup(html, "lxml")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                m = re.search(r"bookid=(\d+)", href)
                if not m:
                    continue
                bookid = m.group(1)
                if bookid in books:
                    continue
                # Title: prefer the link's own text, fall back to nearby heading
                title = a.get_text(separator=" ", strip=True)
                if not title:
                    # look for closest parent with meaningful text
                    for parent in a.parents:
                        t = parent.get_text(separator=" ", strip=True)
                        if t and len(t) < 120:
                            title = t
                            break
                books[bookid] = title or f"book_{bookid}"

        log(f"נמצאו {len(books)} חוברות PDF")

        if not books:
            return {
                "course_name": course_name, "course_number": course_number,
                "pages_crawled": len(all_html_pages), "pdfs_found": 0,
                "pdfs_downloaded": 0, "download_dir": str(out_dir),
                "files": [], "errors": ["לא נמצאו חוברות בדף הקורס"],
            }

        # ── 3. Download ───────────────────────────────────────────────────────
        downloaded: list[dict] = []
        errors:     list[str]  = []
        names_used: set[str]   = set()

        def _unique(name: str) -> str:
            stem, ext = name[:-4], ".pdf"
            candidate = name
            n = 1
            while candidate in names_used:
                candidate = f"{stem}_{n}{ext}"
                n += 1
            names_used.add(candidate)
            return candidate

        for idx, (bookid, title) in enumerate(books.items(), 1):
            viewer_url = (
                f"{OPAL_BASE}/mod/combopage/item/book/bookview.php"
                f"?bookid={bookid}&combopage=bookNewTab"
            )
            try:
                from urllib.parse import unquote, urljoin

                # ── Resolve the real PDF URL ──────────────────────────────────
                # bookview.php may return:
                #   (a) application/pdf directly  → download as-is
                #   (b) HTML page with the PDF embedded in an <iframe>/<embed>
                resp = client.get(viewer_url, timeout=30)
                ct   = resp.headers.get("content-type", "")

                if "application/pdf" in ct or "octet-stream" in ct:
                    # Case (a) — direct PDF
                    actual_pdf_url  = viewer_url
                    actual_pdf_resp = resp
                else:
                    # Case (b) — HTML wrapper; find the real PDF URL inside
                    soup2 = BeautifulSoup(resp.text, "lxml")

                    actual_pdf_url = None

                    # 1. <iframe src="..."> or <embed src="..."> or <object data="...">
                    for tag, attr in [("iframe", "src"), ("embed", "src"), ("object", "data")]:
                        el = soup2.find(tag, {attr: re.compile(r"pluginfile|\.pdf", re.I)})
                        if el:
                            actual_pdf_url = urljoin(viewer_url, el[attr])
                            break

                    # 2. PDF.js viewer:  viewer.html?file=<encoded_url>
                    if not actual_pdf_url:
                        for a in soup2.find_all(src=re.compile(r"viewer\.html\?file=", re.I)):
                            m = re.search(r"file=([^&\"']+)", a.get("src", ""))
                            if m:
                                actual_pdf_url = unquote(m.group(1))
                                break

                    # 3. Any <a href> or src that looks like a PDF file
                    if not actual_pdf_url:
                        for tag in soup2.find_all(href=re.compile(r"pluginfile.*\.pdf", re.I)):
                            actual_pdf_url = urljoin(viewer_url, tag["href"])
                            break
                    if not actual_pdf_url:
                        for tag in soup2.find_all(src=re.compile(r"pluginfile", re.I)):
                            actual_pdf_url = urljoin(viewer_url, tag.get("src", ""))
                            break

                    if not actual_pdf_url:
                        errors.append(f"לא נמצא PDF בדף: bookid={bookid} — {title[:50]}")
                        log(f"  [{idx}/{len(books)}] דילוג (לא נמצא PDF בדף): {title[:40]}")
                        continue

                    actual_pdf_resp = client.get(actual_pdf_url, timeout=90)

                # ── Determine filename ────────────────────────────────────────
                cd = actual_pdf_resp.headers.get("content-disposition", "")
                cd_match = re.search(r"filename\*?=['\"]?(?:UTF-8'')?([^;'\"\n]+)", cd, re.I)
                if cd_match:
                    raw_name = unquote(cd_match.group(1).strip())
                else:
                    # Fall back to the URL's last path segment, then the link title
                    seg = actual_pdf_url.split("?")[0].split("/")[-1]
                    raw_name = unquote(seg) if seg else _safe_filename(title)

                if not raw_name.lower().endswith(".pdf"):
                    raw_name += ".pdf"
                fname = _unique(_safe_filename(raw_name))
                fpath = out_dir / fname

                # ── Skip already downloaded ───────────────────────────────────
                if fpath.exists() and fpath.stat().st_size > 500:
                    size_mb = round(fpath.stat().st_size / 1024 / 1024, 2)
                    log(f"  [{idx}/{len(books)}] קיים: {fname}")
                    downloaded.append({"filename": fname, "size_mb": size_mb, "url": actual_pdf_url})
                    continue

                # ── Verify it really is a PDF ─────────────────────────────────
                resp_ct = actual_pdf_resp.headers.get("content-type", "")
                if "text/html" in resp_ct:
                    errors.append(f"קיבל HTML (אולי session פג?): bookid={bookid}")
                    continue

                fpath.write_bytes(actual_pdf_resp.content)
                size = fpath.stat().st_size
                if size > 500:
                    size_mb = round(size / 1024 / 1024, 2)
                    log(f"  [{idx}/{len(books)}] {fname}  ({size_mb} MB)")
                    downloaded.append({"filename": fname, "size_mb": size_mb, "url": actual_pdf_url})
                else:
                    fpath.unlink(missing_ok=True)
                    errors.append(f"קובץ ריק: bookid={bookid}")

            except Exception as e:
                errors.append(f"bookid={bookid}: {str(e)[:80]}")

    log(f"הושלם! {len(downloaded)}/{len(books)} PDF הורדו ← {out_dir}")
    return {
        "course_name":     course_name,
        "course_number":   course_number,
        "pages_crawled":   len(all_html_pages),
        "pdfs_found":      len(books),
        "pdfs_downloaded": len(downloaded),
        "download_dir":    str(out_dir),
        "files":           downloaded,
        "errors":          errors[:30],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1.5  Scan course page → return list of sections/units
# ─────────────────────────────────────────────────────────────────────────────

def _run_get_sections_sync(course_url: str, cookies_list: list, log: Callable) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    log("פותח דפדפן וטוען דף קורס...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = browser.new_context(user_agent=_UA, ignore_https_errors=True,
                                  viewport={"width": 1920, "height": 1080})
        ctx.add_cookies(cookies_list)
        page = ctx.new_page()

        try:
            page.goto(course_url, timeout=30_000, wait_until="networkidle")
        except PWTimeout:
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass
        except Exception as e:
            browser.close()
            return {"error": f"לא ניתן לפתוח דף קורס: {e}"}

        log(f"דף נטען: {page.url}")

        # Dump full rendered HTML for inspection
        html = page.content()

        # Try multiple selector strategies to find section/unit rows
        sections = []

        # Strategy 1: look for elements with progress text (X/Y pattern) or checkmarks
        # These are the row items visible in the screenshot
        try:
            rows = page.eval_on_selector_all(
                "li, .ouil_section, [class*='section'], [class*='topic'], "
                "[class*='unit'], [class*='chapter']",
                """els => els
                    .map(e => ({
                        text: e.innerText.trim().split('\\n')[0].trim(),
                        href: (e.querySelector('a') || {}).href || ''
                    }))
                    .filter(r => r.text.length > 2 && r.text.length < 150)
                """
            )
            # Filter to meaningful section titles
            for r in rows:
                text = r.get("text", "").strip()
                href = r.get("href", "")
                # Keep rows that look like section titles (not nav items, etc.)
                if text and len(text) > 3:
                    sections.append({"title": text, "url": href})
        except Exception as e:
            log(f"strategy 1 failed: {e}")

        # Strategy 2: extract all visible text rows from the main content area
        if not sections:
            try:
                rows = page.eval_on_selector_all(
                    "#region-main li, .course-content li, main li",
                    """els => els
                        .map(e => ({
                            text: e.innerText.trim().split('\\n')[0].trim(),
                            href: (e.querySelector('a') || {}).href || ''
                        }))
                        .filter(r => r.text.length > 3 && r.text.length < 200)
                    """
                )
                for r in rows:
                    sections.append({"title": r.get("text",""), "url": r.get("href","")})
            except Exception as e:
                log(f"strategy 2 failed: {e}")

        # Deduplicate by title
        seen_titles: set[str] = set()
        unique_sections = []
        for s in sections:
            t = s["title"]
            if t not in seen_titles:
                seen_titles.add(t)
                unique_sections.append(s)

        log(f"נמצאו {len(unique_sections)} סקשנים בדף")

        # Also save a snippet of the HTML to help debug if 0 found
        html_snippet = html[:3000] if not unique_sections else ""
        browser.close()

    return {
        "sections": unique_sections,
        "html_snippet": html_snippet,  # only included when empty, for debugging
    }


async def get_unit_nav_items(section_url: str, section_title: str, course_url: str,
                             cookies_list: list, log: Callable) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_get_unit_nav_sync,
        section_url, section_title, course_url, cookies_list, log)


def _run_get_unit_nav_sync(section_url: str, section_title: str, course_url: str,
                            cookies_list: list, log: Callable) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    log("פותח דפדפן לניווט יחידה...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = browser.new_context(user_agent=_UA, ignore_https_errors=True,
                                  viewport={"width": 1920, "height": 1080})
        ctx.add_cookies(cookies_list)
        page = ctx.new_page()

        if section_url:
            try:
                page.goto(section_url, timeout=30_000, wait_until="networkidle")
            except PWTimeout:
                try: page.wait_for_timeout(2000)
                except Exception: pass
            except Exception as e:
                browser.close()
                return {"error": f"לא ניתן לפתוח דף יחידה: {e}"}
        else:
            # No direct URL — navigate to course page and click the section title
            log(f"אין URL ישיר, פותח דף קורס ולוחץ על: {section_title}")
            try:
                page.goto(course_url, timeout=30_000, wait_until="networkidle")
            except PWTimeout:
                try: page.wait_for_timeout(2000)
                except Exception: pass
            except Exception as e:
                browser.close()
                return {"error": f"לא ניתן לפתוח דף קורס: {e}"}
            try:
                el = page.get_by_text(section_title, exact=True).first
                if el.is_visible(timeout=3000):
                    el.click()
                    page.wait_for_timeout(2500)
            except Exception:
                pass

        log(f"דף נטען: {page.url}")

        # The block_ouil_navigation uses a tree with AJAX-loaded branches.
        # Step 1: expand the navigation block if it's collapsed (the whole block has a toggle)
        try:
            block_toggle = page.query_selector(
                '[class*="ouil_navigation"] [data-toggle="collapse"], '
                '[class*="ouil_navigation"] [data-bs-toggle="collapse"]'
            )
            if block_toggle:
                aria = block_toggle.get_attribute("aria-expanded") or ""
                if aria.strip().lower() != "true":
                    block_toggle.click()
                    page.wait_for_timeout(600)
                    log("פתחנו את בלוק הניווט")
        except Exception as e:
            log(f"לא הצלחנו לפתוח בלוק ניווט: {e}")

        # Step 2: click every AJAX branch (chapter) so its sub-items load
        try:
            branches = page.query_selector_all('[data-requires-ajax="true"]')
            log(f"נמצאו {len(branches)} פרקים לטעינה")
            for branch in branches:
                try:
                    branch.scroll_into_view_if_needed(timeout=2000)
                    branch.click(timeout=3000)
                    # Wait until data-loaded becomes "true" or timeout
                    try:
                        page.wait_for_function(
                            f"""() => {{
                                const el = document.getElementById('{branch.get_attribute("id") or ""}');
                                return !el || el.getAttribute('data-loaded') === 'true';
                            }}""",
                            timeout=4000
                        )
                    except Exception:
                        page.wait_for_timeout(1500)
                except Exception:
                    pass
        except Exception as e:
            log(f"שגיאה בטעינת פרקים: {e}")

        # Step 3: collect all links from the navigation tree
        nav_items = []
        seen_urls: set[str] = set()
        try:
            raw_items = page.eval_on_selector_all(
                '.block_tree a, [class*="ouil_navigation"] a',
                """els => els.map(e => ({
                    href: e.href || '',
                    text: (e.innerText || e.textContent || '').trim().split('\\n')[0].trim()
                })).filter(item =>
                    item.href &&
                    item.href.includes('opal.openu.ac.il') &&
                    !item.href.includes('javascript:') &&
                    item.text.length > 1 && item.text.length < 150
                )"""
            )
            for item in raw_items:
                url = item.get("href", "").split("#")[0]
                text = item.get("text", "").strip()
                if not url or not text:
                    continue
                if re.search(r"from=courseHome", url, re.I):
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                nav_items.append({"title": text, "url": url})
        except Exception as e:
            browser.close()
            return {"error": f"שגיאת חילוץ ניווט: {e}"}

        log(f"נמצאו {len(nav_items)} פריטי ניווט")
        browser.close()

    return {"nav_items": nav_items}


async def get_course_sections(course_url: str, cookies_list: list, log: Callable) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_get_sections_sync, course_url, cookies_list, log)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2  Scan a single section → return list of all files found
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan_section_sync(
    section_url: str, section_title: str, course_url: str,
    cookies_list: list, log: Callable
) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    from urllib.parse import unquote

    files: list[dict] = []
    seen_urls: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = browser.new_context(user_agent=_UA, ignore_https_errors=True,
                                  viewport={"width": 1920, "height": 1080})
        ctx.add_cookies(cookies_list)
        page = ctx.new_page()

        # ── If direct URL exists, navigate there ─────────────────────────────
        if section_url:
            log(f"מנווט לסקשן: {section_url}")
            try:
                page.goto(section_url, timeout=30_000, wait_until="networkidle")
            except PWTimeout:
                try: page.wait_for_timeout(2000)
                except Exception: pass
            except Exception as e:
                browser.close()
                return {"error": f"לא ניתן לפתוח סקשן: {e}"}

        # ── Otherwise: open course page and click the section by title ────────
        else:
            log(f"פותח דף קורס ולוחץ על: {section_title}")
            try:
                page.goto(course_url, timeout=30_000, wait_until="networkidle")
            except PWTimeout:
                try: page.wait_for_timeout(2000)
                except Exception: pass
            except Exception as e:
                browser.close()
                return {"error": f"לא ניתן לפתוח דף קורס: {e}"}

            # Click the row that contains the section title
            clicked = False
            try:
                # Try exact text match first
                el = page.get_by_text(section_title, exact=True).first
                if el.is_visible(timeout=3000):
                    el.click()
                    clicked = True
            except Exception:
                pass

            if not clicked:
                # Fallback: find any element whose text contains the title
                try:
                    els = page.locator(f"text={section_title[:30]}").all()
                    for el in els:
                        try:
                            if el.is_visible(timeout=1000):
                                el.click()
                                clicked = True
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

            if not clicked:
                log("לא הצלחתי ללחוץ על הסקשן — ממשיך עם מה שיש בדף")

            # Wait for any navigation or content expansion
            try:
                page.wait_for_timeout(2500)
            except Exception:
                pass

        log(f"דף נטען: {page.url}")
        single_page_mode = bool(section_url)  # when URL given directly, no BFS needed

        def _extract_bookids_from_html(html: str, label: str) -> list[dict]:
            """Scan raw HTML for bookid patterns and PDF pluginfile URLs."""
            found = []

            # Pattern 1: bookid=XXXX  (URL query param or anywhere in HTML)
            # Pattern 2: "bookid":"XXXX" or "bookid":XXXX  (JSON / JS config)
            bid_seen: set[str] = set()
            for m in re.finditer(
                r'(?:bookid=|["\']bookid["\']\s*:\s*["\']?)(\d+)', html
            ):
                bid = m.group(1)
                if bid in bid_seen:
                    continue
                bid_seen.add(bid)
                url = (f"{OPAL_BASE}/mod/combopage/item/book/bookview.php"
                       f"?bookid={bid}&combopage=bookNewTab")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                s  = max(0, m.start() - 400)
                e  = min(len(html), m.end() + 400)
                ctx = html[s:e]
                tm  = re.search(
                    r'(?:title|data-title|aria-label|data-name|"name"|"title")'
                    r'\s*[=:]\s*["\']([^"\']{3,120})["\']', ctx)
                found.append({
                    "title":  tm.group(1) if tm else f"חוברת {bid} ({label})",
                    "url":    url,
                    "type":   "book_pdf",
                    "bookid": bid,
                })

            # Pattern 3: pluginfile.php PDF links only (skip images/css/etc.)
            for m in re.finditer(
                r'https?://opal\.openu\.ac\.il/pluginfile\.php/[^\s"\'<>\\]+', html
            ):
                url = m.group(0).rstrip("\\")
                ext = url.split("?")[0].split(".")[-1].lower()
                if ext not in ("pdf",):          # only PDFs from pluginfile
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                title = unquote(url.split("/")[-1].split("?")[0]) or "קובץ"
                found.append({"title": title, "url": url, "type": "pdf"})

            return found

        # ── Step A: scan the landing page ─────────────────────────────────────
        files.extend(_extract_bookids_from_html(page.content(), "עמוד ראשי"))

        # ── Single-page mode: no BFS — URL was given directly ─────────────────
        if single_page_mode:
            # Intercept dynamic bookview.php requests (loaded via JS/iframe)
            intercepted_single: list[str] = []
            def _on_req_single(request):
                if "bookview.php" in request.url:
                    m2 = re.search(r"bookid=(\d+)", request.url)
                    if m2:
                        intercepted_single.append(m2.group(1))
            page.on("request", _on_req_single)

            # Wait for dynamic content to load
            page.wait_for_timeout(2500)
            files.extend(_extract_bookids_from_html(page.content(), "single"))

            # Add any intercepted bookids
            for bid in intercepted_single:
                url = (f"{OPAL_BASE}/mod/combopage/item/book/bookview.php"
                       f"?bookid={bid}&combopage=bookNewTab")
                if url not in seen_urls:
                    seen_urls.add(url)
                    files.append({"title": f"קריאה ממוקדת {bid}",
                                  "url": url, "type": "book_pdf", "bookid": bid})

            # Deduplicate
            seen_t: set[str] = set()
            unique = []
            for f in files:
                if f["url"] not in seen_t:
                    seen_t.add(f["url"])
                    unique.append(f)
            log(f"נמצאו {len(unique)} קבצים (מצב דף בודד)")
            browser.close()
            return {"files": unique, "total": len(unique)}

        # ── Step B: only relevant for combopage/view.php ──────────────────────
        combopage_m = re.search(
            r"https?://opal\.openu\.ac\.il/mod/combopage/view\.php\?id=(\d+)",
            page.url
        )
        if not combopage_m:
            log(f"לא combopage — נמצאו {len(files)} קבצים")
            browser.close()
            return {"files": files, "total": len(files)}

        cp_base_id = combopage_m.group(1)
        cp_base    = f"{OPAL_BASE}/mod/combopage/view.php?id={cp_base_id}"

        # ── Step C: click "פתיחה הכל" to expand sidebar ───────────────────────
        try:
            for expand_sel in [
                "text=פתיחה הכל", "text=הרחב הכל", "text=expand all",
                "[class*='expandall']", "[data-action='expandall']",
                "text=פתח הכל", "text=הצג הכל",
            ]:
                try:
                    btn = page.locator(expand_sel).first
                    if btn.is_visible(timeout=800):
                        btn.click()
                        page.wait_for_timeout(1000)
                        log(f"לחץ '{expand_sel}'")
                        break
                except Exception:
                    pass
        except Exception:
            pass

        # ── Steps D+E: two-level crawl of the unit's combopage tree ─────────
        #
        # Level 0: landing page (already scanned in Step A)
        # Level 1: chapter sub-combopages — found via `from=nav` links
        #          (sidebar TOC items for this unit only)
        # Level 2: cpage=N pages within each chapter
        #
        # We intentionally SKIP bottomPrev/topPrev/bottomNext/topNext links
        # because those lead to OTHER units and would crawl the whole course.

        def _is_content_link(url: str) -> bool:
            """True for sidebar (from=nav) links; False for prev/next/home nav."""
            if re.search(r"from=(bottom|top)(Prev|Next)", url, re.I):
                return False
            if re.search(r"from=courseHome", url, re.I):
                return False
            return True

        def _chapter_links_from_html(html: str) -> list[str]:
            """Return `from=nav` combopage links — i.e. sidebar chapter links."""
            found_links = []
            for m2 in re.finditer(
                r'href=["\'](' + re.escape(OPAL_BASE) +
                r'/mod/combopage/view\.php\?[^"\'#\s]+)["\']',
                html,
            ):
                url = m2.group(1).replace("&amp;", "&")
                if _is_content_link(url):
                    found_links.append(url)
            for m2 in re.finditer(
                r'href=["\'](/mod/combopage/view\.php\?[^"\'#\s]+)["\']',
                html,
            ):
                url = (OPAL_BASE + m2.group(1)).replace("&amp;", "&")
                if _is_content_link(url):
                    found_links.append(url)
            return found_links

        landing_html = page.content()
        visited_nav: set[str] = {cp_base}

        # Level 1: chapter pages linked from the unit landing page
        chapter_urls = _chapter_links_from_html(landing_html)
        # Also add cpage= pages of the landing page itself
        for m2 in re.finditer(r"cpage=(\d+)", landing_html):
            chapter_urls.append(f"{cp_base}&cpage={m2.group(1)}")

        log(f"BFS start: {len(chapter_urls)} פריטים ראשוניים")

        # Intercept bookview.php requests (bookids loaded via iframe/JS)
        intercepted_bookids: list[tuple[str, str]] = []

        def _on_request(request):
            url = request.url
            if "bookview.php" in url:
                m2 = re.search(r"bookid=(\d+)", url)
                if m2:
                    intercepted_bookids.append((m2.group(1), url))

        page.on("request", _on_request)

        def _drain_intercepted(label: str) -> list[dict]:
            drained = []
            while intercepted_bookids:
                bid, _ = intercepted_bookids.pop(0)
                url = (f"{OPAL_BASE}/mod/combopage/item/book/bookview.php"
                       f"?bookid={bid}&combopage=bookNewTab")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                drained.append({"title": f"קריאה ממוקדת {bid} ({label})",
                                "url": url, "type": "book_pdf", "bookid": bid})
            return drained

        def _collect_nav_links_from_dom(pg) -> list[str]:
            """
            Use Playwright JS to pull every combopage link from the DOM,
            including those inside collapsed/hidden sidebar sections.
            Then filter out cross-unit navigation (bottomPrev/topNext etc.).
            """
            try:
                links = pg.eval_on_selector_all(
                    "a[href*='combopage/view.php']",
                    """els => els
                        .map(e => e.href)
                        .filter(h => h.includes('opal.openu.ac.il'))
                    """
                )
            except Exception:
                links = []
            # Keep only sidebar content links, skip prev/next/courseHome navigation
            return [l for l in links if _is_content_link(l)]

        # Collect all combopage links visible (or present) in the DOM right now
        chapter_urls = _collect_nav_links_from_dom(page)
        log(f"BFS start: {len(chapter_urls)} פריטים מה-DOM")

        # BFS: follow from=nav links recursively (stays within the unit)
        bfs_queue: list[str] = list(chapter_urls)

        while bfs_queue:
            raw_url = bfs_queue.pop(0)
            clean = raw_url.split("#")[0].replace("&amp;", "&")
            if clean in visited_nav:
                continue
            visited_nav.add(clean)

            intercepted_bookids.clear()
            try:
                page.goto(clean, timeout=25_000, wait_until="networkidle")
                page.wait_for_timeout(800)
            except Exception:
                try:
                    page.wait_for_timeout(2000)
                except Exception:
                    pass

            # Collect all nav links from DOM on this page and add new ones to queue
            for lnk in _collect_nav_links_from_dom(page):
                clean_new = lnk.split("#")[0].replace("&amp;", "&")
                if clean_new not in visited_nav:
                    bfs_queue.append(lnk)
            sub_html = page.content()

            found = _extract_bookids_from_html(sub_html, clean[-50:])
            found += _drain_intercepted(clean[-40:])
            if found:
                log(f"  {clean[-70:]}: {len(found)} קבצים")
                files.extend(found)

            # Discover new sidebar items and add to queue
            for new_url in _chapter_links_from_html(sub_html):
                clean_new = new_url.split("#")[0].replace("&amp;", "&")
                if clean_new not in visited_nav:
                    bfs_queue.append(new_url)

        log(f"BFS הסתיים: {len(visited_nav)} דפים, {len(files)} קבצים")

        log(f"נמצאו {len(files)} קבצים סה\"כ")
        browser.close()

    # Final dedup by bookid
    seen_bids: set[str] = set()
    final: list[dict] = []
    for f in files:
        if f["type"] == "book_pdf":
            if f["bookid"] in seen_bids:
                continue
            seen_bids.add(f["bookid"])
        final.append(f)
    return {"files": final, "total": len(final)}


def _resolve_pdf_url_sync(file_url: str, cookies_list: list) -> tuple[str, bytes]:
    """
    Given a bookview or pluginfile URL + session cookies,
    returns (filename, pdf_bytes).
    Handles:
    - Direct PDF responses
    - HTML wrappers with embedded iframes/embeds
    - OpenU book viewer pattern: URL contains kat= (PDF with page range restriction)
    """
    import httpx
    from bs4 import BeautifulSoup
    from urllib.parse import unquote, urljoin, urlparse, parse_qs, urlencode, urlunparse

    cookies_dict = {c["name"]: c["value"] for c in cookies_list}
    headers = {"User-Agent": _UA, "Referer": OPAL_BASE}

    with httpx.Client(cookies=cookies_dict, headers=headers,
                      follow_redirects=True, timeout=60, verify=False) as client:
        resp = client.get(file_url, timeout=30)
        ct   = resp.headers.get("content-type", "")

        if "application/pdf" in ct or "octet-stream" in ct:
            actual_url = str(resp.url)
            pdf_bytes  = resp.content
        else:
            soup = BeautifulSoup(resp.text, "lxml")
            actual_url = None
            pdf_bytes  = None

            # ── Pattern 1: iframe / embed / object with PDF src ────────────────
            for tag, attr in [("iframe", "src"), ("embed", "src"), ("object", "data")]:
                el = soup.find(tag, {attr: re.compile(r"pluginfile|\.pdf", re.I)})
                if el:
                    actual_url = urljoin(str(resp.url), el[attr])
                    break

            # ── Pattern 2: PDF.js viewer.html?file= ───────────────────────────
            if not actual_url:
                for script in soup.find_all(src=re.compile(r"viewer\.html\?file=", re.I)):
                    m = re.search(r"file=([^&\"']+)", script.get("src", ""))
                    if m:
                        actual_url = unquote(m.group(1))
                        break

            # ── Pattern 3: any href pointing to a PDF ─────────────────────────
            if not actual_url:
                for a in soup.find_all(href=re.compile(r"pluginfile.*\.pdf|\.pdf\b", re.I)):
                    actual_url = urljoin(str(resp.url), a["href"])
                    break

            # ── Pattern 4: OpenU kat= book viewer ────────────────────────────
            # The bookview page redirects to a URL like:
            #   ?kat=10406-5099&courseid=54071&pages=7-12#view=Fit&...
            # Each "book" is really a page range of one large PDF.
            # Strip pages= and fetch the full PDF directly.
            if not actual_url:
                parsed = urlparse(str(resp.url))
                qs     = parse_qs(parsed.query, keep_blank_values=True)
                if "kat" in qs:
                    # Get book title for the filename
                    title_tag  = soup.find("title")
                    book_title = title_tag.get_text(strip=True) if title_tag else qs["kat"][0]

                    # Build URL without pages= restriction
                    base_params = {k: v[0] for k, v in qs.items() if k != "pages"}
                    base_url    = urlunparse(parsed._replace(
                        query=urlencode(base_params), fragment=""
                    ))

                    # Try with explicit PDF Accept header first
                    for accept in ("application/pdf", "*/*"):
                        r2 = client.get(
                            base_url,
                            headers={**headers, "Accept": accept},
                            timeout=60,
                        )
                        if "application/pdf" in r2.headers.get("content-type", "") or \
                           r2.content[:4] == b"%PDF":
                            filename  = _safe_filename(book_title) + ".pdf"
                            return filename, r2.content

                    # Fallback: search script tags inside the viewer HTML for a PDF URL
                    for script in soup.find_all("script"):
                        text = script.get_text() or ""
                        m = re.search(
                            r'["\']([^"\']*(?:pluginfile|/pdf/|\.pdf)[^"\']*)["\']', text
                        )
                        if m:
                            candidate = urljoin(str(resp.url), m.group(1))
                            r3 = client.get(candidate, timeout=60)
                            if "application/pdf" in r3.headers.get("content-type", "") or \
                               r3.content[:4] == b"%PDF":
                                filename = _safe_filename(book_title) + ".pdf"
                                return filename, r3.content

            if not actual_url and not pdf_bytes:
                raise ValueError(f"לא נמצא PDF בתוך הדף | url={str(resp.url)[-80:]}")

            if not pdf_bytes:
                r2        = client.get(actual_url, timeout=60)
                pdf_bytes = r2.content

        # Filename from Content-Disposition or URL
        cd    = resp.headers.get("content-disposition", "")
        cd_m  = re.search(r"filename\*?=['\"]?(?:UTF-8'')?([^;'\"\n]+)", cd, re.I)
        if cd_m:
            filename = unquote(cd_m.group(1).strip())
        else:
            seg      = (actual_url or file_url).split("?")[0].split("/")[-1]
            filename = unquote(seg) if seg else "file.pdf"
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        return _safe_filename(filename), pdf_bytes


async def scan_section_files(
    section_url: str, section_title: str, course_url: str,
    cookies_list: list, log: Callable,
) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_scan_section_sync,
        section_url, section_title, course_url, cookies_list, log)


def _run_download_unit_sync(
    section_url: str, section_title: str, course_url: str,
    course_folder: str, cookies_list: list, log: Callable,
) -> dict:
    """Get nav items for a section, scan each page, download all PDFs."""
    from urllib.parse import unquote as _unquote

    out_dir = OPENU_DOWNLOADS_DIR / _safe_filename(course_folder) / _safe_filename(section_title)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: get nav items ────────────────────────────────────────────────
    log(f"טוען פריטי ניווט עבור: {section_title}")
    nav_result = _run_get_unit_nav_sync(section_url, section_title, course_url, cookies_list, log)
    if "error" in nav_result:
        return nav_result
    nav_items = nav_result.get("nav_items", [])
    log(f"נמצאו {len(nav_items)} פריטי ניווט")

    # ── Step 2: scan each nav item for PDFs ─────────────────────────────────
    # Only scan pages likely to contain PDFs (reading material & presentations).
    # Video pages, discussion questions, glossaries etc. never have PDFs.
    _PDF_TITLE_KEYWORDS = ("קריאה ממוקדת", "מצגת")

    all_files: list[dict] = []
    seen_urls: set[str] = set()
    for item in nav_items:
        item_url   = item.get("url", "")
        item_title = item.get("title", "")
        if not item_url:
            continue
        if not any(kw in item_title for kw in _PDF_TITLE_KEYWORDS):
            log(f"דילוג (אין PDF צפוי): {item_title}")
            continue
        log(f"סורק: {item_title} | {item_url[-60:]}")
        scan = _run_scan_section_sync(item_url, item_title, course_url, cookies_list, log)
        item_files = scan.get("files", [])
        log(f"  → {len(item_files)} קבצים")
        for f in item_files:
            if f["url"] not in seen_urls:
                seen_urls.add(f["url"])
                all_files.append(f)

    log(f"סה\"כ {len(all_files)} קבצים לפני הורדה")

    # ── Step 3: download each file ───────────────────────────────────────────
    def _unique_path(p: Path) -> Path:
        if not p.exists():
            return p
        stem, suf = p.stem, p.suffix
        for i in range(1, 200):
            c = p.parent / f"{stem}_{i}{suf}"
            if not c.exists():
                return c
        return p

    downloaded = []
    errors = []
    for f in all_files:
        try:
            log(f"מוריד: {f['title']}")
            fname, pdf_bytes = _resolve_pdf_url_sync(f["url"], cookies_list)
            fpath = _unique_path(out_dir / fname)
            fpath.write_bytes(pdf_bytes)
            size_mb = round(len(pdf_bytes) / 1_048_576, 2)
            downloaded.append({"filename": fname, "size_mb": size_mb, "title": f["title"]})
            log(f"  ✓ {fname} ({size_mb} MB)")
        except Exception as e:
            log(f"  ✗ {f['title']}: {e}")
            errors.append(str(e))

    log(f"הורדה הסתיימה: {len(downloaded)} קבצים")
    return {
        "files":      downloaded,
        "errors":     errors,
        "out_dir":    str(out_dir),
        "section":    section_title,
        "total":      len(downloaded),
    }


async def download_unit_pdfs(
    section_url: str, section_title: str, course_url: str,
    course_folder: str, cookies_list: list, log: Callable,
) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_download_unit_sync,
        section_url, section_title, course_url, course_folder, cookies_list, log,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Fast download by combopage page IDs (no browser needed)
# ─────────────────────────────────────────────────────────────────────────────

def _run_download_page_ids_sync(
    page_ids: list[int], course_folder: str, cookies_list: list, log: Callable,
) -> dict:
    """
    For each combopage view.php?id=XXXXX:
      1. Fetch HTML via httpx (server-rendered, no JS needed for bookid extraction)
      2. Extract embedded bookids with regex
      3. Download each bookid PDF via _resolve_pdf_url_sync
    Much faster than browser-based scanning — no Playwright, no navigation overhead.
    """
    import httpx
    from urllib.parse import unquote as _unquote
    from datetime import datetime

    cookies_dict = {c["name"]: c["value"] for c in cookies_list}
    headers = {"User-Agent": _UA, "Referer": OPAL_BASE}

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = OPENU_DOWNLOADS_DIR / _safe_filename(course_folder) / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"שומר לתיקייה: {out_dir}")

    downloaded, errors = [], []
    seen_bookids: set[str] = set()
    seen_urls: set[str] = set()
    seen_kat: set[str] = set()   # avoid re-downloading the same base PDF

    def _unique_path(p: Path) -> Path:
        if not p.exists():
            return p
        stem, suf = p.stem, p.suffix
        for i in range(1, 999):
            c = p.parent / f"{stem}_{i}{suf}"
            if not c.exists():
                return c
        return p

    with httpx.Client(cookies=cookies_dict, headers=headers,
                      follow_redirects=True, timeout=30, verify=False) as http:
        for page_id in page_ids:
            page_url = f"{OPAL_BASE}/mod/combopage/view.php?id={page_id}&from=nav"
            log(f"סורק: {page_url[-60:]}")
            try:
                resp = http.get(page_url, timeout=20)
                html = resp.text

                # Detect if we landed on a login/error page instead of course content
                if "sso.apps.openu.ac.il" in str(resp.url) or "login" in str(resp.url).lower():
                    log(f"  ⚠ הופנינו לדף כניסה — הסשן אינו תקף לדף זה")
                    errors.append(f"page_id={page_id}: סשן לא תקף")
                    continue
                if "bookid" not in html and "pluginfile" not in html:
                    log(f"  ⚠ דף {page_id} לא מכיל תוכן קורס (content-type={resp.headers.get('content-type','?')[:40]}, url={str(resp.url)[-60:]})")
                    continue

                # Extract bookids (URL param or JSON config)
                for m in re.finditer(
                    r'(?:bookid=|["\']bookid["\']\s*:\s*["\']?)(\d+)', html
                ):
                    bid = m.group(1)
                    if bid in seen_bookids:
                        continue
                    seen_bookids.add(bid)
                    book_url = (f"{OPAL_BASE}/mod/combopage/item/book/bookview.php"
                                f"?bookid={bid}&combopage=bookNewTab")
                    log(f"  מוריד חוברת {bid}")
                    try:
                        fname, pdf_bytes = _resolve_pdf_url_sync(book_url, cookies_list)
                        fpath = _unique_path(out_dir / fname)
                        fpath.write_bytes(pdf_bytes)
                        size_mb = round(len(pdf_bytes) / 1_048_576, 2)
                        downloaded.append({"filename": fpath.name, "size_mb": size_mb})
                        log(f"  ✓ {fpath.name} ({size_mb} MB)")
                    except Exception as e:
                        log(f"  ✗ חוברת {bid}: {e}")
                        errors.append(f"bookid={bid}: {e}")

                # Extract direct pluginfile PDFs
                for m in re.finditer(
                    r'https?://opal\.openu\.ac\.il/pluginfile\.php/[^\s"\'<>\\]+', html
                ):
                    url = m.group(0).rstrip("\\")
                    if url.split("?")[0].split(".")[-1].lower() != "pdf":
                        continue
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    title = _unquote(url.split("/")[-1].split("?")[0]) or "file.pdf"
                    log(f"  מוריד קובץ: {title}")
                    try:
                        fname, pdf_bytes = _resolve_pdf_url_sync(url, cookies_list)
                        fpath = _unique_path(out_dir / fname)
                        fpath.write_bytes(pdf_bytes)
                        size_mb = round(len(pdf_bytes) / 1_048_576, 2)
                        downloaded.append({"filename": fpath.name, "size_mb": size_mb})
                        log(f"  ✓ {fpath.name} ({size_mb} MB)")
                    except Exception as e:
                        log(f"  ✗ {title}: {e}")
                        errors.append(f"{title}: {e}")

            except Exception as e:
                log(f"  שגיאה בדף {page_id}: {e}")
                errors.append(f"page_id={page_id}: {e}")

    log(f"הורדה הסתיימה: {len(downloaded)} קבצים")
    return {
        "downloaded": downloaded,
        "errors": errors,
        "total": len(downloaded),
        "course_folder": course_folder,
    }


async def download_page_ids_fast(
    page_ids: list[int], course_folder: str, cookies_list: list, log: Callable,
) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_download_page_ids_sync,
        page_ids, course_folder, cookies_list, log,
    )


async def download_course_pdfs(
    course_url: str, course_name: str, course_number: str,
    cookies_list: list, log: Callable,
) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor, _run_course_download_sync,
        course_url, course_name, course_number, cookies_list, log,
    )
