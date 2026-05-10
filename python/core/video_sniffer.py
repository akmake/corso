import asyncio
import os
from pathlib import Path

CHROME_USER_DATA = os.path.expandvars(
    r"%LOCALAPPDATA%\Google\Chrome\User Data"
)


async def sniff_video_urls(page_url: str, log_fn, timeout: int = 60) -> dict:
    """
    Open a real Chrome window with the user's profile, navigate to page_url,
    and capture any .m3u8 / .mp4 streaming URLs from network requests.
    """
    from playwright.async_api import async_playwright

    found: list[str] = []
    seen: set[str] = set()

    async with async_playwright() as p:
        log_fn("פותח Chrome עם הפרופיל שלך...")

        # Use persistent context = real Chrome with existing login cookies
        context = await p.chromium.launch_persistent_context(
            user_data_dir=CHROME_USER_DATA,
            channel="chrome",          # use installed Chrome, not bundled Chromium
            headless=False,
            args=["--no-first-run", "--no-default-browser-check"],
        )

        page = context.pages[0] if context.pages else await context.new_page()

        def on_request(request):
            url = request.url
            if url in seen:
                return
            if ".m3u8" in url or (
                ".mp4" in url and any(x in url for x in ["?", "token", "expires", "md5"])
            ):
                seen.add(url)
                found.append(url)
                short = url[:90] + "..." if len(url) > 90 else url
                log_fn(f"נמצא: {short}")

        context.on("request", on_request)

        log_fn(f"נווט אל: {page_url}")
        try:
            await page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
        except Exception:
            pass  # timeout on slow pages is OK, we keep listening

        log_fn("ממתין לסרטון — לחץ Play אם צריך...")

        # Poll until we find something or timeout
        elapsed = 0
        while elapsed < timeout:
            if found:
                break
            await asyncio.sleep(1)
            elapsed += 1
            if elapsed % 10 == 0:
                log_fn(f"עדיין מחכה... ({elapsed}s)")

        await context.close()

    if found:
        log_fn(f"סה\"כ נמצאו {len(found)} URL(s)")
        return {"urls": found}
    else:
        return {"error": "לא נמצא URL לסרטון. ודא שלחצת Play ושהסרטון מתחיל לפני הזמן הקצוב."}
