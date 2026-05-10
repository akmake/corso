"""
SOCMINT Module — Social Media Intelligence
-------------------------------------------
Username enumeration across 83+ platforms (built-in) + 2,500+ via Maigret.
If Maigret is installed, results are merged for maximum coverage.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Literal

import httpx

from core.tool_runner import is_available, run_tool, make_temp_file, get_mode

_log = logging.getLogger(__name__)

# ── Platform definitions ──────────────────────────────────────────────────────
# check:
#   "status"   → 200 = found, 404 = not found
#   "body"     → look for not_found string in body; if absent = found
#   "redirect" → if redirect goes to login/error = not found

@dataclass
class Platform:
    name:      str
    url:       str                          # {} = username placeholder
    check:     Literal["status", "body"]   = "status"
    not_found: list[str]                   = field(default_factory=list)
    category:  str                         = "social"


PLATFORMS: list[Platform] = [
    # ── Social / General ────────────────────────────────────────────────────
    # Facebook תמיד מחזיר 200 — חייב body check
    Platform("Facebook",     "https://www.facebook.com/{}",          "body", ["This page isn't available", "content isn't available", "Page Not Found"], "social"),
    Platform("Reddit",       "https://www.reddit.com/user/{}",       "body", ["nobody on reddit", "page not found", "Sorry, nobody"], "social"),
    # Twitter/X עבר ל-x.com, דורש body check בגלל login wall
    Platform("Twitter/X",    "https://x.com/{}",                     "body", ["This account doesn't exist", "Hmm...this page doesn't exist", "page doesn't exist"], "social"),
    Platform("Instagram",    "https://www.instagram.com/{}/",        "body", ["Page Not Found", "Sorry, this page"], "social"),
    Platform("TikTok",       "https://www.tiktok.com/@{}",           "body", ["Couldn't find this account", "404"], "social"),
    Platform("YouTube",      "https://www.youtube.com/@{}",          "body", ["This page isn't available", "404"], "social"),
    Platform("Pinterest",    "https://www.pinterest.com/{}/",        "body", ["Sorry! We couldn't find that page"], "social"),
    Platform("Snapchat",     "https://www.snapchat.com/add/{}",      "body", ["Sorry, we couldn't find"], "social"),
    Platform("Flickr",       "https://www.flickr.com/people/{}",     "body", ["Page Not Found"], "social"),
    Platform("Vimeo",        "https://vimeo.com/{}",                 "body", ["Page not found"], "social"),
    Platform("Telegram",     "https://t.me/{}",                      "body", ["If you have Telegram"], "social"),
    # פלטפורמות 2026 חדשות
    Platform("Threads",      "https://www.threads.net/@{}",          "body", ["Sorry, this page isn't available", "Page not found", "isn't available"], "social"),
    Platform("Bluesky",      "https://bsky.app/profile/{}",          "body", ["Profile not found", "Not Found", "does not exist"], "social"),
    Platform("LinkedIn",     "https://www.linkedin.com/in/{}/",      "body", ["Page not found", "This LinkedIn Page doesn't exist", "profile does not exist"], "professional"),
    Platform("Mastodon",     "https://mastodon.social/@{}",          "body", ["User not found", "There is no account", "404"], "social"),

    # ── Russian & Asian (Crucial for OSINT) ─────────────────────────────────
    Platform("VKontakte",    "https://vk.com/{}",                    "body", ["This page is private", "Page not found", "не существует"], "social_ru"),
    Platform("OK.ru",        "https://ok.ru/{}",                     "body", ["Page not found", "Страница не найдена"], "social_ru"),

    # ── Alt-Tech / Uncensored ───────────────────────────────────────────────
    Platform("Rumble",       "https://rumble.com/user/{}",           "body", ["The page you requested does not exist", "404"], "alt_tech"),
    Platform("Gab",          "https://gab.com/{}",                   "body", ["User not found", "This account does not exist"], "alt_tech"),
    Platform("Gettr",        "https://gettr.com/user/{}",            "status", [], "alt_tech"),
    Platform("TruthSocial",  "https://truthsocial.com/@{}",          "status", [], "alt_tech"),
    Platform("Odysee",       "https://odysee.com/@{}",               "status", [], "alt_tech"),
    Platform("Bitchute",     "https://www.bitchute.com/channel/{}/", "body", ["Channel does not exist", "404"], "alt_tech"),

    # ── Hacking / Cybersecurity ─────────────────────────────────────────────
    Platform("HackTheBox",   "https://forum.hackthebox.com/u/{}/summary", "status", [], "cyber"),
    Platform("TryHackMe",    "https://tryhackme.com/p/{}",           "body", ["Not Found", "404"], "cyber"),
    Platform("HackerOne",    "https://hackerone.com/{}",             "body", ["Page not found"], "cyber"),
    Platform("Bugcrowd",     "https://bugcrowd.com/{}",              "status", [], "cyber"),
    Platform("RootMe",       "https://www.root-me.org/{}",           "status", [], "cyber"),
    Platform("VulnDB",       "https://vulndb.cyberriskanalytics.com/authors/{}", "status", [], "cyber"),
    Platform("0x00sec",      "https://0x00sec.org/u/{}",             "body", ["The page you requested doesn't exist"], "cyber"),
    
    # ── Crypto / Finance ────────────────────────────────────────────────────
    Platform("CoinMarketCap","https://coinmarketcap.com/community/profile/{}", "status", [], "crypto"),
    Platform("Binance",      "https://www.binance.com/en/feed/profile/{}", "status", [], "crypto"),
    Platform("Patreon",      "https://www.patreon.com/{}",           "body", ["Sorry, this page"], "finance"),
    Platform("Ko-fi",        "https://ko-fi.com/{}",                 "body", ["Page Not Found"], "finance"),
    Platform("Venmo",        "https://account.venmo.com/u/{}",       "status", [], "finance"),

    # ── Adult / Dating (High reuse of usernames) ────────────────────────────
    Platform("OnlyFans",     "https://onlyfans.com/{}",              "status", [], "adult"),
    Platform("Pornhub",      "https://www.pornhub.com/users/{}",     "body", ["Cannot find"], "adult"),
    Platform("Xvideos",      "https://www.xvideos.com/profiles/{}",  "status", [], "adult"),
    Platform("Chaturbate",   "https://chaturbate.com/{}",            "status", [], "adult"),
    Platform("xHamster",     "https://xhamster.com/users/{}",        "status", [], "adult"),
    Platform("Badoo",        "https://badoo.com/profile/{}",         "status", [], "adult"),

    # ── Gaming ──────────────────────────────────────────────────────────────
    Platform("Steam",        "https://steamcommunity.com/id/{}",     "body", ["The specified profile could not be found"], "gaming"),
    Platform("Xbox",         "https://www.xboxgamertag.com/search/{}","body", ["not found"], "gaming"),
    Platform("Twitch",       "https://www.twitch.tv/{}",             "body", ["channel does not exist"], "gaming"),
    Platform("Kick",         "https://kick.com/{}",                  "body", ["404"], "gaming"),
    Platform("Chess.com",    "https://www.chess.com/member/{}",      "body", ["Oops"], "gaming"),
    Platform("Lichess",      "https://lichess.org/@/{}",             "body", ["Page not found"], "gaming"),
    Platform("Osu!",         "https://osu.ppy.sh/users/{}",          "body", ["User not found"], "gaming"),
    Platform("NameMC",       "https://namemc.com/profile/{}",        "body", ["Not Found"], "gaming"),
    Platform("Faceit",       "https://www.faceit.com/en/players/{}", "status", [], "gaming"),
    Platform("Roblox",       "https://www.roblox.com/user.aspx?username={}", "status", [], "gaming"),

    # ── Dev / Tech / IT ─────────────────────────────────────────────────────
    Platform("GitHub",       "https://github.com/{}",                "status", [], "dev"),
    Platform("GitLab",       "https://gitlab.com/{}",                "status", [], "dev"),
    Platform("Gitea",        "https://gitea.com/{}",                 "status", [], "dev"),
    Platform("BitBucket",    "https://bitbucket.org/{}/",            "status", [], "dev"),
    Platform("StackOverflow","https://stackoverflow.com/users/{}",   "body", ["Page Not Found"], "dev"),
    Platform("Pastebin",     "https://pastebin.com/u/{}",            "status", [], "dev"),
    Platform("Replit",       "https://replit.com/@{}",               "body", ["not found"], "dev"),
    Platform("HackerRank",   "https://www.hackerrank.com/{}",        "status", [], "dev"),
    Platform("LeetCode",     "https://leetcode.com/{}",              "status", [], "dev"),
    Platform("CodePen",      "https://codepen.io/{}",                "body", ["404"], "dev"),
    Platform("Kaggle",       "https://www.kaggle.com/{}",            "status", [], "dev"),
    Platform("npm",          "https://www.npmjs.com/~{}",            "body", ["404"], "dev"),
    Platform("PyPI",         "https://pypi.org/user/{}/",            "body", ["does not exist"], "dev"),
    Platform("DockerHub",    "https://hub.docker.com/u/{}",          "body", ["Page Not Found"], "dev"),
    Platform("Keybase",      "https://keybase.io/{}",                "body", ["Not found"], "dev"),

    # ── Forums & Niche Social ───────────────────────────────────────────────
    Platform("XDA-Devs",     "https://forum.xda-developers.com/m/{}/", "status", [], "forums"),
    Platform("MyAnimeList",  "https://myanimelist.net/profile/{}",   "status", [], "forums"),
    Platform("Wattpad",      "https://www.wattpad.com/user/{}",      "body", ["User not found"], "forums"),
    Platform("Goodreads",    "https://www.goodreads.com/{}",         "status", [], "forums"),
    Platform("Foursquare",   "https://foursquare.com/{}",            "status", [], "forums"),
    Platform("Archive.org",  "https://archive.org/details/@{}",      "status", [], "tech"),
    Platform("Wikipedia",    "https://en.wikipedia.org/wiki/User:{}", "status", [], "tech"),
    Platform("DeviantArt",   "https://www.deviantart.com/{}",        "status", [], "art"),
    Platform("FurAffinity",  "https://www.furaffinity.net/user/{}",  "status", [], "art"),
    Platform("ArtStation",   "https://www.artstation.com/{}",        "status", [], "art"),
    Platform("Pixiv",        "https://www.pixiv.net/en/users/{}",    "status", [], "art"),
    Platform("Behance",      "https://www.behance.net/{}",           "body", ["Page not found"], "art"),
    Platform("Dribbble",     "https://dribbble.com/{}",              "body", ["Whoops"], "art"),
    Platform("SoundCloud",   "https://soundcloud.com/{}",            "body", ["404"], "music"),
    Platform("Spotify",      "https://open.spotify.com/user/{}",     "body", ["Page not found"], "music"),
    Platform("Bandcamp",     "https://{}.bandcamp.com",              "body", ["Sorry"], "music"),
    Platform("Last.fm",      "https://www.last.fm/user/{}",          "body", ["User not found"], "music"),
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ── Scanner ───────────────────────────────────────────────────────────────────
class UsernameScanner:
    def __init__(self, username: str):
        self.username = username.strip().lstrip("@")

    async def scan(self) -> dict:
        """
        Check the username across all available sources.
        If Maigret is installed → run it (2,500+ sites) and merge with built-in.
        Otherwise → run built-in 83-platform scanner only.
        """
        # Run built-in scan always (fast, known platforms)
        builtin_task = self._scan_builtin()

        # Try Maigret in parallel if available
        maigret_task = self._scan_maigret() if is_available("maigret") else None

        if maigret_task:
            builtin_result, maigret_result = await asyncio.gather(
                builtin_task, maigret_task, return_exceptions=True,
            )
            if isinstance(maigret_result, Exception):
                _log.warning("Maigret failed, using built-in only: %s", maigret_result)
                maigret_result = None
        else:
            builtin_result = await builtin_task
            maigret_result = None

        if isinstance(builtin_result, Exception):
            builtin_result = {"username": self.username, "found": [], "not_found": [], "errors": [], "summary": {}}

        # Merge Maigret results into built-in
        if maigret_result:
            builtin_result = self._merge_results(builtin_result, maigret_result)

        return builtin_result

    async def _scan_maigret(self) -> dict | None:
        """Run Maigret CLI and parse NDJSON output (native or Docker)."""
        import os, tempfile, glob

        mode = get_mode("maigret")
        outdir = tempfile.mkdtemp(prefix="maigret_")
        try:
            if mode == "docker":
                # Docker: mount host outdir to /output inside container
                from core.tool_runner import _run_docker
                code, stdout, stderr = await _run_docker(
                    "soxoj/maigret",
                    [self.username, "-J", "ndjson", "--folderoutput", "/output",
                     "--timeout", "15", "--no-color"],
                    timeout=180,
                    stdin_data=None,
                    extra_args=["-v", f"{outdir}:/output"],
                )
            else:
                # Native: use --folderoutput on host path
                code, stdout, stderr = await run_tool(
                    "maigret",
                    [self.username, "-J", "ndjson", "--folderoutput", outdir,
                     "--timeout", "15", "--no-color"],
                    timeout=180,
                )

            # Find the NDJSON output file (named report_<username>_ndjson.json)
            ndjson_files = glob.glob(os.path.join(outdir, "*ndjson*"))
            if not ndjson_files:
                return None

            found, not_found = [], []
            seen_platforms = set()
            with open(ndjson_files[0], "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    site_name = entry.get("sitename") or entry.get("siteName") or entry.get("name", "unknown")
                    if site_name in seen_platforms:
                        continue
                    seen_platforms.add(site_name)

                    item = {
                        "platform": site_name,
                        "url": entry.get("url_user", entry.get("url_main", "")),
                        "category": entry.get("tags", ["other"])[0] if entry.get("tags") else "other",
                        "source": "maigret",
                    }

                    status = entry.get("status", {})
                    if isinstance(status, dict):
                        is_claimed = status.get("status") == "Claimed"
                    else:
                        is_claimed = str(status) == "Claimed"

                    if is_claimed:
                        item["status"] = "found"
                        found.append(item)
                    else:
                        item["status"] = "not_found"
                        not_found.append(item)

            return {
                "found": found,
                "not_found": not_found,
                "total_checked": len(seen_platforms),
            }
        except Exception as e:
            _log.warning("Maigret execution failed: %s", e)
            return None
        finally:
            import shutil
            shutil.rmtree(outdir, ignore_errors=True)

    def _merge_results(self, builtin: dict, maigret: dict) -> dict:
        """Merge Maigret results into built-in, deduplicating by platform name."""
        # Platforms already found by built-in
        builtin_names = {r["platform"].lower() for r in builtin["found"]}
        builtin_names |= {r["platform"].lower() for r in builtin["not_found"]}
        builtin_names |= {r["platform"].lower() for r in builtin.get("errors", [])}

        # Add Maigret-only platforms
        maigret_extra_found = []
        maigret_extra_not_found = []
        for item in maigret.get("found", []):
            if item["platform"].lower() not in builtin_names:
                maigret_extra_found.append(item)
        for item in maigret.get("not_found", []):
            if item["platform"].lower() not in builtin_names:
                maigret_extra_not_found.append(item)

        merged_found = builtin["found"] + maigret_extra_found
        merged_not_found = builtin["not_found"] + maigret_extra_not_found

        total = len(merged_found) + len(merged_not_found) + len(builtin.get("errors", []))
        return {
            "username": self.username,
            "found": sorted(merged_found, key=lambda x: x["platform"]),
            "not_found": sorted(merged_not_found, key=lambda x: x["platform"]),
            "errors": builtin.get("errors", []),
            "summary": {
                "found": len(merged_found),
                "not_found": len(merged_not_found),
                "errors": len(builtin.get("errors", [])),
                "total": total,
                "maigret_extra": len(maigret_extra_found) + len(maigret_extra_not_found),
                "engine": "maigret+builtin" if maigret else "builtin",
            },
        }

    async def _scan_builtin(self) -> dict:
        """Built-in check across 83 platforms with rate limiting."""
        sem = asyncio.Semaphore(30)  # מגביל ל-30 בקשות בו-זמנית למניעת חסימות והעמסה
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=15,  # הארכנו ל-15 שניות לאתרים נידחים וכבדים
            verify=False,
        ) as client:
            tasks = [self._check(client, p, sem) for p in PLATFORMS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        found, not_found, errors = [], [], []
        for r in results:
            if isinstance(r, Exception):
                continue
            if r["status"] == "found":
                found.append(r)
            elif r["status"] == "error":
                errors.append(r)
            else:
                not_found.append(r)

        return {
            "username":  self.username,
            "found":     sorted(found,     key=lambda x: x["platform"]),
            "not_found": sorted(not_found, key=lambda x: x["platform"]),
            "errors":    errors,
            "summary": {
                "found":     len(found),
                "not_found": len(not_found),
                "errors":    len(errors),
                "total":     len(PLATFORMS),
            },
        }

    async def _check(self, client: httpx.AsyncClient, platform: Platform, sem: asyncio.Semaphore) -> dict:
        async with sem:
            url = platform.url.format(self.username)
            base = {
                "platform": platform.name,
                "url":      url,
                "category": platform.category,
            }
            try:
                r = await client.get(url)
    
                if platform.check == "status":
                    found = r.status_code == 200
                else:
                    body_lower = r.text.lower()
                    found = r.status_code == 200 and not any(
                        phrase.lower() in body_lower
                        for phrase in platform.not_found
                    )
    
                return {**base, "status": "found" if found else "not_found"}
    
            except Exception as e:
                return {**base, "status": "error", "error": str(e)[:80]}
