"""
Person Intelligence Module
--------------------------
Takes a name / email / phone and extracts every public data point available.

External tool integration:
  - Holehe (if installed): checks email on 120+ services (vs 5 built-in)

Email:
  - Format & domain validation (MX records)
  - Gravatar profile (linked avatar, display name)
  - HaveIBeenPwned breach check
  - Social account registration check (120+ sites via Holehe, fallback to 5 built-in)
  - Domain intel on the email provider
  - Google/Bing dork links

Phone:
  - Full parsing: country, carrier, line type (mobile/landline/VoIP)
  - Israeli number breakdown (operator, region)
  - WhatsApp presence check
  - Telegram presence check
  - Google/Bing dork links

Name:
  - Google dork search
  - Username variations generated from the name
  - Run those variations through the SOCMINT scanner
  - LinkedIn / Facebook / Twitter search links
"""

import asyncio
import hashlib
import re
import urllib.parse
from bs4 import BeautifulSoup
from typing import Any

import httpx
import dns.resolver

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

from core.socmint import UsernameScanner

# ── Holehe integration (email → 120+ service check) ──────────────────────────
try:
    import holehe.core as holehe_core
    import httpx as _holehe_httpx
    HOLEHE_AVAILABLE = True
except ImportError:
    HOLEHE_AVAILABLE = False


async def _holehe_check(email: str) -> dict:
    """Run Holehe to check email registration on 120+ services."""
    if not HOLEHE_AVAILABLE:
        return {"available": False}
    try:
        out = []
        await holehe_core.import_submodules()
        modules = holehe_core.get_functions()
        client = _holehe_httpx.AsyncClient(timeout=15, verify=False)
        try:
            tasks = []
            for module in modules:
                tasks.append(module(email, client, out))
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await client.aclose()

        found = [r["name"] for r in out if r.get("exists") is True]
        not_found = [r["name"] for r in out if r.get("exists") is False]
        unknown = [r["name"] for r in out if r.get("exists") is None]

        return {
            "available": True,
            "found": sorted(found),
            "not_found": sorted(not_found),
            "unknown": unknown,
            "total_checked": len(out),
            "engine": "holehe",
        }
    except Exception as e:
        return {"available": True, "error": str(e)}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
}

EMAIL_RE = re.compile(r'^[\w.+\-]+@[\w\-]+\.[\w.]{2,}$')
PHONE_RE = re.compile(r'^[\+\d\s\-\(\)\.]{7,20}$')


# ── Site list for email registration check ────────────────────────────────────
# Each entry: (platform_name, method, url_or_endpoint, body_template, found_indicator, not_found_indicator)
# method: "forgot" = POST to forgot-password endpoint
#         "register" = POST to registration endpoint
#         "get" = GET profile URL

EMAIL_SITES = [
    {
        "name": "GitHub",
        "url":  "https://github.com/password_reset",
        "method": "post",
        "body": {"email": "{email}"},
        "found": "We will send you an email",
        "not_found": "Email not found",
    },
    {
        "name": "Gravatar",
        "url":  "https://en.gravatar.com/{hash}",  # MD5 hash of email
        "method": "gravatar",
        "found": '"entry"',
        "not_found": "User not found",
    },
    {
        "name": "Twitter/X",
        "url":  "https://api.twitter.com/i/users/email_available.json?email={email}",
        "method": "get",
        "found": '"valid":false',    # false = already taken = account exists
        "not_found": '"valid":true',
    },
    {
        "name": "Instagram",
        "url":  "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
        "method": "post",
        "body": {"email": "{email}", "username": "", "first_name": ""},
        "found": "email_is_taken",
        "not_found": "email_is_available",
    },
    {
        "name": "Spotify",
        "url":  "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
        "method": "get",
        "found": '"status":20',   # 20 = already registered
        "not_found": '"status":10',
    },
    {
        "name": "Adobe",
        "url":  "https://auth.services.adobe.com/en_US/index.html#from=https://www.adobe.com/",
        "method": "get_email_check",
        "check_url": "https://ims-na1.adobelogin.com/ims/check/v1/token?client_id=adobeid&email={email}",
        "found": "foundInadobe",
        "not_found": "notFoundInAdobe",
    },
    {
        "name": "Duolingo",
        "url":  "https://www.duolingo.com/2017-06-30/users?email={email}",
        "method": "get",
        "found": '"users":[{',
        "not_found": '"users":[]',
    },
    {
        "name": "Dropbox",
        "url":  "https://www.dropbox.com/forgot",
        "method": "post",
        "body": {"email": "{email}"},
        "found": "Check your email",
        "not_found": "There is no account",
    },
    {
        "name": "Pinterest",
        "url":  "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data=%7B%22options%22%3A%7B%22email%22%3A%22{email}%22%7D%7D",
        "method": "get",
        "found": '"is_taken": true',
        "not_found": '"is_taken": false',
    },
    {
        "name": "Imgur",
        "url":  "https://imgur.com/signin",
        "method": "post",
        "body": {"username": "{email}"},
        "found": '"email": "Email"',  # crude check
        "not_found": "Username or email not found",
    },
]


def _detect_type(query: str) -> str:
    q = query.strip()
    if EMAIL_RE.match(q):
        return "email"
    # Detect phone: mostly digits + allowed separators
    digits = re.sub(r'[^\d]', '', q)
    if len(digits) >= 7 and PHONE_RE.match(q):
        return "phone"
    return "name"


def _generate_username_variants(name: str) -> list[str]:
    """Generate common username variations from a full name."""
    parts = name.lower().split()
    if not parts:
        return []

    first = parts[0]
    last  = parts[-1] if len(parts) > 1 else ""
    variants = set()

    if first:
        variants.add(first)
    if last:
        variants.add(last)
    if first and last:
        variants.update([
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{last}_{first}",
            f"{first[0]}.{last}",
        ])
    return sorted(variants)[:8]


class PersonIntel:
    def __init__(self, query: str, query_type: str = "auto"):
        self.query      = query.strip()
        self.query_type = query_type if query_type != "auto" else _detect_type(query)

    async def investigate(self) -> dict:
        async with httpx.AsyncClient(
            headers=HEADERS,
            follow_redirects=True,
            timeout=15,
            verify=False,
        ) as client:
            if self.query_type == "email":
                return await self._email_intel(client)
            elif self.query_type == "phone":
                return await self._phone_intel(client)
            else:
                return await self._name_intel(client)
                
    # ── מנוע Dorking אמיתי (Deep Web Scraper) ─────────────────────────────────
    async def _deep_dork(self, client: httpx.AsyncClient, query: str) -> list[dict]:
        """
        שולח בקשה ל-DuckDuckGo HTML ו-Bing כ-fallback.
        הבאג הישן: חיפש result__url (span ללא href) — עכשיו מחפש result__a (הלינק האמיתי).
        """
        results: list[dict] = []
        encoded_q = urllib.parse.quote(f'"{query}"')

        # 1. DuckDuckGo HTML (POST עוקף חלק מהחסימות)
        try:
            r = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{query}"'},
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for result in soup.find_all("div", class_="result"):
                    # result__a הוא הלינק האמיתי — result__url הוא טקסט תצוגה בלבד (ללא href)
                    link_tag = result.find("a", class_="result__a")
                    snippet_tag = result.find("a", class_="result__snippet")
                    if not link_tag:
                        continue
                    link = link_tag.get("href", "")
                    # DDG לפעמים עוטף ב-redirect
                    if "duckduckgo.com/l/?" in link or link.startswith("//duckduckgo.com"):
                        try:
                            link = urllib.parse.unquote(link.split("uddg=")[1].split("&")[0])
                        except Exception:
                            continue
                    if link and link.startswith("http"):
                        results.append({
                            "url": link,
                            "title": link_tag.get_text(strip=True),
                            "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                        })
        except Exception:
            pass

        # 2. Bing fallback — אם DDG חסום או ריק
        if len(results) < 3:
            try:
                r = await client.get(
                    f"https://www.bing.com/search?q={encoded_q}&count=10",
                    timeout=15,
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for li in soup.find_all("li", class_="b_algo"):
                        h2 = li.find("h2")
                        a = h2.find("a") if h2 else None
                        cap = li.find("div", class_="b_caption") or li.find("p")
                        if a and a.get("href", "").startswith("http"):
                            results.append({
                                "url": a.get("href"),
                                "title": a.get_text(strip=True),
                                "snippet": cap.get_text(strip=True) if cap else "",
                            })
            except Exception:
                pass

        # Deduplicate by URL
        seen: set[str] = set()
        unique = []
        for r in results:
            if r["url"] not in seen:
                seen.add(r["url"])
                unique.append(r)
        return unique[:10]

    # ── Email ─────────────────────────────────────────────────────────────────
    async def _email_intel(self, client: httpx.AsyncClient) -> dict:
        email   = self.query
        local   = email.split("@")[0]
        domain  = email.split("@")[-1]

        results = await asyncio.gather(
            self._email_validate(domain),
            self._gravatar(client, email),
            self._hibp_check(client, email),
            self._email_social_check(client, email),
            self._deep_dork(client, email),
            self._github_by_email(client, email),
            return_exceptions=True,
        )

        keys = ["validation", "gravatar", "breaches", "social_accounts", "deep_dorks", "github"]
        data: dict[str, Any] = {"query": email, "type": "email", "local": local, "domain": domain}
        for key, r in zip(keys, results):
            data[key] = r if not isinstance(r, Exception) else {"error": str(r)}

        data["search_links"] = _search_links(f'"{email}"')
        return data

    async def _github_by_email(self, client: httpx.AsyncClient, email: str) -> dict:
        """
        GitHub API v3 — חיפוש משתמשים לפי אימייל (ציבורי, ללא auth).
        מוצא פרופיל GitHub אם האימייל גלוי ציבורית בפרופיל.
        """
        try:
            # חיפוש commits עם האימייל — GitHub חושף מחבר commits
            r = await client.get(
                f"https://api.github.com/search/commits?q=author-email:{email}&per_page=3",
                headers={**HEADERS, "Accept": "application/vnd.github.cloak-preview+json"},
                timeout=10,
            )
            result: dict[str, Any] = {"found": False}
            if r.status_code == 200:
                data = r.json()
                commits = data.get("items", [])
                if commits:
                    author = commits[0].get("commit", {}).get("author", {})
                    committer = commits[0].get("author") or {}
                    result = {
                        "found":    True,
                        "username": committer.get("login"),
                        "name":     author.get("name"),
                        "profile":  committer.get("html_url"),
                        "avatar":   committer.get("avatar_url"),
                        "repos_seen": list({c.get("repository", {}).get("full_name") for c in commits if c.get("repository")}),
                    }
            # חיפוש משתמשים ישיר
            r2 = await client.get(
                f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email&per_page=3",
                headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if r2.status_code == 200:
                users = r2.json().get("items", [])
                if users:
                    u = users[0]
                    # קבל פרטים מלאים
                    r3 = await client.get(u["url"], headers={**HEADERS}, timeout=8)
                    if r3.status_code == 200:
                        ud = r3.json()
                        result.update({
                            "found":       True,
                            "username":    ud.get("login"),
                            "name":        ud.get("name"),
                            "profile":     ud.get("html_url"),
                            "avatar":      ud.get("avatar_url"),
                            "bio":         ud.get("bio"),
                            "company":     ud.get("company"),
                            "location":    ud.get("location"),
                            "blog":        ud.get("blog"),
                            "public_repos":ud.get("public_repos"),
                            "followers":   ud.get("followers"),
                            "created_at":  ud.get("created_at"),
                        })
            return result
        except Exception as e:
            return {"found": False, "error": str(e)}

    async def _email_validate(self, domain: str) -> dict:
        info: dict[str, Any] = {"domain": domain, "mx_records": [], "valid_mx": False}
        try:
            mx = dns.resolver.resolve(domain, "MX")
            info["mx_records"] = sorted(str(r) for r in mx)
            info["valid_mx"]   = True
        except Exception:
            info["valid_mx"] = False
        return info

    async def _gravatar(self, client: httpx.AsyncClient, email: str) -> dict:
        h   = hashlib.md5(email.lower().strip().encode()).hexdigest()
        url = f"https://www.gravatar.com/{h}.json"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code == 200:
                entry = r.json().get("entry", [{}])[0]
                return {
                    "found":        True,
                    "display_name": entry.get("displayName"),
                    "username":     entry.get("preferredUsername"),
                    "location":     entry.get("currentLocation"),
                    "about":        entry.get("aboutMe"),
                    "urls":         [u.get("value") for u in entry.get("urls", [])],
                    "avatar":       f"https://www.gravatar.com/avatar/{h}?s=200",
                    "profile_url":  f"https://gravatar.com/{h}",
                }
            return {"found": False}
        except Exception as e:
            return {"found": False, "error": str(e)}

    async def _hibp_check(self, client: httpx.AsyncClient, email: str) -> dict:
        """
        Check HaveIBeenPwned v3 API.
        ב-2025 HIBP דורש API Key בתשלום לחיפוש אימיילים של אחרים.
        אם אין key מקבלים 401 — מחזירים לינק לבדיקה ידנית.
        """
        encoded = urllib.parse.quote(email)
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"
        try:
            r = await client.get(
                url,
                headers={**HEADERS, "hibp-api-key": ""},
                timeout=10,
            )
            if r.status_code == 200:
                breaches = r.json()
                return {
                    "found":    True,
                    "count":    len(breaches),
                    "breaches": [
                        {
                            "name":         b.get("Name"),
                            "domain":       b.get("Domain"),
                            "breach_date":  b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count":    b.get("PwnCount"),
                        }
                        for b in breaches
                    ],
                }
            elif r.status_code == 404:
                return {"found": False, "message": "לא נמצא בדליפות ידועות"}
            elif r.status_code == 401:
                # HIBP דורש API Key — מחזיר לינק לבדיקה ידנית
                return {
                    "found":       None,
                    "requires_key": True,
                    "check_url":   f"https://haveibeenpwned.com/account/{encoded}",
                    "message":     "HIBP דורש API Key — לחץ לבדיקה ידנית",
                }
            else:
                return {"found": None, "status": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    async def _email_social_check(self, client: httpx.AsyncClient, email: str) -> dict:
        """
        Check if email is registered on platforms.
        Uses Holehe (120+ services) if installed, otherwise falls back to 5 built-in checks.
        """
        # Try Holehe first (120+ services)
        if HOLEHE_AVAILABLE:
            holehe_result = await _holehe_check(email)
            if holehe_result.get("available") and "error" not in holehe_result:
                return holehe_result

        # Fallback to built-in 5-platform check
        found, not_found, errors = [], [], []

        checks = [
            self._check_github_email(client, email),
            self._check_spotify_email(client, email),
            self._check_duolingo_email(client, email),
            self._check_pinterest_email(client, email),
            self._check_dropbox_email(client, email),
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)

        platforms = ["GitHub", "Spotify", "Duolingo", "Pinterest", "Dropbox"]
        for name, r in zip(platforms, results):
            if isinstance(r, Exception):
                errors.append(name)
            elif r is True:
                found.append(name)
            elif r is False:
                not_found.append(name)
            else:
                errors.append(name)

        return {"found": found, "not_found": not_found, "errors": errors}

    async def _check_github_email(self, client: httpx.AsyncClient, email: str) -> bool | None:
        """Forgot-password endpoint — אם האימייל קיים GitHub שולח מייל איפוס."""
        try:
            r = await client.post(
                "https://github.com/password_reset",
                data={"email": email},
                timeout=10,
            )
            text = r.text
            if "We will send you an email" in text or "check your email" in text.lower():
                return True
            if "Email not found" in text or "no account" in text.lower():
                return False
            return None
        except Exception:
            return None

    async def _check_dropbox_email(self, client: httpx.AsyncClient, email: str) -> bool | None:
        try:
            r = await client.post(
                "https://www.dropbox.com/forgot",
                data={"email": email},
                timeout=10,
            )
            text = r.text
            if "Check your email" in text or "sent you an email" in text.lower():
                return True
            if "There is no account" in text or "no Dropbox" in text.lower():
                return False
            return None
        except Exception:
            return None

    async def _check_spotify_email(self, client: httpx.AsyncClient, email: str) -> bool | None:
        try:
            r = await client.get(
                f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={urllib.parse.quote(email)}",
                timeout=8,
            )
            data = r.json()
            return data.get("status") == 20
        except Exception:
            return None

    async def _check_duolingo_email(self, client: httpx.AsyncClient, email: str) -> bool | None:
        try:
            r = await client.get(
                f"https://www.duolingo.com/2017-06-30/users?email={urllib.parse.quote(email)}",
                timeout=8,
            )
            data = r.json()
            return bool(data.get("users"))
        except Exception:
            return None

    async def _check_pinterest_email(self, client: httpx.AsyncClient, email: str) -> bool | None:
        try:
            encoded = urllib.parse.quote(email)
            r = await client.get(
                f"https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data=%7B%22options%22%3A%7B%22email%22%3A%22{encoded}%22%7D%7D",
                timeout=8,
            )
            text = r.text
            if '"is_taken": true' in text or '"is_taken":true' in text:
                return True
            if '"is_taken": false' in text or '"is_taken":false' in text:
                return False
            return None
        except Exception:
            return None

    # ── Phone ─────────────────────────────────────────────────────────────────
    async def _phone_intel(self, client: httpx.AsyncClient) -> dict:
        phone = self.query
        data: dict[str, Any] = {"query": phone, "type": "phone"}

        # Parse with phonenumbers library
        data["parsed"] = self._parse_phone(phone)

        # Parallel checks
        results = await asyncio.gather(
            self._whatsapp_check(client, phone),
            self._telegram_check(client, phone),
            self._deep_dork(client, phone),
            return_exceptions=True,
        )
        data["whatsapp"] = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
        data["telegram"] = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
        data["deep_dorks"] = results[2] if not isinstance(results[2], Exception) else []
        data["search_links"] = _search_links(f'"{phone}"')
        return data

    def _parse_phone(self, phone: str) -> dict:
        if not PHONENUMBERS_AVAILABLE:
            return {"error": "pip install phonenumbers"}
        try:
            # Try with IL first (Israeli default), then without country code
            for region in ("IL", None):
                try:
                    parsed = phonenumbers.parse(phone, region)
                    if phonenumbers.is_valid_number(parsed):
                        break
                except Exception:
                    continue
            else:
                return {"valid": False, "raw": phone}

            line_type_map = {
                phonenumbers.PhoneNumberType.MOBILE:        "נייד (Mobile)",
                phonenumbers.PhoneNumberType.FIXED_LINE:    "קווי (Fixed line)",
                phonenumbers.PhoneNumberType.VOIP:          "VoIP",
                phonenumbers.PhoneNumberType.TOLL_FREE:     "חינם (Toll free)",
                phonenumbers.PhoneNumberType.PREMIUM_RATE:  "Premium rate",
                phonenumbers.PhoneNumberType.UNKNOWN:       "לא ידוע",
            }

            line_type = phonenumbers.number_type(parsed)
            geo       = geocoder.description_for_number(parsed, "he")
            carr      = carrier.name_for_number(parsed, "en")
            tzones    = list(timezone.time_zones_for_number(parsed))

            return {
                "valid":          True,
                "international":  phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "e164":           phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "national":       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "country_code":   f"+{parsed.country_code}",
                "country":        geocoder.description_for_number(parsed, "en"),
                "region":         geo or None,
                "carrier":        carr or None,
                "line_type":      line_type_map.get(line_type, "לא ידוע"),
                "timezones":      tzones,
                "possible":       phonenumbers.is_possible_number(parsed),
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    async def _whatsapp_check(self, client: httpx.AsyncClient, phone: str) -> dict:
        """Check WhatsApp via wa.me link."""
        digits = re.sub(r'[^\d]', '', phone)
        if not digits.startswith("972") and digits.startswith("0"):
            digits = "972" + digits[1:]
        wa_url = f"https://api.whatsapp.com/send?phone={digits}"
        try:
            r = await client.get(wa_url, timeout=10)
            # WhatsApp redirects to app if number exists
            found = "phone=" in str(r.url) and r.status_code == 200
            return {
                "likely_active": found,
                "link": f"https://wa.me/{digits}",
                "note": "פתח את הלינק לאימות ידני",
            }
        except Exception as e:
            return {"error": str(e)}

    async def _telegram_check(self, client: httpx.AsyncClient, phone: str) -> dict:
        """Telegram doesn't expose phone lookup publicly — returns manual link."""
        digits = re.sub(r'[^\d]', '', phone)
        if not digits.startswith("972") and digits.startswith("0"):
            digits = "972" + digits[1:]
        return {
            "note": "Telegram לא חושף חיפוש טלפון בפומבי",
            "manual_check": f"https://t.me/+{digits}",
        }

    # ── Name ──────────────────────────────────────────────────────────────────
    async def _name_intel(self, client: httpx.AsyncClient) -> dict:
        name     = self.query
        variants = _generate_username_variants(name)

        data: dict[str, Any] = {
            "query":             name,
            "type":              "name",
            "username_variants": variants,
            "search_links":      _search_links(f'"{name}"'),
            "social_search":     _social_search_links(name),
        }

        # Run username SOCMINT on variants
        if variants:
            all_found: list[dict] = []
            tasks = [UsernameScanner(v).scan() for v in variants[:4]]  # top 4 variants
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for variant, result in zip(variants[:4], results):
                if not isinstance(result, Exception):
                    for hit in result.get("found", []):
                        hit["searched_variant"] = variant
                        all_found.append(hit)

            # Deduplicate by platform
            seen: set[str] = set()
            unique_found = []
            for hit in all_found:
                if hit["platform"] not in seen:
                    seen.add(hit["platform"])
                    unique_found.append(hit)

            data["accounts_found"] = sorted(unique_found, key=lambda x: x["platform"])
            data["accounts_total"] = len(unique_found)
            
        # שאיבת מידע אמיתי מהרשת על השם
        data["deep_dorks"] = await self._deep_dork(client, name)

        return data


# ── Helpers ───────────────────────────────────────────────────────────────────
def _search_links(query: str) -> dict:
    encoded = urllib.parse.quote(query)
    return {
        "google":  f"https://www.google.com/search?q={encoded}",
        "bing":    f"https://www.bing.com/search?q={encoded}",
        "yandex":  f"https://yandex.com/search/?text={encoded}",
        "duckduckgo": f"https://duckduckgo.com/?q={encoded}",
    }

def _social_search_links(name: str) -> dict:
    encoded = urllib.parse.quote(name)
    return {
        "linkedin":  f"https://www.linkedin.com/search/results/people/?keywords={encoded}",
        "facebook":  f"https://www.facebook.com/search/people/?q={encoded}",
        "twitter":   f"https://twitter.com/search?q={encoded}&f=user",
        "instagram": f"https://www.instagram.com/explore/tags/{encoded.replace('+','')}/",
        "google":    f"https://www.google.com/search?q=site:linkedin.com+OR+site:facebook.com+{encoded}",
    }
