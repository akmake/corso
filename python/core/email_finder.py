"""
email_finder.py — Discover email addresses for a person by name + domain.

Strategy (in order):
1. Hunter.io API — professional email finder (50 free/month), set HUNTER_API_KEY env var
2. Name permutation generation — all common firstname.lastname@domain patterns
3. SMTP verification — check MX records + VRFY/RCPT TO without sending mail
4. Holehe — check which services are registered with an email (if installed)
5. GitHub commit search — find public commit emails for a username
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import smtplib
import logging
from itertools import product
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import httpx

from core.tool_runner import is_available, run_tool

log = logging.getLogger(__name__)

_HUNTER_KEY = os.getenv("HUNTER_API_KEY", "")
_HUNTER_SEARCH_URL = "https://api.hunter.io/v2/email-finder"
_HUNTER_VERIFY_URL = "https://api.hunter.io/v2/email-verifier"

_executor = ThreadPoolExecutor(max_workers=4)

# Common Israeli/international free email providers to skip permutation on
_FREE_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "walla.co.il", "walla.com", "bezeqint.net", "netvision.net.il",
    "012.net.il", "013.net", "017.net.il",
})

_EMAIL_RE = re.compile(r'\b[a-zA-Z][a-zA-Z0-9._%+\-]{1,40}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')


# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------

def _transliterate_he_to_en(name: str) -> list[str]:
    """
    Very rough Hebrew → English transliteration for common names.
    Returns possible English spellings.
    """
    mapping = {
        'א': ['a', ''],
        'ב': ['b', 'v'],
        'ג': ['g'],
        'ד': ['d'],
        'ה': ['h', ''],
        'ו': ['v', 'u', 'o', 'w'],
        'ז': ['z'],
        'ח': ['h', 'ch'],
        'ט': ['t'],
        'י': ['y', 'i', ''],
        'כ': ['k', 'c'],
        'ך': ['k', 'ch'],
        'ל': ['l'],
        'מ': ['m'],
        'ם': ['m'],
        'נ': ['n'],
        'ן': ['n'],
        'ס': ['s'],
        'ע': ['a', ''],
        'פ': ['p', 'f'],
        'ף': ['f', 'p'],
        'צ': ['tz', 'ts', 'z'],
        'ץ': ['tz', 'ts'],
        'ק': ['k', 'q'],
        'ר': ['r'],
        'ש': ['sh', 's'],
        'ת': ['t', 'th'],
    }
    results = ['']
    for char in name:
        options = mapping.get(char, [char])
        results = [prev + opt for prev in results for opt in options]
        # Cap explosion
        if len(results) > 64:
            results = results[:64]
    return list(set(r for r in results if r))


def _build_name_variants(first: str, last: str) -> list[tuple[str, str]]:
    """
    Generate (first_variant, last_variant) pairs, handling Hebrew input.
    """
    pairs = [(first, last)]

    def _is_hebrew(s: str) -> bool:
        return any('\u05d0' <= c <= '\u05ea' for c in s)

    if _is_hebrew(first):
        first_en_list = _transliterate_he_to_en(first)
    else:
        first_en_list = [first.lower()]

    if _is_hebrew(last):
        last_en_list = _transliterate_he_to_en(last)
    else:
        last_en_list = [last.lower()]

    for f, l in product(first_en_list, last_en_list):
        if f and l:
            pairs.append((f.lower(), l.lower()))

    # deduplicate preserving order
    seen = set()
    unique = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique[:20]  # cap


def generate_email_permutations(first: str, last: str, domain: str) -> list[str]:
    """
    Generate all common email patterns for first + last + domain.
    """
    if not first or not last or not domain:
        return []

    variants = _build_name_variants(first, last)
    patterns_seen = set()
    emails = []

    for f, l in variants:
        if not f or not l:
            continue
        fi = f[0]  # first initial
        li = l[0]  # last initial
        candidates = [
            f"{f}.{l}",
            f"{f}{l}",
            f"{f}_{l}",
            f"{fi}{l}",
            f"{fi}.{l}",
            f"{f}.{li}",
            f"{f}{li}",
            f"{l}.{f}",
            f"{l}{f}",
            f"{l}_{f}",
            f"{li}{f}",
            f"{f}",
            f"{l}",
        ]
        for local in candidates:
            email = f"{local}@{domain}"
            if email not in patterns_seen:
                patterns_seen.add(email)
                emails.append(email)

    return emails


# ---------------------------------------------------------------------------
# Hunter.io
# ---------------------------------------------------------------------------

async def hunter_find(first: str, last: str, domain: str) -> Optional[dict]:
    """Call Hunter.io email-finder API. Returns dict or None."""
    if not _HUNTER_KEY:
        return None
    params = {
        "first_name": first,
        "last_name": last,
        "domain": domain,
        "api_key": _HUNTER_KEY,
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(_HUNTER_SEARCH_URL, params=params)
            if r.status_code == 200:
                data = r.json().get("data", {})
                email = data.get("email")
                score = data.get("score", 0)
                if email and score > 20:
                    return {
                        "email": email,
                        "confidence": round(score / 100, 2),
                        "source": "hunter.io",
                        "verified": data.get("smtp_check", False),
                    }
    except Exception as exc:
        log.debug("Hunter.io error: %s", exc)
    return None


async def hunter_verify(email: str) -> dict:
    """Verify a single email via Hunter.io. Returns verification dict."""
    if not _HUNTER_KEY:
        return {"email": email, "verified": None, "source": "hunter.io (no key)"}
    params = {"email": email, "api_key": _HUNTER_KEY}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(_HUNTER_VERIFY_URL, params=params)
            if r.status_code == 200:
                data = r.json().get("data", {})
                return {
                    "email": email,
                    "status": data.get("status"),          # "valid" / "invalid" / "risky"
                    "score": data.get("score", 0),
                    "smtp_check": data.get("smtp_check"),
                    "source": "hunter.io",
                }
    except Exception as exc:
        log.debug("Hunter.io verify error: %s", exc)
    return {"email": email, "verified": None}


# ---------------------------------------------------------------------------
# SMTP verification (no Hunter key needed)
# ---------------------------------------------------------------------------

def _get_mx_host(domain: str) -> Optional[str]:
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, 'MX')
        best = sorted(answers, key=lambda r: r.preference)[0]
        return str(best.exchange).rstrip('.')
    except Exception:
        pass
    # Fallback: try mail.domain
    return f"mail.{domain}"


def _smtp_verify_sync(email: str) -> dict:
    domain = email.split('@')[-1]
    mx = _get_mx_host(domain)
    result = {"email": email, "deliverable": None, "mx": mx, "source": "smtp_verify"}
    if not mx:
        result["deliverable"] = False
        return result
    try:
        with smtplib.SMTP(timeout=10) as smtp:
            smtp.connect(mx, 25)
            smtp.ehlo("example.com")
            smtp.mail("probe@example.com")
            code, _ = smtp.rcpt(email)
            result["deliverable"] = (code == 250)
    except smtplib.SMTPRecipientsRefused:
        result["deliverable"] = False
    except Exception as exc:
        log.debug("SMTP verify error for %s: %s", email, exc)
        result["deliverable"] = None  # inconclusive
    return result


async def smtp_verify(email: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _smtp_verify_sync, email)


# ---------------------------------------------------------------------------
# Holehe (check service registrations)
# ---------------------------------------------------------------------------

async def holehe_check(email: str) -> list[dict]:
    """
    Use holehe to check which services are registered with this email.
    Returns list of {service, registered, source}.
    Requires: pip install holehe
    """
    try:
        import holehe.core as holehe_core  # type: ignore
        import holehe.modules  # type: ignore
        import importlib, pkgutil

        modules = []
        for _, modname, _ in pkgutil.walk_packages(
            holehe.modules.__path__, prefix="holehe.modules."
        ):
            try:
                mod = importlib.import_module(modname)
                fn_name = modname.split('.')[-1]
                fn = getattr(mod, fn_name, None)
                if callable(fn):
                    modules.append(fn)
            except Exception:
                pass

        results = []
        loop = asyncio.get_event_loop()

        async def _check_one(fn):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    out = []
                    await fn(email, session, out)
                    return out
            except Exception:
                return []

        tasks = [_check_one(fn) for fn in modules[:30]]  # cap at 30 services
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for service_results in all_results:
            if isinstance(service_results, list):
                for item in service_results:
                    if item.get("exists"):
                        results.append({
                            "service": item.get("name", "unknown"),
                            "registered": True,
                            "source": "holehe",
                        })
        return results

    except ImportError:
        log.debug("holehe not installed")
        return []
    except Exception as exc:
        log.warning("holehe error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# GitHub commit email search
# ---------------------------------------------------------------------------

async def github_commit_emails(username: str) -> list[str]:
    """Search GitHub commit history for email addresses associated with a username."""
    emails = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get user's repos
            r = await client.get(
                f"https://api.github.com/users/{username}/repos",
                params={"per_page": 10, "sort": "pushed"},
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if r.status_code != 200:
                return []
            repos = r.json()

            for repo in repos[:5]:
                repo_name = repo.get("name", "")
                commits_r = await client.get(
                    f"https://api.github.com/repos/{username}/{repo_name}/commits",
                    params={"author": username, "per_page": 5},
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                if commits_r.status_code != 200:
                    continue
                for commit in commits_r.json():
                    author = commit.get("commit", {}).get("author", {})
                    email = author.get("email", "")
                    if email and not email.endswith("@users.noreply.github.com"):
                        emails.add(email)

    except Exception as exc:
        log.debug("GitHub commit email search error: %s", exc)

    return list(emails)


# ---------------------------------------------------------------------------
# Epieos-style reverse email enrichment
# ---------------------------------------------------------------------------

async def reverse_email_enrich(email: str) -> dict:
    """
    Enrich an email address — check Google account, Gravatar, etc.
    Uses public endpoints (no API key needed).
    """
    result = {"email": email, "profiles": [], "gravatar": None}

    # Gravatar
    try:
        import hashlib
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{email_hash}.json"
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(gravatar_url)
            if r.status_code == 200:
                data = r.json()
                entry = data.get("entry", [{}])[0]
                result["gravatar"] = {
                    "display_name": entry.get("displayName"),
                    "username": entry.get("preferredUsername"),
                    "profile_url": entry.get("profileUrl"),
                    "about_me": entry.get("aboutMe"),
                    "location": (entry.get("addresses") or [{}])[0].get("formatted"),
                }
                result["profiles"].append({"service": "gravatar", "url": entry.get("profileUrl")})
    except Exception as exc:
        log.debug("Gravatar lookup error: %s", exc)

    return result


# ---------------------------------------------------------------------------
# theHarvester integration — finds real emails from a domain using OSINT sources
# ---------------------------------------------------------------------------

async def _run_theharvester(domain: str) -> list[str]:
    """Run theHarvester to find real-world emails for a domain."""
    try:
        code, stdout, stderr = await run_tool(
            "theHarvester",
            ["-d", domain, "-b", "duckduckgo,bing,crtsh", "-l", "100"],
            timeout=90,
        )
        emails = set()
        for line in stdout.splitlines():
            line = line.strip()
            # theHarvester outputs emails as plain text lines
            match = _EMAIL_RE.search(line)
            if match:
                email = match.group(0).lower()
                if email.endswith(domain):
                    emails.add(email)
        return sorted(emails)
    except Exception as e:
        log.warning("theHarvester failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Main EmailFinder class
# ---------------------------------------------------------------------------

class EmailFinder:
    """
    Find and verify email addresses for a person.

    Usage:
        finder = EmailFinder(first="משה", last="קהן", domain="example.com")
        results = await finder.find()
        # returns list of {email, confidence, verified, source, ...}
    """

    def __init__(
        self,
        first: str,
        last: str,
        domain: str = "",
        username: str = "",
        verify: bool = True,
    ):
        self.first = first.strip()
        self.last = last.strip()
        self.domain = domain.strip().lstrip("@")
        self.username = username.strip()
        self.verify = verify

    async def find(self) -> list[dict]:
        found: list[dict] = []
        seen_emails: set[str] = set()

        # 1. Hunter.io (if domain provided and not free provider)
        if self.domain and self.domain not in _FREE_PROVIDERS and _HUNTER_KEY:
            hit = await hunter_find(self.first, self.last, self.domain)
            if hit and hit["email"] not in seen_emails:
                seen_emails.add(hit["email"])
                found.append(hit)

        # 1.5. theHarvester (if installed — finds real emails from domain)
        if self.domain and self.domain not in _FREE_PROVIDERS and is_available("theHarvester"):
            harvested = await _run_theharvester(self.domain)
            for email in harvested:
                if email not in seen_emails:
                    seen_emails.add(email)
                    found.append({
                        "email": email,
                        "confidence": 0.80,
                        "verified": False,
                        "source": "theHarvester",
                    })

        # 2. Permutation + SMTP verification (if domain is a company/org domain)
        if self.domain and self.domain not in _FREE_PROVIDERS:
            permutations = generate_email_permutations(self.first, self.last, self.domain)
            if self.verify and permutations:
                # Verify top permutations via SMTP (limit to 8 to avoid rate limits)
                verify_tasks = [smtp_verify(e) for e in permutations[:8]]
                verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)
                for vr in verify_results:
                    if isinstance(vr, dict) and vr.get("deliverable"):
                        email = vr["email"]
                        if email not in seen_emails:
                            seen_emails.add(email)
                            found.append({
                                "email": email,
                                "confidence": 0.75,
                                "verified": True,
                                "source": "smtp_verify",
                            })
            else:
                for email in permutations[:5]:
                    if email not in seen_emails:
                        seen_emails.add(email)
                        found.append({
                            "email": email,
                            "confidence": 0.3,
                            "verified": False,
                            "source": "permutation",
                        })

        # 3. GitHub commit emails (if username given)
        if self.username:
            gh_emails = await github_commit_emails(self.username)
            for email in gh_emails:
                if email not in seen_emails:
                    seen_emails.add(email)
                    found.append({
                        "email": email,
                        "confidence": 0.85,
                        "verified": True,
                        "source": "github_commits",
                    })

        # 4. Enrich found emails with Gravatar/reverse lookup
        enrich_tasks = [reverse_email_enrich(e["email"]) for e in found[:5]]
        enrichments = await asyncio.gather(*enrich_tasks, return_exceptions=True)
        for i, enrichment in enumerate(enrichments):
            if isinstance(enrichment, dict) and i < len(found):
                if enrichment.get("gravatar"):
                    found[i]["gravatar"] = enrichment["gravatar"]
                if enrichment.get("profiles"):
                    found[i]["linked_profiles"] = enrichment["profiles"]

        return found

    async def check_email(self, email: str) -> dict:
        """Full check on a specific email: verify + holehe + enrichment."""
        result = {"email": email}

        # SMTP verify
        smtp_result = await smtp_verify(email)
        result["deliverable"] = smtp_result.get("deliverable")
        result["mx"] = smtp_result.get("mx")

        # Hunter verify (if key available)
        if _HUNTER_KEY:
            hunter_result = await hunter_verify(email)
            result["hunter_status"] = hunter_result.get("status")
            result["hunter_score"] = hunter_result.get("score")

        # Holehe (service registrations)
        services = await holehe_check(email)
        result["registered_services"] = services

        # Enrichment
        enrichment = await reverse_email_enrich(email)
        result["gravatar"] = enrichment.get("gravatar")
        result["profiles"] = enrichment.get("profiles", [])

        return result
