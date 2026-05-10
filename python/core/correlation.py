"""
Pivot Chain Engine
------------------
Automated recursive OSINT investigation via BFS.

Starting from a single seed (email, domain, IP, username, or phone),
the engine fans out through every available free data source, extracts
NEW entities from each result, and investigates those in turn — building
a complete intelligence graph automatically.

Architecture:
  BFS queue → _pivot() → entity extractor → confidence filter → enqueue
  All entities at the same BFS depth are investigated concurrently.
  Depth and node limits prevent runaway exploration.

Usage (same interface as the old CorrelationEngine):
    engine = CorrelationEngine("admin@example.com")
    result = await engine.build_graph()
    # result = {"target", "nodes", "edges", "stats"}
"""

import asyncio
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

# ── Regex helpers ─────────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r'^[\w.+\-]+@[\w\-]+\.[\w.]{2,}$')
_PHONE_RE = re.compile(r'^[\+\d\s\-\(\)\.]{7,20}$')
_IP_RE    = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

# Common email providers — the domain itself carries no investigation value
_COMMON_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "icloud.com", "protonmail.com", "proton.me", "mail.com",
    "yandex.com", "yandex.ru", "zoho.com", "aol.com",
    "live.com", "msn.com", "me.com", "mac.com",
})

# Shared infrastructure to skip as investigation targets (CDNs, big registrars)
_SKIP_DOMAINS = frozenset({
    "cloudflare.com", "akamai.com", "akamaiedge.net", "akamaitechnologies.com",
    "amazonaws.com", "awsdns-1.com", "awsdns-2.com", "awsdns-3.com",
    "googledomains.com", "google.com", "gstatic.com", "googlevideo.com",
    "fastly.net", "edgekey.net", "nsone.net", "incapdns.net",
    "registrar-servers.com", "name.com", "godaddy.com", "namecheap.com",
    "domaincontrol.com", "parkingcrew.net", "sedo.com",
})


def _is_skip_domain(domain: str) -> bool:
    d = domain.lower().strip().rstrip(".")
    return any(d == skip or d.endswith("." + skip) for skip in _SKIP_DOMAINS)


def _detect_type(value: str) -> str:
    v = value.strip()
    if _EMAIL_RE.match(v):
        return "email"
    if _IP_RE.match(v):
        return "ip"
    digits = re.sub(r'[^\d]', '', v)
    if len(digits) >= 7 and _PHONE_RE.match(v):
        return "phone"
    if re.match(r'^[\w\.-]+\.[a-zA-Z]{2,}$', v) and "/" not in v:
        return "domain"
    return "username"


# ── Internal entity representation ───────────────────────────────────────────
@dataclass
class _Entity:
    value:      str
    type:       str    # email | domain | ip | username | phone | social_profile
    source:     str    # human-readable "how this was found"
    confidence: float  # 0.0 – 1.0
    depth:      int = 0


# ── Main engine ───────────────────────────────────────────────────────────────
class CorrelationEngine:
    """
    BFS Pivot Chain Engine.

    Each entity type has a dedicated _pivot_* method that:
      1. Calls one or more real, free data sources
      2. Extracts NEW entities embedded in the results
      3. Returns them with a confidence score

    The engine enqueues every new entity above the confidence threshold
    and investigates it in the next BFS level — automatically.
    """

    CONFIDENCE_THRESHOLD = 0.45

    def __init__(self, target: str, max_depth: int = 3, max_nodes: int = 60):
        self.target    = target.strip()
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self._nodes:      dict[str, dict]  = {}   # node_id → node dict
        self._edges:      list[dict]       = []
        self._visited:    set[str]         = set()
        self._seen_edges: set[tuple]       = set()

    # ── Public API ────────────────────────────────────────────────────────────

    async def build_graph(self) -> dict:
        seed_type = _detect_type(self.target)
        queue: list[_Entity] = [_Entity(self.target, seed_type, "seed", 1.0, 0)]

        while queue and len(self._nodes) < self.max_nodes:
            # BFS: pull all entities at the current minimum depth
            min_depth   = min(e.depth for e in queue)
            current     = [e for e in queue if e.depth == min_depth]
            queue       = [e for e in queue if e.depth != min_depth]

            to_process = [
                e for e in current
                if e.value not in self._visited
                and e.confidence >= self.CONFIDENCE_THRESHOLD
                and e.depth <= self.max_depth
            ]
            if not to_process:
                continue

            # Register nodes before pivoting (so leaf social_profiles appear even if capped)
            for entity in to_process:
                self._visited.add(entity.value)
                self._nodes[entity.value] = {
                    "id":         entity.value,
                    "label":      entity.value,
                    "group":      entity.type,
                    "confidence": round(entity.confidence, 2),
                    "depth":      entity.depth,
                    "source":     entity.source,
                }

            # Pivot all entities at this BFS level concurrently
            pivot_results = await asyncio.gather(
                *[self._pivot(e) for e in to_process],
                return_exceptions=True,
            )

            for entity, new_entities in zip(to_process, pivot_results):
                if isinstance(new_entities, Exception):
                    continue
                for new_e in new_entities:
                    new_e.depth = entity.depth + 1
                    if new_e.value not in self._visited:
                        self._add_edge(entity.value, new_e.value, new_e.source, new_e.confidence)
                        queue.append(new_e)

        result = {
            "target": self.target,
            "nodes":  list(self._nodes.values()),
            "edges":  self._edges,
            "stats": {
                "total_nodes":       len(self._nodes),
                "total_edges":       len(self._edges),
                "by_type":           self._count_types(),
                "max_depth_reached": max((n["depth"] for n in self._nodes.values()), default=0),
            },
        }
        self._persist_to_neo4j(result)
        return result

    # ── Graph helpers ─────────────────────────────────────────────────────────

    def _add_edge(self, src: str, dst: str, label: str, confidence: float):
        key = (src, dst)
        if key not in self._seen_edges:
            self._seen_edges.add(key)
            self._edges.append({
                "from":       src,
                "to":         dst,
                "label":      label,
                "confidence": round(confidence, 2),
            })

    def _count_types(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self._nodes.values():
            t = node["group"]
            counts[t] = counts.get(t, 0) + 1
        return counts

    # ── Pivot dispatcher ──────────────────────────────────────────────────────

    async def _pivot(self, entity: _Entity) -> list[_Entity]:
        try:
            if entity.type == "domain":       return await self._pivot_domain(entity.value)
            if entity.type == "ip":           return await self._pivot_ip(entity.value)
            if entity.type == "email":        return await self._pivot_email(entity.value)
            if entity.type == "username":     return await self._pivot_username(entity.value)
            if entity.type == "phone":        return await self._pivot_phone(entity.value)
            # social_profile and breach are leaf nodes — nothing further to pivot
            return []
        except Exception:
            return []

    # ── Domain pivot ──────────────────────────────────────────────────────────

    async def _pivot_domain(self, domain: str) -> list[_Entity]:
        if _is_skip_domain(domain):
            return []

        from core.domain_intel import DomainIntelligence
        result  = await DomainIntelligence(domain).full_recon()
        entities: list[_Entity] = []

        # DNS A records → IPs
        for ip in result.get("dns", {}).get("A", []):
            entities.append(_Entity(ip, "ip", f"DNS A of {domain}", 0.95))

        # DNS MX → mail server domains  (format: "10 mail.example.com.")
        for mx in result.get("dns", {}).get("MX", []):
            mx_domain = mx.split()[-1].rstrip(".") if mx.split() else ""
            if mx_domain and mx_domain != domain and not _is_skip_domain(mx_domain):
                entities.append(_Entity(mx_domain, "domain", f"MX server of {domain}", 0.70))

        # WHOIS registrant emails
        whois_emails = result.get("whois", {}).get("emails") or []
        if isinstance(whois_emails, str):
            whois_emails = [whois_emails]
        for email in whois_emails:
            if email and "@" in email:
                entities.append(_Entity(email, "email", f"WHOIS registrant of {domain}", 0.90))

        # SSL Subject Alternative Names → related domains
        for san in result.get("ssl", {}).get("san", []):
            san = san.lstrip("*.")
            if san and san != domain and "." in san and not _is_skip_domain(san):
                entities.append(_Entity(san, "domain", f"SSL SAN of {domain}", 0.85))

        # crt.sh subdomains (cap at 8 to avoid flooding the graph)
        for sub in result.get("subdomains", [])[:8]:
            if sub != domain:
                entities.append(_Entity(sub, "domain", f"Subdomain of {domain}", 0.80))

        # Shodan InternetDB hostnames
        for hostname in result.get("shodan", {}).get("hostnames", [])[:5]:
            if hostname and hostname != domain and not _is_skip_domain(hostname):
                entities.append(_Entity(hostname, "domain", f"Shodan hostname for {domain}", 0.75))

        # Reverse IP → co-hosted domains (cap at 5)
        for co_domain in result.get("reverse_ip", [])[:5]:
            if co_domain and co_domain != domain and not _is_skip_domain(co_domain):
                entities.append(_Entity(co_domain, "domain", f"Co-hosted on same IP as {domain}", 0.65))

        return entities

    # ── IP pivot ──────────────────────────────────────────────────────────────

    async def _pivot_ip(self, ip: str) -> list[_Entity]:
        shodan_result, hackert_result, rdns = await asyncio.gather(
            self._shodan_ip(ip),
            self._hackertarget_reverse_ip(ip),
            self._reverse_dns(ip),
            return_exceptions=True,
        )
        entities: list[_Entity] = []

        if not isinstance(shodan_result, Exception):
            for hostname in (shodan_result.get("hostnames") or [])[:5]:
                if not _is_skip_domain(hostname):
                    entities.append(_Entity(hostname, "domain", f"Shodan hostname for {ip}", 0.80))

        if not isinstance(hackert_result, Exception):
            for domain in (hackert_result or [])[:5]:
                if not _is_skip_domain(domain):
                    entities.append(_Entity(domain, "domain", f"Co-hosted on {ip}", 0.70))

        if not isinstance(rdns, Exception) and rdns and not _is_skip_domain(rdns):
            entities.append(_Entity(rdns, "domain", f"Reverse DNS of {ip}", 0.80))

        return entities

    async def _shodan_ip(self, ip: str) -> dict:
        async with httpx.AsyncClient(timeout=10, headers=_HEADERS) as client:
            r = await client.get(f"https://internetdb.shodan.io/{ip}")
            return r.json() if r.status_code == 200 else {}

    async def _hackertarget_reverse_ip(self, ip: str) -> list[str]:
        async with httpx.AsyncClient(timeout=10, headers=_HEADERS) as client:
            r = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
            if r.status_code == 200 and "error" not in r.text.lower():
                return [line.strip() for line in r.text.strip().splitlines() if line.strip()]
        return []

    async def _reverse_dns(self, ip: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return hostname
        except Exception:
            return None

    # ── Email pivot ───────────────────────────────────────────────────────────

    async def _pivot_email(self, email: str) -> list[_Entity]:
        entities: list[_Entity] = []
        domain = email.split("@")[-1].lower()

        # The domain part is itself an investigation target (unless big provider)
        if domain not in _COMMON_PROVIDERS:
            entities.append(_Entity(domain, "domain", f"Domain of {email}", 0.85))

        # Run Gravatar + GitHub lookups concurrently
        gravatar, github = await asyncio.gather(
            self._check_gravatar(email),
            self._github_by_email(email),
            return_exceptions=True,
        )

        if not isinstance(gravatar, Exception) and gravatar.get("found"):
            username = gravatar.get("username")
            if username:
                entities.append(_Entity(username, "username", f"Gravatar username for {email}", 0.90))
            for url in (gravatar.get("urls") or [])[:3]:
                if url:
                    d = urlparse(url).netloc
                    if d and not _is_skip_domain(d):
                        entities.append(_Entity(d, "domain", f"Gravatar profile URL of {email}", 0.60))

        if not isinstance(github, Exception) and github.get("found"):
            username = github.get("username")
            if username:
                entities.append(_Entity(username, "username", f"GitHub username for {email}", 0.95))

        return entities

    async def _check_gravatar(self, email: str) -> dict:
        import hashlib
        h = hashlib.md5(email.lower().strip().encode()).hexdigest()
        async with httpx.AsyncClient(timeout=8, headers=_HEADERS) as client:
            r = await client.get(f"https://www.gravatar.com/{h}.json")
            if r.status_code == 200:
                entry = r.json().get("entry", [{}])[0]
                return {
                    "found":    True,
                    "username": entry.get("preferredUsername"),
                    "urls":     [u.get("value") for u in entry.get("urls", [])],
                }
        return {"found": False}

    async def _github_by_email(self, email: str) -> dict:
        import urllib.parse
        async with httpx.AsyncClient(timeout=10, headers=_HEADERS) as client:
            r = await client.get(
                f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}&per_page=3",
                headers={**_HEADERS, "Accept": "application/vnd.github.cloak-preview+json"},
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                if items:
                    author = items[0].get("author") or {}
                    return {"found": True, "username": author.get("login")}
        return {"found": False}

    # ── Username pivot ────────────────────────────────────────────────────────

    async def _pivot_username(self, username: str) -> list[_Entity]:
        entities: list[_Entity] = []

        # SOCMINT scan across 70+ platforms — results are leaf social_profile nodes
        from core.socmint import UsernameScanner
        scan_result = await UsernameScanner(username).scan()
        for account in scan_result.get("found", []):
            entities.append(_Entity(
                account["url"],
                "social_profile",
                f"{account['platform']} profile of {username}",
                0.85,
            ))

        # GitHub public profile → may expose email and blog domain
        await self._github_username_pivot(username, entities)

        return entities

    async def _github_username_pivot(self, username: str, entities: list[_Entity]):
        try:
            async with httpx.AsyncClient(timeout=10, headers=_HEADERS) as client:
                r = await client.get(f"https://api.github.com/users/{username}")
                if r.status_code == 200:
                    data = r.json()
                    if data.get("email"):
                        entities.append(_Entity(
                            data["email"], "email",
                            f"GitHub public email of {username}", 0.90,
                        ))
                    blog = data.get("blog", "")
                    if blog:
                        if not blog.startswith("http"):
                            blog = "https://" + blog
                        d = urlparse(blog).netloc
                        if d and not _is_skip_domain(d):
                            entities.append(_Entity(d, "domain", f"GitHub blog of {username}", 0.70))
        except Exception:
            pass

    # ── Phone pivot ───────────────────────────────────────────────────────────

    async def _pivot_phone(self, phone: str) -> list[_Entity]:
        # Phone verification is manual — surface the direct-action links as leaf nodes
        digits = re.sub(r'[^\d]', '', phone)
        if not digits.startswith("972") and digits.startswith("0"):
            digits = "972" + digits[1:]
        return [
            _Entity(f"https://wa.me/{digits}",   "social_profile", f"WhatsApp for {phone}", 0.60),
            _Entity(f"https://t.me/+{digits}",   "social_profile", f"Telegram for {phone}", 0.55),
        ]

    # ── Neo4j persistence (optional — silent if not running) ──────────────────

    def _persist_to_neo4j(self, result: dict):
        try:
            from core.graph_db import OsintGraphDatabase
            db = OsintGraphDatabase()
            if not db.available:
                return
            for node in result["nodes"]:
                db.create_entity(
                    node["group"], node["id"],
                    {"label": node["label"], "confidence": node["confidence"]},
                )
            for edge in result["edges"]:
                src_group = self._nodes.get(edge["from"], {}).get("group", "entity")
                dst_group = self._nodes.get(edge["to"],   {}).get("group", "entity")
                db.create_relationship(
                    src_group, edge["from"],
                    edge["label"],
                    dst_group, edge["to"],
                )
            db.close()
        except Exception:
            pass
