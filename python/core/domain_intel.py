"""
Domain Intelligence Module
--------------------------
Collects full infrastructure intel on a domain:
  - DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - WHOIS ownership data
  - SSL certificate details + SANs
  - Subdomain enumeration via Certificate Transparency (crt.sh)
  - IP geolocation (ip-api.com)
"""

import asyncio
import socket
import ssl
import json
from datetime import datetime
from typing import Any

import httpx
import dns.resolver
import whois

from core.tool_runner import is_available, run_tool_json, run_tool


class DomainIntelligence:
    def __init__(self, domain: str):
        # Strip protocol and path, keep only the hostname
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        self.domain = domain.lower().strip()

    async def full_recon(self) -> dict:
        """Run all recon tasks concurrently and return a unified result."""
        results = await asyncio.gather(
            self._dns_records(),
            self._whois_data(),
            self._ssl_certificate(),
            self._subdomains_crtsh(),
            self._ip_geolocation(),
            return_exceptions=True
        )

        keys = ["dns", "whois", "ssl", "subdomains", "geolocation"]
        data: dict = {}
        for key, result in zip(keys, results):
            data[key] = result if not isinstance(result, Exception) else {"error": str(result)}

        # Shodan InternetDB — חינם לגמרי, ללא API key, נותן פורטים + CVEs
        ip = data.get("geolocation", {}).get("ip")
        if ip:
            data["shodan"] = await self._shodan_internetdb(ip)
            data["reverse_ip"] = await self._hackertarget_reverse_ip(ip)
        else:
            data["shodan"]     = {"error": "IP not resolved"}
            data["reverse_ip"] = []

        # httpx probe — check which subdomains are alive with HTTP details
        sub_list = data.get("subdomains", [])
        if isinstance(sub_list, list) and sub_list and is_available("httpx"):
            data["httpx_probe"] = await self.httpx_probe(sub_list[:50])
        else:
            data["httpx_probe"] = []

        return {"domain": self.domain, **data}

    # ------------------------------------------------------------------ #
    #  DNS
    # ------------------------------------------------------------------ #
    async def _dns_records(self) -> dict:
        loop = asyncio.get_event_loop()

        def _resolve():
            records = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
            return records

        return await loop.run_in_executor(None, _resolve)

    # ------------------------------------------------------------------ #
    #  WHOIS
    # ------------------------------------------------------------------ #
    async def _whois_data(self) -> dict:
        loop = asyncio.get_event_loop()

        def _fetch():
            w = whois.whois(self.domain)

            def serialize(v: Any) -> Any:
                if v is None:
                    return None
                if isinstance(v, list):
                    return [serialize(i) for i in v]
                if isinstance(v, datetime):
                    return v.isoformat()
                return str(v)

            return {
                "registrar":        serialize(w.registrar),
                "creation_date":    serialize(w.creation_date),
                "expiration_date":  serialize(w.expiration_date),
                "updated_date":     serialize(w.updated_date),
                "name_servers":     serialize(w.name_servers),
                "registrant":       serialize(w.get("registrant_name") or w.get("name")),
                "emails":           serialize(w.emails),
                "country":          serialize(w.country),
                "org":              serialize(w.org),
                "status":           serialize(w.status),
            }

        return await loop.run_in_executor(None, _fetch)

    # ------------------------------------------------------------------ #
    #  SSL Certificate
    # ------------------------------------------------------------------ #
    async def _ssl_certificate(self) -> dict:
        loop = asyncio.get_event_loop()

        def _fetch():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.domain, 443), timeout=10),
                server_hostname=self.domain
            ) as s:
                cert = s.getpeercert()

            # Subject Alternative Names
            sans = [
                v for kind, v in cert.get("subjectAltName", [])
                if kind == "DNS"
            ]

            return {
                "subject":     dict(x[0] for x in cert.get("subject", [])),
                "issuer":      dict(x[0] for x in cert.get("issuer", [])),
                "valid_from":  cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
                "san":         sans,
                "version":     cert.get("version"),
            }

        return await loop.run_in_executor(None, _fetch)

    # ------------------------------------------------------------------ #
    #  Subdomains: Subfinder (40+ sources) → crt.sh → HackerTarget fallback
    # ------------------------------------------------------------------ #
    async def _subdomains_crtsh(self) -> list[str]:
        # Prefer Subfinder if installed (40+ passive sources)
        all_subs: set[str] = set()

        if is_available("subfinder"):
            subs = await self._subfinder_query()
            all_subs.update(subs)

        # Amass — 100+ sources (OWASP)
        if is_available("amass"):
            amass_subs = await self._amass_query()
            all_subs.update(amass_subs)

        if all_subs:
            # Also merge crt.sh for completeness
            crtsh = await self._crtsh_query()
            all_subs.update(crtsh)
            return sorted(all_subs)

        # Fallback chain: crt.sh → HackerTarget
        subdomains = await self._crtsh_query()
        if not subdomains:
            subdomains = await self._hackertarget_subdomains()
        return subdomains

    async def _subfinder_query(self) -> list[str]:
        """Run Subfinder CLI for passive subdomain enumeration from 40+ sources."""
        try:
            code, stdout, stderr = await run_tool(
                "subfinder",
                ["-d", self.domain, "-silent", "-timeout", "30"],
                timeout=60,
            )
            if not stdout.strip():
                return []
            subdomains = set()
            for line in stdout.strip().splitlines():
                host = line.strip().lower()
                if host and host.endswith(self.domain) and host != self.domain:
                    subdomains.add(host)
            return sorted(subdomains)
        except Exception:
            return []

    async def _amass_query(self) -> list[str]:
        """Run OWASP Amass for subdomain enumeration from 100+ sources."""
        try:
            code, stdout, stderr = await run_tool(
                "amass",
                ["enum", "-passive", "-d", self.domain, "-timeout", "2"],
                timeout=180,
            )
            if not stdout.strip():
                return []
            subdomains = set()
            for line in stdout.strip().splitlines():
                host = line.strip().lower()
                if host and host.endswith(self.domain) and host != self.domain:
                    subdomains.add(host)
            return sorted(subdomains)
        except Exception:
            return []

    async def httpx_probe(self, subdomains: list[str]) -> list[dict]:
        """Run httpx to probe which subdomains are alive with HTTP details."""
        if not is_available("httpx") or not subdomains:
            return []
        try:
            stdin_data = "\n".join(subdomains)
            code, stdout, stderr = await run_tool(
                "httpx",
                ["-json", "-silent", "-no-color",
                 "-status-code", "-title", "-tech-detect",
                 "-timeout", "10", "-threads", "20"],
                timeout=120,
                stdin_data=stdin_data,
            )
            results = []
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    results.append({
                        "url": entry.get("url", ""),
                        "status_code": entry.get("status_code", 0),
                        "title": entry.get("title", ""),
                        "tech": entry.get("tech", []),
                        "content_length": entry.get("content_length", 0),
                        "webserver": entry.get("webserver", ""),
                    })
                except json.JSONDecodeError:
                    continue
            return results
        except Exception:
            return []

    async def _crtsh_query(self) -> list[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            # Increased timeout: crt.sh is notoriously slow under load
            async with httpx.AsyncClient(timeout=45) as client:
                r = await client.get(url)
                if r.status_code != 200:
                    return []
                data = r.json()

            subdomains: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(self.domain) and name != self.domain:
                        subdomains.add(name)

            return sorted(subdomains)
        except Exception:
            return []

    async def _hackertarget_subdomains(self) -> list[str]:
        """HackerTarget free subdomain finder — fallback when crt.sh times out."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                )
            if r.status_code != 200 or "error" in r.text.lower():
                return []
            subdomains: set[str] = set()
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    host = parts[0].strip()
                    if host.endswith(self.domain) and host != self.domain:
                        subdomains.add(host)
            return sorted(subdomains)
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  Shodan InternetDB — FREE, no API key needed
    #  נותן: פורטים פתוחים, CVEs, hostnames, CPEs לכל IP
    # ------------------------------------------------------------------ #
    async def _shodan_internetdb(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://internetdb.shodan.io/{ip}")
                if r.status_code == 200:
                    d = r.json()
                    return {
                        "ports":     d.get("ports", []),
                        "vulns":     d.get("vulns", []),
                        "hostnames": d.get("hostnames", []),
                        "cpes":      d.get("cpes", []),
                        "tags":      d.get("tags", []),
                    }
                return {"ports": [], "vulns": [], "error": f"Status {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------ #
    #  Reverse IP via HackerTarget — חינם, ללא key
    # ------------------------------------------------------------------ #
    async def _hackertarget_reverse_ip(self, ip: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
                if r.status_code == 200 and "error" not in r.text.lower():
                    domains = [line.strip() for line in r.text.strip().splitlines() if line.strip()]
                    return domains[:50]
            return []
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  IP Geolocation
    # ------------------------------------------------------------------ #
    async def _ip_geolocation(self) -> dict:
        loop = asyncio.get_event_loop()

        # Resolve domain → IP (blocking, run in thread)
        ip = await loop.run_in_executor(None, socket.gethostbyname, self.domain)

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            geo = r.json()

        return {
            "ip":      ip,
            "country": geo.get("country"),
            "city":    geo.get("city"),
            "isp":     geo.get("isp"),
            "org":     geo.get("org"),
            "asn":     geo.get("as"),
            "lat":     geo.get("lat"),
            "lon":     geo.get("lon"),
        }
