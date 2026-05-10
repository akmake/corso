"""
Nuclei Runner
-------------
Full integration with ProjectDiscovery's Nuclei scanner:
  - Auto-detects nuclei binary (PATH, common install dirs)
  - Updates templates on first run
  - Runs full scan, severity-filtered, or tag-filtered
  - Parses JSON output into Finding objects
  - Falls back to curated manual checks when nuclei is unavailable
  - Respects rate limits / timeout
"""

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""
    tags: list = field(default_factory=list)
    cve: str = ""

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tags": self.tags,
            "cve": self.cve,
        }

# ── Nuclei binary discovery ───────────────────────────────────────────────────

_NUCLEI_SEARCH_PATHS = [
    "nuclei",  # PATH
    "/usr/local/bin/nuclei",
    "/usr/bin/nuclei",
    os.path.expanduser("~/go/bin/nuclei"),
    os.path.expanduser("~/.local/bin/nuclei"),
    "/opt/nuclei/nuclei",
    "C:/Users/" + os.environ.get("USERNAME", "") + "/go/bin/nuclei.exe",
    "C:/tools/nuclei/nuclei.exe",
]

def _find_nuclei() -> Optional[str]:
    for path in _NUCLEI_SEARCH_PATHS:
        found = shutil.which(path) or (path if os.path.isfile(path) else None)
        if found:
            return found
    return None

# ── Template paths ────────────────────────────────────────────────────────────

_TEMPLATE_DIRS = [
    os.path.expanduser("~/nuclei-templates"),
    os.path.expanduser("~/.local/nuclei-templates"),
    "/root/nuclei-templates",
    "/opt/nuclei-templates",
]

def _find_templates() -> Optional[str]:
    for d in _TEMPLATE_DIRS:
        if os.path.isdir(d):
            return d
    return None

# ── Severity mapping ──────────────────────────────────────────────────────────

_SEV_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

# ── Recommendation map by tag ─────────────────────────────────────────────────

_TAG_RECOMMENDATIONS = {
    "sqli":        "השתמש ב-Parameterized Queries. אל תשרשר קלט משתמש ל-SQL.",
    "xss":         "Encode פלט. הוסף CSP header. השתמש ב-DOMPurify.",
    "ssrf":        "Whitelist URLs מותרים. חסום גישה לפנימי (169.254.x.x, 10.x.x.x).",
    "lfi":         "ולידציה של נתיבי קבצים. אל תקבל נתיבים מהמשתמש.",
    "rce":         "עדכן את הגרסה מיידית. בדוק patches רלוונטיים.",
    "cve":         "עדכן את הרכיב לגרסה המתוקנת האחרונה.",
    "exposure":    "הגבל גישה לקבצי הגדרות. הסר endpoints debug בפרודקשן.",
    "misconfig":   "בדוק הגדרות security בתיעוד השירות.",
    "default":     "עקוב אחר המלצת הממצא. בדוק CVE references.",
    "jwt":         "ולידציה מחמירה של JWT. השתמש ב-HS256/RS256 עם secret חזק.",
    "cors":        "הגדר CORS מדויק — רק דומיינים מהימנים. הסר wildcard.",
    "redirect":    "ולידציה של redirect URLs. השתמש ב-allowlist.",
    "takeover":    "הגדר DNS record נכון. מחק records לא פעילים.",
}

def _get_recommendation(tags: list) -> str:
    for tag in tags:
        tl = tag.lower()
        for k, v in _TAG_RECOMMENDATIONS.items():
            if k in tl:
                return v
    return _TAG_RECOMMENDATIONS["default"]

# ── Scanner ───────────────────────────────────────────────────────────────────

class NucleiRunner:
    def __init__(
        self,
        url: str,
        severity: str = "critical,high,medium",
        tags: str = "",
        timeout: int = 300,
        rate_limit: int = 50,
        log: Optional[Callable] = None,
    ):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.severity = severity
        self.tags = tags
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._log = log or (lambda m: None)
        self.findings: list[Finding] = []
        self._nuclei_path = _find_nuclei()
        self._templates_path = _find_templates()

    # ── Template management ───────────────────────────────────────────────────

    async def _ensure_templates(self):
        if not self._nuclei_path:
            return
        if self._templates_path:
            self._log("Nuclei: תבניות קיימות — מדלג על עדכון")
            return
        self._log("Nuclei: מוריד תבניות (nuclei -update-templates)...")
        try:
            proc = await asyncio.create_subprocess_exec(
                self._nuclei_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            self._templates_path = _find_templates()
            self._log(f"Nuclei: תבניות עודכנו → {self._templates_path}")
        except Exception as e:
            self._log(f"Nuclei: שגיאה בעדכון תבניות — {e}")

    # ── Run nuclei ────────────────────────────────────────────────────────────

    async def _run_nuclei(self) -> list[dict]:
        if not self._nuclei_path:
            return []

        out_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        out_file.close()

        cmd = [
            self._nuclei_path,
            "-u", self.url,
            "-json-export", out_file.name,
            "-severity", self.severity,
            "-rate-limit", str(self.rate_limit),
            "-timeout", "10",
            "-retries", "1",
            "-silent",
            "-no-color",
        ]

        if self.tags:
            cmd += ["-tags", self.tags]

        if self._templates_path:
            cmd += ["-t", self._templates_path]

        self._log(f"Nuclei: מריץ סריקה על {self.url} (severity={self.severity})...")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            results = []
            if os.path.exists(out_file.name):
                with open(out_file.name, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                results.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                os.unlink(out_file.name)

            self._log(f"Nuclei: נמצאו {len(results)} ממצאים גולמיים")
            return results

        except asyncio.TimeoutError:
            self._log(f"Nuclei: timeout אחרי {self.timeout}s")
            try:
                proc.kill()
            except Exception:
                pass
            return []
        except Exception as e:
            self._log(f"Nuclei: שגיאה — {e}")
            return []

    # ── Parse results ─────────────────────────────────────────────────────────

    def _parse_result(self, raw: dict):
        info = raw.get("info", {})
        template_id = raw.get("template-id", "")
        matched_at = raw.get("matched-at", "")
        severity = _SEV_MAP.get(info.get("severity", "info").lower(), "info")
        name = info.get("name", template_id)
        description = info.get("description", "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        reference = info.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]
        cve = next((r for r in tags if r.startswith("cve-")), "")

        evidence = [f"Matched: {matched_at}"]
        if raw.get("curl-command"):
            evidence.append(f"Curl: {raw['curl-command'][:200]}")
        if raw.get("extracted-results"):
            evidence.append(f"Extracted: {raw['extracted-results'][:5]}")
        if reference:
            evidence.extend(reference[:3])

        self.findings.append(Finding(
            severity=severity,
            category="Nuclei / CVE",
            title=name,
            description=description or f"Nuclei template '{template_id}' matched on {matched_at}",
            evidence=evidence,
            recommendation=_get_recommendation(tags),
            tags=tags,
            cve=cve.upper() if cve else "",
        ))

    # ── Fallback: manual high-value checks ────────────────────────────────────

    async def _fallback_manual_checks(self):
        """When nuclei is not installed, run a curated set of high-value HTTP checks."""
        import aiohttp
        self._log("Nuclei: לא מותקן — מריץ בדיקות CVE ידניות (fallback)...")

        TIMEOUT = aiohttp.ClientTimeout(total=10)
        HEADERS = {"User-Agent": "Mozilla/5.0"}

        checks = [
            # (path, method, body, response_pattern, title, severity, tags)
            ("/.env",            "GET", None, r"APP_KEY|DB_PASSWORD|SECRET",        "Exposed .env file",        "critical", ["exposure", "secrets"]),
            ("/.git/HEAD",       "GET", None, r"ref: refs/heads",                   "Exposed .git directory",   "critical", ["exposure", "git"]),
            ("/phpinfo.php",     "GET", None, r"PHP Version|phpinfo\(\)",            "phpinfo() Exposed",        "high",     ["exposure", "php"]),
            ("/wp-login.php",    "GET", None, r"WordPress|wp-login",                "WordPress Login Detected",  "info",     ["wordpress", "cms"]),
            ("/xmlrpc.php",      "POST","<methodCall><methodName>system.listMethods</methodName></methodCall>",
                                              r"<array>|<methodResponse>",           "WordPress XML-RPC Active", "medium",   ["wordpress", "xmlrpc"]),
            ("/robots.txt",      "GET", None, r"Disallow:",                         "robots.txt Found",         "info",     ["exposure", "recon"]),
            ("/api/swagger",     "GET", None, r"swagger|openapi",                   "Swagger UI Exposed",       "medium",   ["exposure", "api"]),
            ("/api/swagger.json","GET", None, r'"swagger"|"openapi"',               "Swagger JSON Exposed",     "medium",   ["exposure", "api"]),
            ("/swagger-ui.html", "GET", None, r"swagger|Swagger UI",               "Swagger UI Exposed",       "medium",   ["exposure", "api"]),
            ("/graphql",         "POST",'{"query":"{__typename}"}',
                                              r'"__typename"',                       "GraphQL Endpoint Active",  "medium",   ["graphql", "api"]),
            ("/admin",           "GET", None, r"admin|Admin|Dashboard",             "Admin Panel Found",        "medium",   ["admin", "exposure"]),
            ("/backup.zip",      "GET", None, r"PK\x03\x04",                        "Backup ZIP Exposed",       "critical", ["exposure", "backup"]),
            ("/backup.sql",      "GET", None, r"INSERT INTO|CREATE TABLE",          "SQL Backup Exposed",       "critical", ["exposure", "backup"]),
            ("/.htaccess",       "GET", None, r"RewriteEngine|Options|AuthType",    ".htaccess Exposed",        "high",     ["exposure", "apache"]),
            ("/server-status",   "GET", None, r"Apache Server Status|Server Version","Apache server-status Exposed","medium",["exposure", "apache"]),
            ("/actuator",        "GET", None, r'"_links"|"health"',                 "Spring Boot Actuator",     "high",     ["exposure", "spring"]),
            ("/actuator/env",    "GET", None, r'"activeProfiles"|"propertySources"',"Spring Boot Env Exposed",  "critical", ["exposure", "spring"]),
            ("/v1/sys/health",   "GET", None, r'"initialized"|"sealed"',            "Vault API Exposed",        "critical", ["exposure", "vault"]),
            ("/metrics",         "GET", None, r"go_goroutines|http_requests_total", "Prometheus Metrics Exposed","medium",  ["exposure", "metrics"]),
            ("/.DS_Store",       "GET", None, r"\x00\x00\x00\x01",                 ".DS_Store File Exposed",   "low",      ["exposure", "mac"]),
        ]

        from urllib.parse import urlparse
        base = "{p.scheme}://{p.netloc}".format(p=urlparse(self.url))

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for path, method, body, pattern, title, severity, tags in checks:
                tasks.append(self._check_path(session, base, path, method, body, pattern, title, severity, tags))
            await asyncio.gather(*tasks)

    async def _check_path(self, session, base, path, method, body, pattern, title, severity, tags):
        import aiohttp
        url = f"{base}{path}"
        try:
            TIMEOUT = aiohttp.ClientTimeout(total=8)
            HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            if method == "GET":
                resp = await session.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            else:
                ct = "text/xml" if body and body.startswith("<") else "application/json"
                resp = await session.post(url, headers={**HEADERS, "Content-Type": ct}, data=body, timeout=TIMEOUT)

            if resp.status in (404, 410):
                return

            text = await resp.text(errors="replace")
            if re.search(pattern, text, re.I | re.S):
                self._log(f"Nuclei fallback {severity.upper()}: {title} — {path}")
                self.findings.append(Finding(
                    severity=severity,
                    category="Exposure / Misconfiguration",
                    title=title,
                    description=f"{title} נמצא ב-{url}",
                    evidence=[f"URL: {url}", f"Status: {resp.status}", f"Pattern matched: {pattern}"],
                    recommendation=_get_recommendation(tags),
                    tags=tags,
                ))
        except Exception:
            pass

    # ── Version / CVE checks ──────────────────────────────────────────────────

    async def _check_known_cves(self):
        """Check response headers for version strings with known CVEs."""
        import aiohttp, re
        self._log("Nuclei: בודק גרסאות וCVEs ידועים בHeaders...")

        TIMEOUT = aiohttp.ClientTimeout(total=10)
        HEADERS = {"User-Agent": "Mozilla/5.0"}

        version_cves = [
            (r"Apache/([12]\.\d+\.\d+)", "Apache", {
                "2.4.49": ("CVE-2021-41773", "critical", "Path Traversal + RCE"),
                "2.4.50": ("CVE-2021-42013", "critical", "Path Traversal + RCE"),
                "2.4.51": ("CVE-2021-42013", "critical", "Path Traversal"),
            }),
            (r"nginx/([01]\.\d+\.\d+)", "nginx", {
                "1.19": ("CVE-2021-23017", "high", "DNS Resolver Buffer Overflow"),
            }),
            (r"PHP/([5-7]\.\d+\.\d+)", "PHP", {
                "5.": ("EOL-PHP5", "high", "PHP 5.x End of Life — no security patches"),
                "7.0": ("EOL-PHP70", "medium", "PHP 7.0 End of Life"),
                "7.1": ("EOL-PHP71", "medium", "PHP 7.1 End of Life"),
                "7.2": ("EOL-PHP72", "medium", "PHP 7.2 End of Life"),
            }),
            (r"OpenSSL/([01]\.\d+\.\d+)", "OpenSSL", {
                "1.0.1": ("CVE-2014-0160", "critical", "Heartbleed"),
                "1.0.2": ("CVE-2016-0800", "high", "DROWN Attack"),
            }),
        ]

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                resp = await session.get(self.url, headers=HEADERS, timeout=TIMEOUT)
                server_header = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")
                combined = f"{server_header} {x_powered}"

                for pattern, software, cve_map in version_cves:
                    m = re.search(pattern, combined, re.I)
                    if m:
                        version = m.group(1)
                        for ver_prefix, (cve_id, severity, vuln_desc) in cve_map.items():
                            if version.startswith(ver_prefix):
                                self.findings.append(Finding(
                                    severity=severity,
                                    category="CVE / Version",
                                    title=f"{software} {version} — {cve_id}",
                                    description=f"גרסה {version} של {software} חשופה ל-{vuln_desc} ({cve_id})",
                                    evidence=[
                                        f"Header: {combined}",
                                        f"Version: {version}",
                                        f"CVE: {cve_id}",
                                    ],
                                    recommendation=f"עדכן {software} לגרסה האחרונה. בדוק patches רלוונטיים.",
                                    tags=["cve", software.lower(), cve_id.lower()],
                                    cve=cve_id,
                                ))
                                break
            except Exception:
                pass

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def scan(self) -> dict:
        self._log(f"Nuclei Runner: מתחיל על {self.url}")

        if self._nuclei_path:
            self._log(f"Nuclei: נמצא ב-{self._nuclei_path}")
            await self._ensure_templates()
            raw_results = await self._run_nuclei()
            for r in raw_results:
                self._parse_result(r)
        else:
            self._log("Nuclei: לא מותקן — מריץ fallback checks")
            await self._fallback_manual_checks()

        await self._check_known_cves()

        critical = len([f for f in self.findings if f.severity == "critical"])
        high = len([f for f in self.findings if f.severity == "high"])
        self._log(f"Nuclei Runner: הושלם — {len(self.findings)} ממצאים ({critical} קריטי, {high} גבוה)")

        return {
            "target": self.url,
            "nuclei_available": bool(self._nuclei_path),
            "total": len(self.findings),
            "critical": critical,
            "high": high,
            "findings": [f.to_dict() for f in self.findings],
        }


async def run_nuclei(url: str, severity: str = "critical,high,medium", tags: str = "", log=None) -> dict:
    runner = NucleiRunner(url, severity=severity, tags=tags, log=log)
    return await runner.scan()
