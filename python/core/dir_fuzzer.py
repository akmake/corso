"""
Directory & File Fuzzer
-----------------------
FFuF integration (when installed) + built-in async directory brute-forcer.
If ffuf is available → uses it with SecLists-style wordlists (much faster, more paths).
Otherwise → built-in ~270 high-value paths.
"""

import asyncio
import json
import os
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from core.tool_runner import is_available, run_tool, make_temp_file

_log = logging.getLogger(__name__)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""


_WORDLIST = [
    # ── Admin panels ──────────────────────────────────────────────────────────
    "admin", "admin/", "administrator", "admin.php", "admin.html",
    "admin/login", "admin/login.php", "admin/index.php", "admin_login.php",
    "wp-admin", "wp-admin/", "wp-login.php", "cpanel", "cpanel/",
    "phpmyadmin", "phpmyadmin/", "pma", "pma/", "adminer", "adminer.php",
    "dbadmin", "mysql", "panel", "controlpanel", "manage", "manager",
    "management", "backend", "cms", "dashboard", "portal", "console",
    "webadmin", "siteadmin", "adminpanel", "adminarea",
    "login", "login.php", "login.html", "signin", "sign-in",
    "moderator", "superadmin", "root",

    # ── Environment & config files ────────────────────────────────────────────
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.backup", ".env.bak", ".env.old", ".env.example",
    "config.php", "config.yml", "config.yaml", "config.json", "config.ini",
    "configuration.php", "settings.php", "settings.py", "settings.json",
    "app.config", "web.config", "appsettings.json", "database.yml",
    "database.php", "db.php", "db.yml", "db.json",
    "application.properties", "application.yml", "application.yaml",
    "config/database.yml", "config/secrets.yml", "config/application.yml",
    "config/config.php", "config/settings.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "wp-config.php~", "wp-config.bak",
    ".htaccess", ".htpasswd", ".htpasswd.bak",
    "secrets.yml", "secrets.json", "credentials.json", "credentials.yml",
    "local_settings.py", "local.py", "private.php",

    # ── Backup & archive files ─────────────────────────────────────────────────
    "backup", "backup/", "backup.zip", "backup.tar.gz", "backup.sql",
    "backup.gz", "backup.bak", "backup.rar", "backup.tgz", "backup.7z",
    "backup.tar", "backup.tar.bz2",
    "site.zip", "site.tar.gz", "site.tar", "www.zip", "www.tar.gz",
    "dump.sql", "db.sql", "database.sql", "mysql.sql", "data.sql",
    "backup.sql.gz", "dump.sql.gz",
    "old", "old/", "old.zip", "archive", "archive/", "archive.zip",
    "files.zip", "data.zip", "website.zip", "public_html.zip",
    "html.zip", "htdocs.zip",
    "db_backup.sql", "database_backup.sql", "full_backup.zip",

    # ── Git / VCS exposure ────────────────────────────────────────────────────
    ".git", ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".git/index", ".git/packed-refs", ".git/logs/HEAD",
    ".gitignore", ".gitattributes", ".gitmodules",
    ".svn", ".svn/entries", ".svn/wc.db",
    ".hg", ".hg/hgrc", ".bzr", ".DS_Store",

    # ── Debug / dev / test files ──────────────────────────────────────────────
    "phpinfo.php", "info.php", "test.php", "debug.php", "check.php",
    "phpinfo", "test", "debug", "dev", "development", "local", "staging",
    "demo", "temp", "tmp", "sample", "example",
    "install.php", "install", "setup.php", "setup", "install/",
    "update.php", "upgrade.php", "migrate.php", "migration.php",
    "console.php", "shell.php", "cmd.php", "exec.php", "eval.php",
    "probe.php", "probe", "diagnostic.php",

    # ── Log files ─────────────────────────────────────────────────────────────
    "error.log", "access.log", "error_log", "access_log",
    "debug.log", "app.log", "application.log", "laravel.log",
    "server.log", "php_error.log", "php-error.log",
    "logs/", "logs/error.log", "logs/access.log", "logs/debug.log",
    "log/", "log/error.log",
    "storage/logs/laravel.log", "storage/logs/",
    "var/log/", "tmp/logs/",

    # ── API endpoints ─────────────────────────────────────────────────────────
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v3",
    "api/docs", "api/swagger", "api/swagger-ui",
    "swagger", "swagger.json", "swagger.yaml", "swagger-ui",
    "openapi.json", "openapi.yaml", "api-docs",
    "api/users", "api/admin", "api/auth", "api/login",
    "api/token", "api/health", "api/status", "api/metrics",
    "api/debug", "api/config", "api/env",
    "graphql", "graphiql", "api/graphql", "playground",
    "_api", "v1", "v2", "rest", "rest/",

    # ── Uploads & media ───────────────────────────────────────────────────────
    "uploads", "upload", "files", "file", "media",
    "static", "assets", "images", "img", "documents", "docs",
    "uploads/", "files/",

    # ── Server status & info ──────────────────────────────────────────────────
    "server-status", "server-info", "nginx_status", "nginx-status",
    "fpm-status", "php-status", "status", "health", "ping",
    ".well-known", ".well-known/security.txt",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", "browserconfig.xml",

    # ── Framework files ───────────────────────────────────────────────────────
    "vendor", "vendor/", "vendor/autoload.php",
    "vendor/composer/installed.json",
    "composer.json", "composer.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "Makefile", "Dockerfile", ".dockerignore", "docker-compose.yml",
    "Gruntfile.js", "Gulpfile.js", "webpack.config.js",
    ".travis.yml", ".github/workflows/", "Jenkinsfile",

    # ── Cloud metadata (misconfigured reverse proxies) ────────────────────────
    "metadata", "latest/meta-data", "latest/user-data",
    "computeMetadata/v1/", "metadata/instance",

    # ── Monitoring & metrics ──────────────────────────────────────────────────
    "metrics", "actuator", "actuator/", "actuator/health",
    "actuator/env", "actuator/mappings", "actuator/beans",
    "actuator/configprops", "actuator/info",
    "monitoring", "prometheus", "grafana", "kibana",
    "health-check", "healthcheck", "readiness", "liveness",

    # ── CMS & e-commerce specific ─────────────────────────────────────────────
    "xmlrpc.php", "wp-json/", "wp-json/wp/v2/users",
    "wp-cron.php", "wp-includes/version.php",
    "administrator/", "joomla.xml",
    "sites/default/settings.php", "CHANGELOG.txt", "update.php",
    "magento/", "index.php/admin",
    "store/", "shop/", "checkout/", "cart/",
]

# Severity classification
_CRITICAL = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    "wp-config.php", "wp-config.php.bak", ".htpasswd", "config.php",
    "settings.php", "database.php", "db.php", ".git/config", ".git/HEAD",
    "secrets.yml", "secrets.json", "credentials.json",
    "dump.sql", "db.sql", "database.sql", "backup.sql",
    "shell.php", "cmd.php", "exec.php", "eval.php",
    "actuator/env", "actuator/configprops",
    "vendor/composer/installed.json",
}

_HIGH = {
    "phpmyadmin", "phpmyadmin/", "pma", "pma/", "adminer", "adminer.php",
    "phpinfo.php", "info.php", "install.php", "setup.php",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    ".svn", ".git", "composer.json", "package.json",
    "actuator", "actuator/", "actuator/health", "actuator/mappings",
    "graphiql", "api/debug", "api/config", "api/env",
    "error.log", "access.log", "laravel.log", "debug.log",
    "wp-json/wp/v2/users", "xmlrpc.php",
}


def _classify(path: str) -> str:
    clean = path.lstrip("/").rstrip("/")
    if clean in _CRITICAL:
        return "critical"
    for c in _CRITICAL:
        if clean.startswith(c.rstrip("/")):
            return "critical"
    if clean in _HIGH:
        return "high"
    for h in _HIGH:
        if clean.startswith(h.rstrip("/")):
            return "high"
    return "medium"


async def fuzz_directories(base_url: str, cookies: str = "", auth_token: str = "") -> list[Finding]:
    """
    Directory fuzz with ffuf/feroxbuster (if installed) or built-in wordlist.
    ffuf is ~10x faster and supports SecLists' huge wordlists.
    feroxbuster adds recursive discovery.
    """
    findings = []

    if is_available("ffuf"):
        ffuf_results = await _run_ffuf(base_url)
        if ffuf_results is not None:
            findings.extend(ffuf_results)

    # feroxbuster — recursive directory brute-force
    if is_available("feroxbuster"):
        ferox_results = await _run_feroxbuster(base_url)
        findings.extend(ferox_results)

    if findings:
        return findings

    return await _fuzz_builtin(base_url, cookies=cookies, auth_token=auth_token)


async def _run_feroxbuster(base_url: str) -> list[Finding]:
    """Run feroxbuster for recursive directory discovery."""
    findings = []
    base = base_url.rstrip("/")
    try:
        code, stdout, stderr = await run_tool("feroxbuster", [
            "-u", base,
            "--json",
            "--quiet",
            "--depth", "2",
            "--threads", "30",
            "--timeout", "7",
            "--status-codes", "200,301,302,401,403",
            "--no-state",
            "--auto-tune",
        ], timeout=180)

        seen = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url_found = entry.get("url", "")
            status = entry.get("status", 0)
            if not url_found or url_found in seen:
                continue
            seen.add(url_found)

            path = url_found.replace(base, "").lstrip("/") or "/"
            sev = _classify(path)

            if status == 200:
                label = "200 OK"
            elif status in (301, 302):
                label = f"{status} Redirect"
                if sev == "medium":
                    sev = "low"
            elif status == 401:
                label = "401 Unauthorized"
                sev = "medium" if sev in ("critical", "high") else "low"
            elif status == 403:
                label = "403 Forbidden"
            else:
                continue

            findings.append(Finding(
                sev, "dir_fuzzing",
                f"[feroxbuster] /{path}  [{label}]",
                f"Recursive discovery found /{path} with status {status}.",
                [f"URL: {url_found}", f"Status: {status}",
                 f"Size: {entry.get('content_length', '?')} bytes"],
                "Verify sensitive paths are properly protected.",
            ))

        if findings:
            findings.insert(0, Finding(
                "info", "dir_fuzzing",
                f"[feroxbuster] Recursive scan — {len(findings)} paths discovered",
                "Feroxbuster performed recursive directory brute-forcing.",
                [f"Total paths: {len(findings)}"],
            ))
    except Exception as e:
        _log.debug("feroxbuster error: %s", e)
    return findings


async def _run_ffuf(base_url: str) -> list[Finding] | None:
    """Run ffuf with built-in wordlist, parse JSON output."""
    base = base_url.rstrip("/")
    # Write our wordlist to temp file for ffuf
    wordlist_path = make_temp_file(suffix=".txt", content="\n".join(_WORDLIST))
    outfile = make_temp_file(suffix=".json")
    try:
        code, stdout, stderr = await run_tool(
            "ffuf",
            [
                "-u", f"{base}/FUZZ",
                "-w", wordlist_path,
                "-o", outfile,
                "-of", "json",
                "-mc", "200,301,302,401,403",
                "-t", "50",
                "-timeout", "5",
                "-s",  # silent
            ],
            timeout=120,
        )
        if not os.path.exists(outfile):
            return None

        with open(outfile, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = []
        results = data.get("results", [])

        async def _fetch_body(url: str) -> str:
            try:
                async with httpx.AsyncClient(verify=False, timeout=7) as c:
                    r = await c.get(url, follow_redirects=False)
                    return r.text[:2000].strip()
            except Exception:
                return ""

        # Pre-fetch bodies for all 200 results
        body_map: dict[str, str] = {}
        ok_urls = [
            f"{base}/{entry.get('input', {}).get('FUZZ', '')}"
            for entry in results if entry.get("status") == 200
        ]
        if ok_urls:
            bodies = await asyncio.gather(*[_fetch_body(u) for u in ok_urls])
            body_map = dict(zip(ok_urls, bodies))

        for entry in results:
            path = entry.get("input", {}).get("FUZZ", "")
            status = entry.get("status", 0)
            size = entry.get("length", 0)
            ct = entry.get("content-type", "")

            sev = _classify(path)

            if status == 200:
                label = "200 OK — נגיש לגמרי"
                desc = f"הנתיב /{path} מחזיר 200 ונגיש ללא הרשאה."
            elif status in (301, 302):
                label = f"{status} Redirect — קיים"
                desc = f"הנתיב /{path} קיים ומפנה ({status})."
                if sev == "medium":
                    sev = "low"
            elif status == 401:
                label = "401 Unauthorized — קיים עם הגנה"
                desc = f"הנתיב /{path} קיים ומוגן (authentication)."
                sev = "medium" if sev in ("critical", "high") else "low"
            elif status == 403:
                label = "403 Forbidden — קיים, גישה נחסמה"
                desc = f"הנתיב /{path} קיים. גישה נחסמה."
                sev = "medium" if sev not in ("critical", "high") else sev
            else:
                continue

            evidence = [f"URL: {base}/{path}", f"Status: {status}"]
            if size:
                evidence.append(f"Size: {size} bytes")

            if status == 200:
                body = body_map.get(f"{base}/{path}", "")
                if body:
                    evidence.append(f"--- תוכן התגובה (2000 תווים ראשונים) ---")
                    evidence.append(body)

            findings.append(Finding(
                sev, "dir_fuzzing",
                f"נתיב נמצא: /{path}  [{label}]",
                desc, evidence,
                "ודא שנתיבים רגישים מוגנים ב-authentication.",
            ))

        vuln = [f for f in findings if f.severity in ("critical", "high")]
        summary = Finding(
            "info", "dir_fuzzing",
            f"Directory Fuzzing (ffuf) — {len(findings)} נתיבים נמצאו / {len(_WORDLIST)} נבדקו"
            + (f" — {len(vuln)} קריטיים/גבוהים" if vuln else ""),
            "סריקה באמצעות ffuf (engine חיצוני).",
            [f"/{e.get('input',{}).get('FUZZ','')} → {e.get('status','')}" for e in results[:30]],
        )
        return [summary] + findings
    except Exception as e:
        _log.warning("ffuf failed, falling back to built-in: %s", e)
        return None
    finally:
        for p in (wordlist_path, outfile):
            try:
                os.unlink(p)
            except OSError:
                pass


async def _fuzz_builtin(base_url: str, cookies: str = "", auth_token: str = "") -> list[Finding]:
    findings: list[Finding] = []
    base = base_url.rstrip("/")
    found_lines: list[str] = []

    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)", "Accept": "*/*"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    cookie_dict = {}
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    CONCURRENCY = 50
    sem = asyncio.Semaphore(CONCURRENCY)
    results: list[tuple[str, int, int, str, str]] = []

    # Baseline: fetch a random non-existent path to detect SPA catch-all
    baseline_len: int | None = None
    baseline_snippet: str | None = None

    async with httpx.AsyncClient(headers=headers, cookies=cookie_dict, verify=False) as client:
        try:
            b = await client.get(f"{base}/webint-nonexistent-baseline-{id(base)}", timeout=6, follow_redirects=False)
            if b.status_code == 200:
                baseline_len = len(b.text)
                baseline_snippet = b.text[:300]
        except Exception:
            pass

    def _is_spa(text: str, status: int) -> bool:
        if status != 200 or baseline_len is None:
            return False
        if abs(len(text) - baseline_len) < 100:
            return True
        if baseline_snippet and text[:300] == baseline_snippet:
            return True
        return False

    spa_filtered: list[str] = []

    async def _probe_wrapper(client: httpx.AsyncClient, path: str):
        url = f"{base}/{path}"
        async with sem:
            try:
                r = await client.head(url, timeout=5, follow_redirects=False)
                if r.status_code == 405:
                    r = await client.get(url, timeout=5, follow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    ct = r.headers.get("content-type", "")
                    cl = int(r.headers.get("content-length", 0))
                    body_preview = ""
                    if r.status_code == 200:
                        try:
                            gr = await client.get(url, timeout=7, follow_redirects=False)
                            if _is_spa(gr.text, gr.status_code):
                                spa_filtered.append(path)
                                return
                            raw = gr.text[:2000].strip()
                            body_preview = raw if raw else ""
                        except Exception:
                            pass
                    results.append((path, r.status_code, cl, ct, body_preview))
            except Exception:
                pass

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        await asyncio.gather(*[_probe_wrapper(client, p) for p in _WORDLIST])

    for path, status, size, ct, body_preview in sorted(results, key=lambda x: x[0]):
        sev = _classify(path)

        if status == 200:
            label = "200 OK — נגיש לגמרי"
            desc = f"הנתיב /{path} מחזיר 200 ונגיש ללא הרשאה."
        elif status in (301, 302):
            label = f"{status} Redirect — קיים"
            desc = f"הנתיב /{path} קיים ומפנה ({status})."
            if sev == "medium":
                sev = "low"
        elif status == 401:
            label = "401 Unauthorized — קיים עם הגנה"
            desc = f"הנתיב /{path} קיים ומוגן (authentication). לעיתים ניתן לעקוף."
            sev = "medium" if sev in ("critical", "high") else "low"
        elif status == 403:
            label = "403 Forbidden — קיים, גישה נחסמה"
            desc = f"הנתיב /{path} קיים. גישה נחסמה אך לעיתים ניתן לעקוף עם path traversal."
            sev = "medium" if sev not in ("critical", "high") else sev

        evidence = [f"URL: {base}/{path}", f"Status: {status}"]
        if size:
            evidence.append(f"Size: {size} bytes")
        if ct:
            evidence.append(f"Content-Type: {ct}")
        if body_preview:
            evidence.append(f"--- תוכן התגובה (2000 תווים ראשונים) ---")
            evidence.append(body_preview)

        findings.append(Finding(
            sev, "dir_fuzzing",
            f"נתיב נמצא: /{path}  [{label}]",
            desc,
            evidence,
            "ודא שנתיבים רגישים מוגנים ב-authentication. הסר קבצי dev/backup מה-webroot.",
        ))
        found_lines.append(f"/{path} → {status}")

    # Summary finding first
    vuln = [f for f in findings if f.severity in ("critical", "high")]
    spa_note = f" — {len(spa_filtered)} סוננו כ-SPA false positives" if spa_filtered else ""
    summary = Finding(
        "info", "dir_fuzzing",
        f"Directory Fuzzing — {len(findings)} נתיבים נמצאו / {len(_WORDLIST)} נבדקו{spa_note}",
        "סריקת Wordlist מלאה.",
        found_lines[:30] if found_lines else [f"Wordlist: {len(_WORDLIST)} paths"],
    )
    results_list = [summary] + findings
    if spa_filtered:
        results_list.append(Finding(
            "info", "dir_fuzzing",
            f"SPA catch-all זוהה — {len(spa_filtered)} נתיבים סוננו",
            "האתר מחזיר HTTP 200 + אותו HTML לכל URL לא קיים (React/Vue/Angular SPA). "
            "הנתיבים הבאים אינם קיימים באמת:",
            spa_filtered[:30],
            "אין פעולה נדרשת — הנתיבים אינם קיימים.",
        ))
    return results_list
