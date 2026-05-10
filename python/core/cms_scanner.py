"""
CMS Scanner
-----------
Auto-detects WordPress / Joomla / Drupal and runs platform-specific checks.

WordPress (WPScan techniques):
  - Version: readme.html, feed, wp-links-opml.php, meta generator
  - User enumeration: /wp-json/wp/v2/users + ?author= redirect
  - xmlrpc.php: accessible + system.multicall brute-force vector
  - WP REST API: sensitive route enumeration
  - Sensitive files: wp-config.php.bak, debug.log, install.php
  - Plugin / theme disclosure from HTML source
  - WP Debug mode leak
  - wp-cron.php DoS vector

Joomla (JoomScan techniques):
  - Version: administrator/manifests/files/joomla.xml
  - configuration.php backup exposure
  - Admin panel exposure

Drupal (droopescan techniques):
  - Version: CHANGELOG.txt
  - update.php accessibility
  - /sites/default/settings.php exposure
"""

import re
import asyncio
from dataclasses import dataclass, field

import httpx

from core.tool_runner import is_available, run_tool

log = __import__("logging").getLogger(__name__)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""


_WP_INDICATORS = [
    "/wp-login.php", "/wp-includes/", "/wp-content/", "wp-json", "WordPress",
]

_WP_VERSION_PATTERNS = [
    re.compile(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', re.I),
    re.compile(r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)', re.I),
    re.compile(r'wordpress\.org/\?v=([\d.]+)', re.I),
]

_WP_EOL = [
    ("3.", "critical", "WordPress 3.x — EOL מ-2016, עשרות CVEs קריטיים כולל RCE"),
    ("4.", "critical", "WordPress 4.x — EOL, CVE-2017-9061/9062/8295 ועוד"),
    ("5.0", "high",    "WordPress 5.0 — CVE-2019-8942 (Authenticated RCE via image crop)"),
    ("5.1", "high",    "WordPress 5.1 — CVE-2019-9787 (CSRF→XSS→RCE)"),
    ("5.2", "high",    "WordPress 5.2 — CVE-2019-17671 (Unauthenticated Content Exposure)"),
    ("5.3", "high",    "WordPress 5.3 — עדכן לגרסה נוכחית"),
    ("5.4", "medium",  "WordPress 5.4"),
    ("5.5", "medium",  "WordPress 5.5"),
    ("5.6", "medium",  "WordPress 5.6"),
    ("5.7", "medium",  "WordPress 5.7"),
    ("5.8", "medium",  "WordPress 5.8"),
    ("5.9", "medium",  "WordPress 5.9"),
]


async def _get(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    follow_redirects: bool = True,
    **kwargs,
) -> httpx.Response | None:
    try:
        return await client.request(
            method, url, timeout=8, follow_redirects=follow_redirects, **kwargs
        )
    except Exception:
        return None


async def _detect_wp_version(
    client: httpx.AsyncClient, base: str, html: str
) -> str:
    for pat in _WP_VERSION_PATTERNS:
        m = pat.search(html)
        if m:
            return m.group(1)

    for feed_path in ["/feed/", "/feed"]:
        r = await _get(client, base + feed_path)
        if r and r.status_code == 200:
            for pat in _WP_VERSION_PATTERNS:
                m = pat.search(r.text)
                if m:
                    return m.group(1)

    r = await _get(client, f"{base}/wp-links-opml.php")
    if r and r.status_code == 200:
        m = re.search(r'\?v=([\d.]+)', r.text)
        if m:
            return m.group(1)

    return ""


async def scan_wordpress(
    client: httpx.AsyncClient, base: str, html: str
) -> list[Finding]:
    findings: list[Finding] = []

    # ── Version ──────────────────────────────────────────────────────────────
    wp_version = await _detect_wp_version(client, base, html)

    r_readme = await _get(client, f"{base}/readme.html")
    if r_readme and r_readme.status_code == 200 and "wordpress" in r_readme.text.lower():
        if not wp_version:
            m = re.search(r'[Vv]ersion\s*([\d.]+)', r_readme.text)
            if m:
                wp_version = m.group(1)
        findings.append(Finding(
            "medium", "wordpress",
            "readme.html נגיש — חושף גרסת WordPress",
            "readme.html הוא ציבורי ומכיל את גרסת WordPress. מאפשר מציאת CVEs ספציפיים.",
            [f"{base}/readme.html → HTTP 200"],
            "Nginx: location ~ /readme\\.html { deny all; }\n"
            "Apache: <Files readme.html> Deny from all </Files>",
        ))

    if wp_version:
        findings.append(Finding(
            "info", "wordpress",
            f"WordPress {wp_version} מזוהה",
            "גרסת WordPress זוהתה ממקורות מרובים.",
            [f"גרסה: WordPress {wp_version}"],
            "הסתר גרסה — הוסף ל-functions.php:\n"
            "remove_action('wp_head', 'wp_generator');\n"
            "עדכן לגרסה האחרונה ב-Dashboard → Updates.",
        ))
        for prefix, sev, msg in _WP_EOL:
            if wp_version.startswith(prefix):
                findings.append(Finding(
                    sev, "wordpress",
                    f"WordPress {wp_version} — גרסה פגיעה / EOL",
                    msg,
                    [f"גרסה שזוהתה: {wp_version}"],
                    "עדכן ל-WordPress האחרון מיידית דרך Dashboard → Updates.",
                ))
                break

    # ── User enumeration: REST API ────────────────────────────────────────────
    r_users = await _get(client, f"{base}/wp-json/wp/v2/users")
    if r_users and r_users.status_code == 200:
        try:
            users = r_users.json()
            if isinstance(users, list) and users:
                details = []
                for u in users[:10]:
                    uid  = u.get("id", "?")
                    name = u.get("name", "")
                    slug = u.get("slug", "")
                    details.append(f"ID={uid}  name={name!r}  login_slug={slug!r}")
                findings.append(Finding(
                    "high", "wordpress",
                    f"מניין משתמשים — REST API: {len(users)} משתמשים חשופים",
                    "/wp-json/wp/v2/users חשוף ללא אימות — שמות משתמשים לbrute-force ממוקד "
                    "(wp-login.php / xmlrpc.php).",
                    [f"GET /wp-json/wp/v2/users → {len(users)} users"] + details,
                    "הוסף ל-functions.php:\n"
                    "add_filter('rest_endpoints', function($e) {\n"
                    "  unset($e['/wp/v2/users']);\n"
                    "  unset($e['/wp/v2/users/(?P<id>[\\d]+)']);\n"
                    "  return $e;\n"
                    "});\n"
                    "או השתמש ב-plugin: 'Disable REST API'.",
                ))
        except Exception:
            pass

    # ── User enumeration: ?author= redirect ──────────────────────────────────
    found_via_author: list[str] = []
    for i in range(1, 6):
        r = await _get(client, f"{base}/?author={i}", follow_redirects=False)
        if r and r.status_code in (301, 302):
            loc = r.headers.get("location", "")
            m = re.search(r'/author/([^/?#\s]+)', loc)
            if m:
                found_via_author.append(f"?author={i} → /author/{m.group(1)}/")

    if found_via_author:
        already = any("REST API" in f.title for f in findings)
        if not already:
            findings.append(Finding(
                "high", "wordpress",
                f"מניין משתמשים — ?author= redirect ({len(found_via_author)} משתמשים)",
                "?author=N מפנה ל-/author/USERNAME/ — חושף שמות login לbrute-force.",
                found_via_author,
                "הוסף ל-functions.php:\n"
                "add_action('template_redirect', function() {\n"
                "  if (isset($_GET['author'])) { wp_redirect(home_url(), 301); exit; }\n"
                "});",
            ))
        else:
            findings[-1].evidence.extend(found_via_author)

    # ── xmlrpc.php ────────────────────────────────────────────────────────────
    r_xml = await _get(client, f"{base}/xmlrpc.php")
    if r_xml and r_xml.status_code == 200:
        payload = (
            b"<?xml version='1.0' encoding='utf-8'?>"
            b"<methodCall><methodName>system.listMethods</methodName>"
            b"<params></params></methodCall>"
        )
        r_methods = await _get(
            client, f"{base}/xmlrpc.php",
            method="POST", content=payload,
            headers={"Content-Type": "text/xml"},
        )
        if r_methods and r_methods.status_code == 200 and "methodResponse" in r_methods.text:
            has_multicall = "system.multicall" in r_methods.text
            has_wp_auth   = "wp.getUsersBlogs" in r_methods.text or "wp.getAuthors" in r_methods.text
            method_count  = len(re.findall(r'<value><string>[^<]+</string></value>', r_methods.text))
            evidence = [
                f"GET /xmlrpc.php → HTTP 200",
                f"system.listMethods → {method_count} methods",
            ]
            if has_multicall:
                evidence.append("⚠️  system.multicall פעיל — 1000 ניסיונות סיסמה בבקשה אחת!")
            if has_wp_auth:
                evidence.append("wp.getUsersBlogs / wp.getAuthors — brute-force vectors")
            findings.append(Finding(
                "high", "wordpress",
                "xmlrpc.php פעיל — Brute-Force × 1000 ו-DoS",
                "system.multicall מאפשר 1000 ניסיונות סיסמה בבקשה HTTP אחת — עוקף rate-limiting. "
                "בנוסף: DoS על ידי שליחת עשרות בקשות xmlrpc בו-זמנית.",
                evidence,
                "ב-functions.php:\nadd_filter('xmlrpc_enabled', '__return_false');\n\n"
                "ב-Nginx:\nlocation = /xmlrpc.php { deny all; return 403; }\n\n"
                "ב-Apache:\n<Files xmlrpc.php>\n  Order Deny,Allow\n  Deny from all\n</Files>",
            ))
        else:
            findings.append(Finding(
                "medium", "wordpress",
                "xmlrpc.php נגיש — תגובה לא תקינה",
                "xmlrpc.php קיים ומגיב — ייתכן שמוגבל אך עדיין ווקטור.",
                [f"/xmlrpc.php → HTTP {r_xml.status_code}"],
                "חסום xmlrpc.php בשרת אם לא נחוץ.",
            ))

    # ── wp-cron.php ───────────────────────────────────────────────────────────
    r_cron = await _get(client, f"{base}/wp-cron.php")
    if r_cron and r_cron.status_code == 200:
        findings.append(Finding(
            "low", "wordpress",
            "wp-cron.php נגיש — DoS פוטנציאלי",
            "כל גורם חיצוני יכול לגרום ל-cron jobs להתבצע — עומס CPU/DB.",
            [f"{base}/wp-cron.php → HTTP 200"],
            "ב-wp-config.php:\ndefine('DISABLE_WP_CRON', true);\n"
            "הוסף crontab אמיתי:\n*/5 * * * * wget -q -O- {base}/wp-cron.php",
        ))

    # ── WP REST API routes ────────────────────────────────────────────────────
    r_api = await _get(client, f"{base}/wp-json/")
    if r_api and r_api.status_code == 200:
        try:
            api_data = r_api.json()
            routes = list(api_data.get("routes", {}).keys())
            sensitive = [
                ro for ro in routes
                if any(k in ro.lower() for k in ["user", "setting", "plugin", "theme", "media"])
            ]
            if len(sensitive) >= 3:
                findings.append(Finding(
                    "medium", "wordpress",
                    f"WordPress REST API חשוף — {len(routes)} routes ({len(sensitive)} רגישים)",
                    "REST API חשוף לגמרי — חושף users, media, settings, ועוד.",
                    sensitive[:10],
                    "הגבל REST API:\nadd_filter('rest_authentication_errors', function($r) {\n"
                    "  if (!is_user_logged_in())\n"
                    "    return new WP_Error('rest_forbidden','Auth required',['status'=>401]);\n"
                    "  return $r;\n"
                    "});",
                ))
        except Exception:
            pass

    # ── Sensitive WP files ────────────────────────────────────────────────────
    wp_sensitive = [
        ("/wp-config.php.bak",         "critical", "גיבוי wp-config.php — DB credentials"),
        ("/wp-config.php~",             "critical", "גיבוי wp-config.php"),
        ("/wp-config.php.orig",         "critical", "גיבוי wp-config.php"),
        ("/wp-config.bak",              "critical", "גיבוי wp-config"),
        ("/.wp-config.php.swp",         "critical", "VIM swap של wp-config — מכיל credentials"),
        ("/wp-content/debug.log",       "high",     "WordPress debug.log — stack traces + paths + credentials"),
        ("/wp-admin/install.php",       "high",     "WP install.php — reinstall אפשרי"),
        ("/wp-admin/setup-config.php",  "high",     "WP setup-config.php נגיש"),
        ("/wp-content/uploads/.htaccess", "medium", ".htaccess בתיקיית uploads"),
        ("/license.txt",                "low",      "license.txt — חושף גרסה"),
    ]
    probes = [
        (_get(client, base + path), path, sev, desc)
        for path, sev, desc in wp_sensitive
    ]
    results = await asyncio.gather(*[p[0] for p in probes], return_exceptions=True)
    for resp, (_, path, sev, desc) in zip(results, probes):
        if isinstance(resp, Exception) or resp is None:
            continue
        if resp.status_code == 200 and len(resp.text) > 30:
            findings.append(Finding(
                sev, "wordpress",
                f"קובץ WP רגיש נגיש: {path}",
                desc,
                [f"{base}{path} → HTTP 200 ({len(resp.text):,} bytes)"],
                f"חסום: location ~ {re.escape(path)} {{ deny all; return 403; }}",
            ))

    # ── Plugin / theme disclosure ─────────────────────────────────────────────
    plugins = sorted(set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', html)))
    themes  = sorted(set(re.findall(r'/wp-content/themes/([a-zA-Z0-9_-]+)/',  html)))
    if plugins or themes:
        ev = []
        if plugins: ev.append(f"Plugins ({len(plugins)}): {', '.join(plugins[:15])}")
        if themes:  ev.append(f"Themes  ({len(themes)}): {', '.join(themes[:5])}")
        findings.append(Finding(
            "info", "wordpress",
            f"WordPress — {len(plugins)} plugins ו-{len(themes)} themes מזוהים מ-HTML",
            "שמות plugins ו-themes חשופים — תוקף מחפש CVEs לגרסאות ישנות.",
            ev,
            "עדכן plugins ל-latest תמיד. הסר plugins לא פעילים.\n"
            "שקול plugin 'WP Asset CleanUp' להסתרת paths.",
        ))

    # ── WP_DEBUG leak ─────────────────────────────────────────────────────────
    if re.search(r'WordPress database error|<b>Warning</b>.*?wp-|<b>Notice</b>.*?wp-includes', html, re.I):
        findings.append(Finding(
            "high", "wordpress",
            "WP_DEBUG פעיל — שגיאות PHP/SQL חשופות לכל",
            "WP_DEBUG=true מציג stack traces, שגיאות SQL ו-paths פנימיים לכל גולש.",
            ["שגיאות debug גלויות בתגובת HTTP"],
            "ב-wp-config.php:\n"
            "define('WP_DEBUG', false);\n"
            "define('WP_DEBUG_LOG', true);\n"
            "define('WP_DEBUG_DISPLAY', false);",
        ))

    return findings


async def scan_joomla(client: httpx.AsyncClient, base: str) -> list[Finding]:
    findings: list[Finding] = []

    r = await _get(client, f"{base}/administrator/manifests/files/joomla.xml")
    if r and r.status_code == 200 and "joomla" in r.text.lower():
        m = re.search(r'<version>([\d.]+)</version>', r.text)
        version = m.group(1) if m else "לא ידוע"
        findings.append(Finding(
            "high", "joomla",
            f"Joomla {version} — manifest נגיש",
            "administrator/manifests/files/joomla.xml חשוף — גרסת Joomla מדויקת לחיפוש CVEs.",
            [f"/administrator/manifests/files/joomla.xml → HTTP 200, version={version}"],
            "חסום XML files:\nlocation ~* \\.xml$ { deny all; }",
        ))

    for conf_path in ["/configuration.php-dist", "/configuration.php.bak", "/configuration.bak"]:
        r = await _get(client, base + conf_path)
        if r and r.status_code == 200 and len(r.text) > 50:
            findings.append(Finding(
                "critical", "joomla",
                f"גיבוי configuration.php נגיש: {conf_path}",
                "מכיל DB credentials, secret key ועוד. גישה מיידית למסד הנתונים.",
                [f"{base}{conf_path} → HTTP 200"],
                "מחק קבצי גיבוי. הגדר permissions: chmod 644 configuration.php",
            ))

    r_admin = await _get(client, f"{base}/administrator/", follow_redirects=False)
    if r_admin and r_admin.status_code in (200,) and "joomla" in (r_admin.text or "").lower():
        findings.append(Finding(
            "medium", "joomla",
            "Joomla Admin Panel נגיש (/administrator/)",
            "לוח הניהול נגיש לכולם — חשוף לbrute-force ממוקד.",
            [f"{base}/administrator/ → HTTP 200"],
            "שנה את כתובת Admin Panel. הוסף 2FA. הגבל לפי IP.",
        ))

    return findings


async def scan_drupal(client: httpx.AsyncClient, base: str) -> list[Finding]:
    findings: list[Finding] = []

    for changelog_path in ["/CHANGELOG.txt", "/core/CHANGELOG.txt"]:
        r = await _get(client, base + changelog_path)
        if r and r.status_code == 200 and "Drupal" in r.text:
            m = re.search(r'Drupal ([\d.]+)', r.text)
            version = m.group(1) if m else "לא ידוע"
            findings.append(Finding(
                "high", "drupal",
                f"Drupal {version} — CHANGELOG.txt נגיש",
                "CHANGELOG.txt חשוף — גרסת Drupal מדויקת לחיפוש CVEs (כולל Drupalgeddon).",
                [f"{base}{changelog_path} → HTTP 200, version={version}"],
                "חסום .txt:\nlocation ~* \\.(txt|log|md)$ { deny all; }",
            ))
            break

    r_upd = await _get(client, f"{base}/update.php")
    if r_upd and r_upd.status_code == 200 and "update" in r_upd.text.lower():
        findings.append(Finding(
            "critical", "drupal",
            "Drupal update.php נגיש",
            "תוקף יכול להריץ DB schema updates, לשנות תוכן ולמחוק נתונים.",
            [f"{base}/update.php → HTTP 200"],
            "location = /update.php { deny all; return 403; }",
        ))

    r_set = await _get(client, f"{base}/sites/default/settings.php")
    if r_set and r_set.status_code == 200 and len(r_set.text) > 50:
        findings.append(Finding(
            "critical", "drupal",
            "/sites/default/settings.php נגיש",
            "קובץ ההגדרות של Drupal — DB credentials, hash salt ועוד.",
            [f"{base}/sites/default/settings.php → HTTP 200"],
            "chmod 444 sites/default/settings.php\n"
            "location ~ /sites/.*/settings.php { deny all; }",
        ))

    return findings


async def scan_cms(
    client: httpx.AsyncClient, base: str, homepage_html: str
) -> list[Finding]:
    """Auto-detect CMS and run appropriate deep scanner."""
    html_lower = homepage_html.lower()

    is_wp = any(ind.lower() in html_lower for ind in _WP_INDICATORS)
    if not is_wp:
        r = await _get(client, f"{base}/wp-login.php")
        is_wp = bool(r and r.status_code == 200 and "wp-login" in r.text.lower())

    if is_wp:
        wp = await scan_wordpress(client, base, homepage_html)
        # Run WPScan Docker for CVE-level plugin/theme checking
        if is_available("wpscan"):
            wpscan_results = await run_wpscan(base)
            wp.extend(wpscan_results)
        wp.insert(0, Finding(
            "info", "wordpress",
            "WordPress זוהה — סריקת CMS מלאה בוצעה",
            "האתר נבנה ב-WordPress. בוצעו בדיקות ייחודיות: users, xmlrpc, REST API, plugins, קבצים רגישים."
            + (" + WPScan Docker" if is_available("wpscan") else ""),
            [f"CMS: WordPress @ {base}"],
            "",
        ))
        return wp

    is_joomla = any(ind in html_lower for ind in ["/components/com_", "joomla", "joomla!"])
    if not is_joomla:
        r = await _get(client, f"{base}/administrator/")
        is_joomla = bool(r and r.status_code == 200 and "joomla" in (r.text or "").lower())
    if is_joomla:
        return await scan_joomla(client, base)

    is_drupal = any(ind in html_lower for ind in ["drupal", "/sites/default/", "/core/misc/drupal"])
    if is_drupal:
        return await scan_drupal(client, base)

    return []


# ══════════════════════════════════════════════════════════════════════════════
# WPScan Docker integration — plugin/theme CVE matching
# ══════════════════════════════════════════════════════════════════════════════

async def run_wpscan(base: str) -> list[Finding]:
    """Run WPScan for deep WordPress vulnerability scanning."""
    findings = []
    if not is_available("wpscan"):
        return findings
    try:
        code, stdout, stderr = await run_tool("wpscan", [
            "--url", base,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--enumerate", "vp,vt,u1-5",
            "--detection-mode", "mixed",
        ], timeout=300)

        if not stdout.strip():
            return findings

        import json
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        # Parse interesting findings
        for alert in data.get("interesting_findings", []):
            findings.append(Finding(
                "medium", "wpscan",
                f"[WPScan] {alert.get('to_s', alert.get('type', 'finding'))}",
                alert.get("to_s", str(alert)),
                [ref.get("url", str(ref)) for ref in alert.get("references", {}).get("url", [])][:3],
                "Review and fix per WPScan recommendation.",
            ))

        # Plugins with vulns
        for name, info in data.get("plugins", {}).items():
            for vuln in info.get("vulnerabilities", []):
                title = vuln.get("title", name)
                refs = vuln.get("references", {}).get("url", [])
                findings.append(Finding(
                    "high", "wpscan",
                    f"[WPScan] Plugin vuln: {title}",
                    f"Plugin '{name}' v{info.get('version', {}).get('number', '?')} — {title}",
                    [f"CVE: {', '.join(vuln.get('references', {}).get('cve', []))}" if vuln.get('references', {}).get('cve') else f"Refs: {', '.join(refs[:2])}"],
                    "Update or remove the vulnerable plugin.",
                ))

        # Themes with vulns
        for name, info in data.get("themes", {}).items():
            for vuln in info.get("vulnerabilities", []):
                title = vuln.get("title", name)
                findings.append(Finding(
                    "high", "wpscan",
                    f"[WPScan] Theme vuln: {title}",
                    f"Theme '{name}' — {title}",
                    [],
                    "Update or replace the vulnerable theme.",
                ))

        # Users enumerated
        for user_info in data.get("users", {}).values() if isinstance(data.get("users"), dict) else []:
            uname = user_info if isinstance(user_info, str) else ""
            if uname:
                findings.append(Finding(
                    "low", "wpscan",
                    f"[WPScan] User enumerated: {uname}",
                    f"WordPress user '{uname}' discovered via enumeration.",
                    [],
                    "Use a security plugin to prevent user enumeration.",
                ))

    except Exception as e:
        log.debug("WPScan error: %s", e)
    return findings
