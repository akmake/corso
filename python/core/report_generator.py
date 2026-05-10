"""
Pentest Report Generator
------------------------
Generates a professional HTML pentest report from scan results.
  - Executive summary with severity pie chart (SVG)
  - Full findings table sorted by severity
  - Per-finding sections with evidence and recommendations
  - Attack chains section
  - CVSS score estimation
  - Remediation checklist
  - Export as standalone HTML (no external dependencies)
"""

import json
from datetime import datetime
from typing import Optional
from pathlib import Path

# ── Severity config ────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}
_SEV_HE = {
    "critical": "קריטי",
    "high":     "גבוה",
    "medium":   "בינוני",
    "low":      "נמוך",
    "info":     "מידע",
}

# ── Rough CVSS estimator ───────────────────────────────────────────────────────

_CVSS_APPROX = {
    "critical": "9.0 – 10.0",
    "high":     "7.0 – 8.9",
    "medium":   "4.0 – 6.9",
    "low":      "0.1 – 3.9",
    "info":     "0.0",
}

# ── HTML template ─────────────────────────────────────────────────────────────

def _html_escape(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

def _severity_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#6b7280")
    label = _SEV_HE.get(sev, sev)
    return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;">{label}</span>'

def _svg_pie(counts: dict) -> str:
    """Generate a simple SVG pie chart for severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return ""

    cx, cy, r = 80, 80, 70
    slices = []
    start = -90.0  # Start from top

    def polar(angle, radius=r):
        import math
        rad = math.radians(angle)
        return cx + radius * math.cos(rad), cy + radius * math.sin(rad)

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        angle = 360 * count / total
        end = start + angle
        x1, y1 = polar(start)
        x2, y2 = polar(end)
        large = 1 if angle > 180 else 0
        color = _SEV_COLORS[sev]
        path = f'M {cx},{cy} L {x1:.2f},{y1:.2f} A {r},{r} 0 {large},1 {x2:.2f},{y2:.2f} Z'
        slices.append(f'<path d="{path}" fill="{color}" opacity="0.9"/>')
        start = end

    return f'''<svg viewBox="0 0 160 160" width="160" height="160">
      {"".join(slices)}
    </svg>'''

def _generate_report_html(
    target: str,
    scan_date: str,
    tester: str,
    all_findings: list[dict],
    attack_chains: list[dict] = None,
    scope: str = "",
    executive_summary: str = "",
) -> str:
    # Sort findings by severity
    all_findings = sorted(all_findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    pie_svg = _svg_pie(counts)
    total = len(all_findings)
    attack_chains = attack_chains or []

    # Build findings HTML
    findings_html = ""
    for i, f in enumerate(all_findings, 1):
        sev = f.get("severity", "info")
        color = _SEV_COLORS.get(sev, "#6b7280")
        evidence_items = "".join(
            f'<li><code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:12px;">{_html_escape(str(e))}</code></li>'
            for e in f.get("evidence", [])
        )
        tags_html = "".join(
            f'<span style="background:#e2e8f0;padding:1px 8px;border-radius:10px;font-size:11px;margin-right:4px;">{_html_escape(t)}</span>'
            for t in f.get("tags", [])
        )
        cve = f.get("cve", "")
        cve_html = f'<span style="background:#fef3c7;color:#92400e;padding:1px 8px;border-radius:10px;font-size:11px;">{_html_escape(cve)}</span>' if cve else ""
        cvss = _CVSS_APPROX.get(sev, "N/A")

        findings_html += f'''
        <div id="finding-{i}" style="border:1px solid {color}33;border-left:4px solid {color};border-radius:8px;padding:20px;margin-bottom:16px;background:#fff;">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div>
              <span style="color:#94a3b8;font-size:12px;font-weight:600;">#{i}</span>
              <h3 style="margin:4px 0;font-size:16px;color:#1e293b;">{_html_escape(f.get("title",""))}</h3>
              <div style="margin-top:6px;">{_severity_badge(sev)} {cve_html}</div>
            </div>
            <div style="text-align:right;font-size:12px;color:#64748b;">
              <div><b>CVSS (approx):</b> {cvss}</div>
              <div><b>קטגוריה:</b> {_html_escape(f.get("category",""))}</div>
            </div>
          </div>
          <p style="color:#475569;margin:12px 0 8px;font-size:14px;line-height:1.6;">{_html_escape(f.get("description",""))}</p>
          {'<div style="margin:10px 0;"><b style="font-size:13px;">ראיות:</b><ul style="margin:6px 0;padding-right:20px;">' + evidence_items + '</ul></div>' if evidence_items else ''}
          {'<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:10px 14px;margin-top:10px;"><b style="font-size:13px;color:#166534;">המלצת תיקון:</b><p style="margin:4px 0;font-size:13px;color:#15803d;">' + _html_escape(f.get("recommendation","")) + '</p></div>' if f.get("recommendation") else ''}
          {'<div style="margin-top:10px;">' + tags_html + '</div>' if tags_html else ''}
        </div>'''

    # Build attack chains HTML
    chains_html = ""
    for chain in attack_chains:
        chain_sev = chain.get("severity", "high")
        chain_color = _SEV_COLORS.get(chain_sev, "#ea580c")
        steps = "".join(
            f'<li style="margin:4px 0;font-size:13px;">{_html_escape(str(s))}</li>'
            for s in chain.get("steps", [])
        )
        chains_html += f'''
        <div style="border:1px solid {chain_color}44;border-left:4px solid {chain_color};border-radius:8px;padding:16px;margin-bottom:12px;background:#fff;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            {_severity_badge(chain_sev)}
            <h4 style="margin:0;font-size:15px;">{_html_escape(chain.get("title",""))}</h4>
          </div>
          <p style="color:#475569;font-size:13px;margin:0 0 8px;">{_html_escape(chain.get("description",""))}</p>
          <ol style="margin:0;padding-right:20px;">{steps}</ol>
        </div>'''

    # Summary table rows
    summary_rows = "".join(
        f'<tr><td>{_severity_badge(sev)}</td><td style="font-size:14px;text-align:center;font-weight:700;color:{_SEV_COLORS.get(sev,"#000")};">{counts.get(sev,0)}</td></tr>'
        for sev in ["critical", "high", "medium", "low", "info"]
    )

    # TOC
    toc_items = "".join(
        f'<li><a href="#finding-{i}" style="color:#3b82f6;text-decoration:none;font-size:13px;">'
        f'[{f.get("severity","info").upper()}] {_html_escape(f.get("title",""))[:70]}</a></li>'
        for i, f in enumerate(all_findings, 1)
        if f.get("severity") in ("critical", "high")
    )

    remediation_items = "".join(
        f'<li style="margin:6px 0;font-size:13px;"><label><input type="checkbox"> '
        f'<b>[{f.get("severity","").upper()}]</b> {_html_escape(f.get("title","")[:80])}</label></li>'
        for f in all_findings
        if f.get("severity") in ("critical", "high", "medium")
    )

    risk_level = "קריטי" if counts["critical"] > 0 else ("גבוה" if counts["high"] > 0 else ("בינוני" if counts["medium"] > 0 else "נמוך"))
    risk_color = _SEV_COLORS.get("critical" if counts["critical"] > 0 else ("high" if counts["high"] > 0 else ("medium" if counts["medium"] > 0 else "low")), "#6b7280")

    default_summary = f"""נבדקו {total} ממצאי אבטחה ב-{_html_escape(target)}.
    רמת הסיכון הכוללת: <b style="color:{risk_color};">{risk_level}</b>.
    נמצאו {counts['critical']} ממצאים קריטיים ו-{counts['high']} גבוהים הדורשים טיפול מיידי."""

    return f'''<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Pentest Report — {_html_escape(target)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #1e293b; direction: rtl; }}
    .page {{ max-width: 960px; margin: 0 auto; padding: 32px 24px; }}
    h1, h2, h3, h4 {{ font-weight: 700; }}
    code {{ font-family: "Courier New", monospace; word-break: break-all; }}
    @media print {{
      body {{ background: #fff; }}
      .no-print {{ display: none !important; }}
    }}
  </style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div style="background:linear-gradient(135deg,#1e293b,#0f172a);color:#fff;border-radius:12px;padding:36px;margin-bottom:24px;">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
      <div>
        <div style="font-size:12px;letter-spacing:2px;opacity:0.6;margin-bottom:8px;">WEB PENETRATION TESTING</div>
        <h1 style="font-size:28px;margin-bottom:6px;">דוח בדיקת חדירות</h1>
        <div style="font-size:16px;opacity:0.8;">{_html_escape(target)}</div>
      </div>
      <div style="text-align:left;font-size:13px;opacity:0.8;">
        <div><b>תאריך:</b> {_html_escape(scan_date)}</div>
        <div><b>בודק:</b> {_html_escape(tester or "WEBINT Platform")}</div>
        {'<div><b>Scope:</b> ' + _html_escape(scope) + '</div>' if scope else ''}
        <div style="margin-top:10px;padding:8px 14px;background:rgba(255,255,255,0.1);border-radius:8px;font-weight:700;color:{risk_color};">{risk_level} RISK</div>
      </div>
    </div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #e2e8f0;">
    <h2 style="font-size:18px;margin-bottom:16px;color:#1e293b;">סיכום מנהלים</h2>
    <div style="display:flex;gap:24px;align-items:center;flex-wrap:wrap;">
      <div>{pie_svg}</div>
      <div style="flex:1;">
        <p style="font-size:14px;line-height:1.7;color:#475569;margin-bottom:16px;">{executive_summary or default_summary}</p>
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="background:#f1f5f9;">
              <th style="padding:8px 12px;text-align:right;font-size:13px;">רמת חומרה</th>
              <th style="padding:8px 12px;text-align:center;font-size:13px;">כמות</th>
            </tr>
          </thead>
          <tbody>{summary_rows}</tbody>
          <tfoot>
            <tr style="background:#f8fafc;border-top:2px solid #e2e8f0;">
              <td style="padding:8px 12px;font-weight:700;font-size:14px;">סה"כ</td>
              <td style="padding:8px 12px;text-align:center;font-weight:700;font-size:16px;">{total}</td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  </div>

  <!-- TOC (Critical + High only) -->
  {f'''<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #e2e8f0;">
    <h2 style="font-size:18px;margin-bottom:12px;">ממצאים קריטיים וגבוהים</h2>
    <ol style="padding-right:20px;">{toc_items}</ol>
  </div>''' if toc_items else ''}

  <!-- ATTACK CHAINS -->
  {f'''<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #e2e8f0;">
    <h2 style="font-size:18px;margin-bottom:16px;">שרשראות תקיפה</h2>
    {chains_html}
  </div>''' if chains_html else ''}

  <!-- ALL FINDINGS -->
  <div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #e2e8f0;">
    <h2 style="font-size:18px;margin-bottom:16px;">כל הממצאים ({total})</h2>
    {findings_html if findings_html else '<p style="color:#94a3b8;font-size:14px;">לא נמצאו ממצאים.</p>'}
  </div>

  <!-- REMEDIATION CHECKLIST -->
  {f'''<div style="background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;border:1px solid #e2e8f0;">
    <h2 style="font-size:18px;margin-bottom:16px;">צ'קליסט תיקון</h2>
    <ul style="list-style:none;padding:0;">{remediation_items}</ul>
  </div>''' if remediation_items else ''}

  <!-- FOOTER -->
  <div style="text-align:center;font-size:12px;color:#94a3b8;padding:16px 0;">
    Generated by <b>WEBINT Security Platform</b> — {_html_escape(scan_date)} — CONFIDENTIAL
  </div>

</div>
</body>
</html>'''


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_report(
    target: str,
    all_findings: list[dict],
    attack_chains: list[dict] = None,
    tester: str = "",
    scope: str = "",
    executive_summary: str = "",
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a full HTML pentest report.
    Returns the HTML string and optionally saves to output_path.
    """
    scan_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    html = _generate_report_html(
        target=target,
        scan_date=scan_date,
        tester=tester,
        all_findings=all_findings,
        attack_chains=attack_chains or [],
        scope=scope,
        executive_summary=executive_summary,
    )
    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    return html


def merge_scan_results(*scan_results: dict) -> list[dict]:
    """Merge findings from multiple scanner outputs into a flat list."""
    all_findings = []
    for result in scan_results:
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list):
                all_findings.extend(findings)
            # Some scanners nest findings inside categories
            for k, v in result.items():
                if isinstance(v, dict) and "findings" in v:
                    all_findings.extend(v["findings"])
    return all_findings
