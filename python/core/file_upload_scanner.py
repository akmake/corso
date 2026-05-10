"""
File Upload Scanner
-------------------
Lightweight async scanner for insecure file-upload flows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin

import aiohttp


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    recommendation: str = ""
    tags: list = field(default_factory=list)

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tags": self.tags,
        }


_TIMEOUT = aiohttp.ClientTimeout(total=20)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


def _emit(log: Optional[Callable[[str], None]], msg: str):
    if log:
        try:
            log(msg)
        except Exception:
            pass


def _count(sev: str, findings: list[dict]) -> int:
    return sum(1 for f in findings if f.get("severity") == sev)


async def _fetch_html(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, headers=_HEADERS, ssl=False, allow_redirects=True) as resp:
            ctype = (resp.headers.get("content-type") or "").lower()
            if "html" not in ctype:
                return ""
            return await resp.text(errors="ignore")
    except Exception:
        return ""


def _extract_forms(html: str) -> list[dict]:
    forms: list[dict] = []
    form_re = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

    for m in form_re.finditer(html):
        form_html = m.group(0)
        inner = m.group(1)

        action_m = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        method_m = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        enctype_m = re.search(r'enctype\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)

        has_file_input = re.search(r'<input[^>]*type\s*=\s*["\']file["\']', inner, re.IGNORECASE) is not None

        forms.append({
            "action": action_m.group(1).strip() if action_m else "",
            "method": (method_m.group(1).strip().upper() if method_m else "GET"),
            "enctype": (enctype_m.group(1).strip().lower() if enctype_m else ""),
            "has_file_input": has_file_input,
        })
    return forms


async def scan_file_upload(target_url: str, log: Optional[Callable[[str], None]] = None) -> dict:
    findings: list[dict] = []

    _emit(log, "[FileUpload] איסוף דף יעד...")

    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
        html = await _fetch_html(session, target_url)
        if not html:
            _emit(log, "[FileUpload] לא התקבל HTML לבדיקה")
            return {
                "target": target_url,
                "findings": [],
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0,
                "note": "No HTML response or page not reachable",
            }

        forms = _extract_forms(html)
        upload_forms = [f for f in forms if f["has_file_input"]]

        _emit(log, f"[FileUpload] נמצאו {len(upload_forms)} טפסי העלאת קבצים")

        for i, f in enumerate(upload_forms, start=1):
            action_url = urljoin(target_url, f["action"] or "")
            method = f["method"]
            enctype = f["enctype"]

            if method != "POST":
                findings.append(Finding(
                    severity="medium",
                    category="file-upload",
                    title="Upload form uses non-POST method",
                    description="File upload form appears to use a method other than POST.",
                    evidence=[f"form#{i} method={method}", f"action={action_url}"],
                    recommendation="Use POST for upload endpoints and enforce CSRF protections.",
                    tags=["file-upload", "http-method"],
                ).to_dict())

            if "multipart/form-data" not in enctype:
                findings.append(Finding(
                    severity="low",
                    category="file-upload",
                    title="Upload form missing multipart/form-data",
                    description="Upload form does not explicitly define multipart/form-data enctype.",
                    evidence=[f"form#{i} enctype={enctype or '(missing)'}", f"action={action_url}"],
                    recommendation="Set enctype='multipart/form-data' explicitly.",
                    tags=["file-upload", "form"],
                ).to_dict())

            if re.search(r"upload|file|media|image|video", action_url, re.IGNORECASE):
                findings.append(Finding(
                    severity="info",
                    category="file-upload",
                    title="Potential upload endpoint discovered",
                    description="Endpoint path suggests upload handling and should be hardened.",
                    evidence=[f"form#{i} action={action_url}"],
                    recommendation="Validate extension/MIME/content, store outside webroot, randomize filenames, disable execution.",
                    tags=["file-upload", "discovery"],
                ).to_dict())

    return {
        "target": target_url,
        "findings": findings,
        "critical": _count("critical", findings),
        "high": _count("high", findings),
        "medium": _count("medium", findings),
        "low": _count("low", findings),
        "info": _count("info", findings),
        "total": len(findings),
    }
