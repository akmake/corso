"""
Secret Scanner
--------------
Finds exposed API keys, tokens, and secrets in web pages.
Uses TruffleHog (700+ patterns) if installed, falls back to 8 built-in regex patterns.
"""

import json
import os
import re
import logging
import httpx
from typing import Dict, List, Any

from core.tool_runner import is_available, run_tool, make_temp_file

_log = logging.getLogger(__name__)

SECRET_PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "GitHub Token": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82})",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "JSON Web Token (JWT)": r"ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Generic Password/Secret/Token": r"(?i)(?:password|secret|api_key|apikey|token|auth_token|access_token|client_secret)[^\w]*(?:=|:)[^\w]*([a-zA-Z0-9\-_]{16,})"
}

class SecretScanner:
    """
    Sifts through text or a specific web page/JS file looking for exposed API
    keys, generic secrets, AWS keys and JWTs using Regex patterns.
    """
    def __init__(self, target_url: str = "", cookies: str = "", auth_token: str = ""):
        self.target_url  = target_url
        self.cookies     = cookies
        self.auth_token  = auth_token

    async def scan(self) -> Dict[str, Any]:
        # Try TruffleHog first (700+ patterns)
        if is_available("trufflehog"):
            th_result = await self._scan_trufflehog()
            if th_result is not None:
                return th_result

        # Fallback to built-in regex scan
        result: Dict[str, Any] = {"url": self.target_url, "findings": {}, "total_secrets_found": 0}
        try:
            _headers = {}
            if self.auth_token:
                _headers["Authorization"] = f"Bearer {self.auth_token}"
            _cookies = {}
            if self.cookies:
                for pair in self.cookies.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        _cookies[k.strip()] = v.strip()
            async with httpx.AsyncClient(timeout=15, verify=False, headers=_headers, cookies=_cookies) as client:
                res = await client.get(self.target_url)
                text = res.text
                
            findings = self.scan_text(text)
            result["findings"] = findings
            result["total_secrets_found"] = sum(len(v) for v in findings.values())
            result["engine"] = "builtin"
            
        except Exception as e:
            result["error"] = str(e)
            
        return result

    async def _scan_trufflehog(self) -> Dict[str, Any] | None:
        """Run TruffleHog on the target URL — downloads content to temp file, scans with filesystem source."""
        import tempfile, shutil
        tmpdir = None
        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                r = await client.get(self.target_url)
                page_content = r.text

            tmpdir = tempfile.mkdtemp(prefix="webint_th_")
            tmpfile = os.path.join(tmpdir, "page.html")
            with open(tmpfile, "w", encoding="utf-8", errors="replace") as f:
                f.write(page_content)

            code, stdout, stderr = await run_tool(
                "trufflehog",
                ["filesystem", tmpdir, "--json", "--no-update", "--no-verification"],
                timeout=60,
            )
            if not stdout.strip():
                return {
                    "url": self.target_url,
                    "findings": {},
                    "total_secrets_found": 0,
                    "engine": "trufflehog",
                }

            findings: Dict[str, list] = {}
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                detector = entry.get("DetectorName", entry.get("detectorName", "Unknown"))
                raw = entry.get("Raw", entry.get("raw", ""))
                verified = entry.get("Verified", False)

                label = f"{detector} ({'verified' if verified else 'unverified'})"
                if label not in findings:
                    findings[label] = []
                if raw and raw not in findings[label]:
                    findings[label].append(raw[:200])  # truncate

            return {
                "url": self.target_url,
                "findings": findings,
                "total_secrets_found": sum(len(v) for v in findings.values()),
                "engine": "trufflehog",
            }
        except Exception as e:
            _log.warning("TruffleHog failed: %s", e)
            return None
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def scan_text(self, text: str) -> Dict[str, List[str]]:
        results = {}
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                valid_matches = set()
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    # Basic noise reduction
                    if len(match) > 600: 
                        continue
                    valid_matches.add(match)
                    
                if valid_matches:
                    results[name] = list(valid_matches)
        return results
