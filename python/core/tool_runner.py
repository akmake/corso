"""
External Tool Runner
--------------------
Unified wrapper for invoking external OSINT / security tools.
Discovery order:  native binary in PATH  →  Docker image  →  not available.
If a tool is missing entirely, the caller falls back to its built-in logic.

Supported tools:
  - maigret       (username OSINT, 2500+ sites)
  - holehe        (email → registered services)
  - subfinder     (subdomain enumeration)
  - nuclei        (vulnerability scanning)
  - ffuf          (directory fuzzing)
  - trufflehog    (secret scanning)
  - theHarvester  (email / subdomain harvesting)
  - katana        (web crawling)
  - sqlmap        (SQL injection automation)
  - testssl       (SSL/TLS deep analysis)
  - dalfox        (XSS scanning)
  - nikto         (web server scanner)
  - wpscan        (WordPress vuln scanner)
  - commix        (command injection)
  - wafw00f       (WAF detection)
  - rustscan      (ultra-fast port scan)
  - masscan       (mass IP port scan)
  - amass         (subdomain enum, 100+ sources)
  - httpx         (HTTP probing)
  - feroxbuster   (recursive dir brute-force)
  - arjun         (hidden param discovery)
  - gitleaks      (git secret scanning)
"""

import asyncio
import json
import shutil
import subprocess
import tempfile
import os
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ── Tool registry ─────────────────────────────────────────────────────────────

_TOOLS: dict[str, dict] = {
    "maigret": {
        "commands": ["maigret"],
        "pip": "maigret",
        "check_arg": "--version",
        "docker": "soxoj/maigret",
        "python_module": "maigret",                   # can be used as library
        "description": "Username OSINT — 2,500+ sites",
    },
    "holehe": {
        "commands": ["holehe"],
        "pip": "holehe",
        "check_arg": "--version",
        "docker": None,
        "python_module": "holehe.core",               # used as library import
        "description": "Email → registered services check",
    },
    "subfinder": {
        "commands": ["subfinder", "subfinder.exe"],
        "pip": None,
        "check_arg": "-version",
        "docker": "projectdiscovery/subfinder",
        "description": "Subdomain enumeration — 40+ sources",
    },
    "nuclei": {
        "commands": ["nuclei", "nuclei.exe"],
        "pip": None,
        "check_arg": "-version",
        "docker": "projectdiscovery/nuclei",
        "description": "Vulnerability scanner — 7,000+ templates",
    },
    "ffuf": {
        "commands": ["ffuf", "ffuf.exe"],
        "pip": None,
        "check_arg": "-V",
        "docker": "secsi/ffuf",
        "description": "Directory fuzzer — SecLists compatible",
    },
    "trufflehog": {
        "commands": ["trufflehog", "trufflehog.exe"],
        "pip": None,
        "check_arg": "--version",
        "docker": "trufflesecurity/trufflehog",
        "description": "Secret scanner — 700+ patterns",
    },
    "theHarvester": {
        "commands": ["theHarvester", "theharvester"],
        "pip": "theHarvester",
        "check_arg": "--help",
        "docker": "secsi/theharvester",
        "description": "Email & subdomain harvester",
    },
    "katana": {
        "commands": ["katana", "katana.exe"],
        "pip": None,
        "check_arg": "-version",
        "docker": "projectdiscovery/katana",
        "description": "Web crawler — ProjectDiscovery",
    },
    # ── New tools ─────────────────────────────────────────────────────────
    "sqlmap": {
        "commands": ["sqlmap", "sqlmap.exe"],
        "pip": "sqlmap",
        "check_arg": "--version",
        "python_module": "sqlmap",
        "docker": "googlesky/sqlmap",
        "description": "SQL Injection automation — 6 techniques",
    },
    "testssl": {
        "commands": ["testssl.sh", "testssl"],
        "pip": None,
        "check_arg": "--version",
        "docker": "drwetter/testssl.sh",
        "description": "SSL/TLS deep analysis — cipher suites, protocols, vulns",
    },
    "dalfox": {
        "commands": ["dalfox", "dalfox.exe"],
        "pip": None,
        "check_arg": "version",
        "docker": "hahwul/dalfox",
        "description": "XSS scanner — DOM/Reflected/Stored, WAF bypass",
    },
    "nikto": {
        "commands": ["nikto", "nikto.pl"],
        "pip": None,
        "check_arg": "-Version",
        "docker": "secsi/nikto",
        "description": "Web server scanner — 7,000+ dangerous files/CGIs",
    },
    "wpscan": {
        "commands": ["wpscan", "wpscan.exe"],
        "pip": None,
        "check_arg": "--version",
        "docker": "wpscanteam/wpscan",
        "description": "WordPress vulnerability scanner — plugin/theme CVEs",
    },
    "commix": {
        "commands": ["commix", "commix.py"],
        "pip": None,
        "check_arg": "--version",
        "docker": "googlesky/commix",
        "description": "OS command injection automation",
    },
    "wafw00f": {
        "commands": ["wafw00f"],
        "pip": "wafw00f",
        "check_arg": "--version",
        "python_module": "wafw00f",
        "docker": None,
        "description": "WAF detection — 150+ WAF fingerprints",
    },
    "rustscan": {
        "commands": ["rustscan", "rustscan.exe"],
        "pip": None,
        "check_arg": "--version",
        "docker": "rustscan/rustscan",
        "description": "Ultra-fast port scanner — full 65535 in 3 seconds",
    },
    "masscan": {
        "commands": ["masscan", "masscan.exe"],
        "pip": None,
        "check_arg": "--version",
        "docker": "adarnimrod/masscan",
        "description": "Mass IP port scanner — 10M packets/sec",
    },
    "amass": {
        "commands": ["amass", "amass.exe"],
        "pip": None,
        "check_arg": "version",
        "docker": "caffix/amass",
        "description": "Subdomain enumeration — 100+ sources (OWASP)",
    },
    "httpx": {
        "commands": ["httpx", "httpx.exe"],
        "pip": None,
        "check_arg": "-version",
        "docker": "projectdiscovery/httpx",
        "description": "HTTP probe toolkit — status, title, tech detect",
    },
    "feroxbuster": {
        "commands": ["feroxbuster", "feroxbuster.exe"],
        "pip": None,
        "check_arg": "--version",
        "docker": "epi052/feroxbuster",
        "description": "Recursive directory brute-forcer — Rust-based",
    },
    "arjun": {
        "commands": ["arjun"],
        "pip": "arjun",
        "check_arg": "--help",
        "python_module": "arjun",
        "docker": None,
        "description": "Hidden HTTP parameter discovery",
    },
    "gitleaks": {
        "commands": ["gitleaks", "gitleaks.exe"],
        "pip": None,
        "check_arg": "version",
        "docker": "zricethezav/gitleaks",
        "description": "Git secret scanner — alternative to TruffleHog",
    },
}

# ── Resolution cache ──────────────────────────────────────────────────────────
# Values: "native:<path>" | "docker:<image>" | None (not found)
_resolved: dict[str, Optional[str]] = {}
_docker_ok: Optional[bool] = None          # lazily checked once


def _docker_available() -> bool:
    """Check once whether the docker CLI and daemon are reachable."""
    global _docker_ok
    if _docker_ok is not None:
        return _docker_ok
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=10,
        )
        _docker_ok = r.returncode == 0
    except Exception:
        _docker_ok = False
    return _docker_ok


def _docker_image_exists(image: str) -> bool:
    """Check if a Docker image is already pulled locally."""
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def is_available(tool_name: str) -> bool:
    """Check if an external tool is reachable (native or Docker)."""
    return _resolve(tool_name) is not None


def get_path(tool_name: str) -> Optional[str]:
    """Return native executable path, or None (kept for backward compat)."""
    res = _resolve(tool_name)
    if res and res.startswith("native:"):
        return res[7:]
    return None


def get_mode(tool_name: str) -> Optional[str]:
    """Return 'native', 'docker', 'python', or None."""
    res = _resolve(tool_name)
    if not res:
        return None
    return res.split(":")[0]


def _can_import(module_name: str) -> bool:
    """Check if a Python module can be imported without errors."""
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def _can_execute(path: str, check_arg: str) -> bool:
    """Verify an executable can actually run (detects WDAC blocks)."""
    try:
        r = subprocess.run(
            [path, check_arg],
            capture_output=True, timeout=10,
        )
        # Any exit code is fine — we just need the process to start
        return True
    except OSError:
        # Permission denied / blocked by Application Control
        return False
    except subprocess.TimeoutExpired:
        return True  # started fine, just slow
    except Exception:
        return False


def _resolve(tool_name: str) -> Optional[str]:
    """Resolve how to run a tool: native binary → Python import → Docker."""
    if tool_name in _resolved:
        return _resolved[tool_name]

    info = _TOOLS.get(tool_name)
    if not info:
        _resolved[tool_name] = None
        return None

    # 1. Native binary in PATH — verify it can actually execute
    for cmd in info["commands"]:
        path = shutil.which(cmd)
        if path and _can_execute(path, info.get("check_arg", "--version")):
            _resolved[tool_name] = f"native:{path}"
            return _resolved[tool_name]

    # 2. Python library import (for pip-installed tools whose .exe may be blocked)
    py_mod = info.get("python_module")
    if py_mod and _can_import(py_mod):
        _resolved[tool_name] = f"python:{py_mod}"
        return _resolved[tool_name]

    # 3. Docker image available locally
    docker_img = info.get("docker")
    if docker_img and _docker_available() and _docker_image_exists(docker_img):
        _resolved[tool_name] = f"docker:{docker_img}"
        return _resolved[tool_name]

    _resolved[tool_name] = None
    return None


def get_all_status() -> dict[str, dict]:
    """Return availability status for every registered tool."""
    result = {}
    for name, info in _TOOLS.items():
        res = _resolve(name)
        mode = get_mode(name)
        result[name] = {
            "available": res is not None,
            "mode": mode or "",
            "path": get_path(name) or (res[7:] if res and res.startswith("docker:") else ""),
            "description": info["description"],
            "pip": info.get("pip", ""),
            "docker_image": info.get("docker", ""),
            "install_hint": _install_hint(name),
        }
    return result


def _install_hint(name: str) -> str:
    """Return a user-friendly install command."""
    info = _TOOLS[name]
    hints = []
    if info.get("pip"):
        hints.append(f"pip install {info['pip']}")
    if info.get("docker"):
        hints.append(f"docker pull {info['docker']}")
    if name in ("subfinder", "nuclei", "katana", "ffuf", "httpx"):
        hints.append(f"go install -v github.com/projectdiscovery/{name}/v2/cmd/{name}@latest")
    if name == "trufflehog":
        hints.append("go install github.com/trufflesecurity/trufflehog/v3@latest")
    if name == "dalfox":
        hints.append("go install github.com/hahwul/dalfox/v2@latest")
    if name == "feroxbuster":
        hints.append("cargo install feroxbuster")
    if name == "rustscan":
        hints.append("cargo install rustscan")
    if name == "amass":
        hints.append("go install -v github.com/owasp-amass/amass/v4/...@master")
    if name == "gitleaks":
        hints.append("go install github.com/zricethezav/gitleaks/v8@latest")
    return " | ".join(hints)


# ── Execution ─────────────────────────────────────────────────────────────────

async def run_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 300,
    stdin_data: Optional[str] = None,
) -> tuple[int, str, str]:
    """
    Run an external tool and return (exit_code, stdout, stderr).
    Automatically uses Docker if native binary is not available.
    Raises FileNotFoundError if the tool is not installed at all.
    """
    res = _resolve(tool_name)
    if not res:
        raise FileNotFoundError(f"{tool_name} is not installed. {_install_hint(tool_name)}")

    if res.startswith("docker:"):
        return await _run_docker(res[7:], args, timeout, stdin_data)
    else:
        return await _run_native(res[7:], args, timeout, stdin_data)


async def _run_native(
    path: str, args: list[str], timeout: int, stdin_data: Optional[str],
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        path, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin_data else None,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Timeout after {timeout}s"

    return (
        proc.returncode,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


async def _run_docker(
    image: str, args: list[str], timeout: int, stdin_data: Optional[str],
    extra_args: Optional[list[str]] = None,
) -> tuple[int, str, str]:
    """Run a tool inside a Docker container with --rm."""
    cmd = ["docker", "run", "--rm"]
    if extra_args:
        cmd += extra_args
    cmd += [image] + args

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin_data else None,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Docker timeout after {timeout}s"

    return (
        proc.returncode,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


async def run_tool_json(
    tool_name: str,
    args: list[str],
    timeout: int = 300,
) -> Optional[list | dict]:
    """Run a tool and parse its stdout as JSON (or JSON-Lines)."""
    code, stdout, stderr = await run_tool(tool_name, args, timeout)
    if not stdout.strip():
        return None

    # Try full JSON first
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass

    # Try JSON-lines (one JSON object per line — common in ProjectDiscovery tools)
    items = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items if items else None


def make_temp_file(suffix: str = ".txt", content: str = "") -> str:
    """Create a temp file and return its path. Caller should delete it."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    if content:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        os.close(fd)
    return path
