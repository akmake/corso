"""
Simple file-based cache for OPAL scan results.
Stored at: downloads/openu/scan_cache.json

Keys are derived from (course_url, section_title/url) so the same
scan won't be repeated unnecessarily.  Results expire after TTL_DAYS.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any

_CACHE_FILE = Path(__file__).parent.parent / "downloads" / "openu" / "scan_cache.json"
_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

TTL_DAYS = 7
TTL_SECS = TTL_DAYS * 86_400


def _load() -> dict:
    try:
        if _CACHE_FILE.exists():
            return json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save(cache: dict) -> None:
    try:
        _CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception:
        pass


def _key(*parts: str) -> str:
    joined = "|".join(p.strip() for p in parts if p)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def get(namespace: str, *key_parts: str) -> dict | None:
    """Return cached data or None if missing / expired."""
    cache = _load()
    k = namespace + ":" + _key(*key_parts)
    entry = cache.get(k)
    if not entry:
        return None
    if time.time() - entry.get("ts", 0) > TTL_SECS:
        return None
    return entry.get("data")


def put(namespace: str, data: Any, *key_parts: str) -> None:
    """Store data under the given key."""
    cache = _load()
    k = namespace + ":" + _key(*key_parts)
    cache[k] = {"ts": time.time(), "data": data}
    _save(cache)


def invalidate(namespace: str, *key_parts: str) -> None:
    """Remove a specific cache entry."""
    cache = _load()
    k = namespace + ":" + _key(*key_parts)
    cache.pop(k, None)
    _save(cache)


def clear_all() -> None:
    _save({})
