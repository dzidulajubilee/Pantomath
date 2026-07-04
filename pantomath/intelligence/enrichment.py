"""
Derives a display icon for a feed source from its domain, so the sidebar
and item tags show the publisher's real favicon instead of just a color dot.

Two responsibilities live here:
  1. derive_icon_url()  — guess a favicon URL from a source's domain.
  2. get_cached_icon()  — fetch that URL ONCE and cache the bytes to disk;
     every request after the first is a pure disk read. This is what
     backs GET /api/sources/{id}/icon. If the fetch ever fails, nothing
     is cached and the frontend's onerror handler falls back to a colored
     dot (frontend/components/icon.js) — no broken-image glyphs, no
     repeated failed fetches on every page load.
"""
import os
import time
import urllib.error
import urllib.request

from pantomath.database.sqlite import DB_PATH
from pantomath.feeds.parser import domain_from_url

FAVICON_SERVICE = "https://www.google.com/s2/favicons?sz=64&domain={domain}"
ICON_CACHE_DIR = os.environ.get(
    "PANTOMATH_ICON_CACHE", os.path.join(os.path.dirname(DB_PATH), "icons")
)
FETCH_TIMEOUT = 6  # seconds — don't let a slow/dead favicon host stall a request
NEGATIVE_CACHE_TTL = 3600  # don't retry a known-failed fetch for an hour


def derive_icon_url(source_url: str) -> str:
    domain = domain_from_url(source_url)
    return FAVICON_SERVICE.format(domain=domain)


def _paths(source_id: str):
    base = os.path.join(ICON_CACHE_DIR, source_id)
    return base + ".bin", base + ".ctype", base + ".fail"


def _fetch_bytes(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Pantomath/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        content_type = resp.headers.get("Content-Type", "image/x-icon").split(";")[0]
        return resp.read(), content_type


def fetch_and_cache_icon_sync(source_id: str, fetch_url: str):
    """
    Blocking. Call via loop.run_in_executor() from the API route.
    Returns (path, content_type) on success, None if nothing is cached
    (either never attempted successfully, or a recent attempt failed).
    """
    os.makedirs(ICON_CACHE_DIR, exist_ok=True)
    bin_path, ctype_path, fail_path = _paths(source_id)

    if os.path.exists(bin_path):
        content_type = "image/x-icon"
        if os.path.exists(ctype_path):
            with open(ctype_path) as f:
                content_type = f.read().strip() or content_type
        return bin_path, content_type

    if os.path.exists(fail_path):
        if time.time() - os.path.getmtime(fail_path) < NEGATIVE_CACHE_TTL:
            return None  # tried recently, failed — don't hammer a dead host
        os.remove(fail_path)

    try:
        data, content_type = _fetch_bytes(fetch_url)
        if not data:
            raise ValueError("empty response")
        with open(bin_path, "wb") as f:
            f.write(data)
        with open(ctype_path, "w") as f:
            f.write(content_type)
        return bin_path, content_type
    except Exception:
        with open(fail_path, "w") as f:
            f.write(str(time.time()))
        return None


def invalidate_icon_cache(source_id: str):
    """Called when a source's icon_url changes, so the next request re-fetches."""
    for path in _paths(source_id):
        if os.path.exists(path):
            os.remove(path)
