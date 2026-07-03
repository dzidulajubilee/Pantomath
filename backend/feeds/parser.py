"""
Normalizes a feedparser entry (whose shape varies a lot between publishers)
into the flat dict shape the rest of the app expects.
"""
import time
import hashlib


def normalize_entry(entry) -> dict:
    guid = entry.get("id") or entry.get("link") or hashlib.sha1(
        entry.get("title", "").encode()
    ).hexdigest()

    published_struct = entry.get("published_parsed") or entry.get("updated_parsed")
    published_ts = time.mktime(published_struct) if published_struct else time.time()

    summary = entry.get("summary", "") or entry.get("description", "")

    return {
        "guid": guid,
        "title": entry.get("title", "(no title)"),
        "link": entry.get("link", ""),
        "summary": summary[:2000],
        "published": published_ts,
    }


def domain_from_url(url: str) -> str:
    """Best-effort extraction of a bare domain, used for favicon lookups."""
    stripped = url.split("://", 1)[-1]
    domain = stripped.split("/", 1)[0]
    return domain.split("@")[-1]  # strip any userinfo
