"""
Fetches raw RSS/Atom feeds. feedparser is synchronous/blocking, so callers
must run this inside a thread executor to avoid stalling the event loop.
"""
import feedparser


def fetch_raw(url: str):
    """Blocking fetch+parse of a feed URL. Run via loop.run_in_executor()."""
    return feedparser.parse(url)
