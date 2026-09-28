"""
Fetches the full article page and extracts its plain text, for richer
severity/tag/IOC extraction than an RSS summary alone can provide.

Why this exists: RSS feed summaries are typically short teasers (one or
two sentences) — the real signal for IOC extraction (C2 IPs, file
hashes, full CVE lists) usually lives in the article body on the
publisher's site, not in the feed's teaser text. Scanning only the
teaser systematically under-detects IOCs.

This is best-effort and silent on failure: paywalls, bot-blocking,
timeouts, non-HTML responses, or any other failure just means falling
back to title+summary only for that item — never blocks storing it, and
never raises. See pantomath/connectors/rss.py for how the result is used.
"""
import urllib.error
import urllib.request
from html.parser import HTMLParser

FETCH_TIMEOUT = 8  # seconds — don't let a slow publisher stall the whole poll
MAX_RAW_BYTES = 400_000  # cap what we read; real articles don't need more than this
MAX_TEXT_LENGTH = 20_000  # cap what we hand to the regex-based extractors
_SKIP_TAGS = {"script", "style", "noscript", "header", "footer", "nav", "svg"}


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            text = data.strip()
            if text:
                self.chunks.append(text)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return " ".join(parser.chunks)


def fetch_article_text_sync(url: str) -> str:
    """Blocking. Call via loop.run_in_executor(). Returns '' on any failure — never raises."""
    if not url:
        return ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pantomath/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                return ""
            raw = resp.read(MAX_RAW_BYTES)
        html = raw.decode("utf-8", errors="ignore")
        return html_to_text(html)[:MAX_TEXT_LENGTH]
    except Exception:
        return ""
