"""
Fetches raw RSS/Atom feeds. Blocking — callers must run this inside a
thread executor to avoid stalling the event loop.

The HTTP fetch is done here with urllib rather than by handing the URL
straight to feedparser.parse(), because feedparser's built-in fetcher has
two properties that are fine for a one-off script and wrong for a
long-running poller:

  1. No timeout. It opens the URL with no socket timeout at all, so a
     feed server that accepts the connection and then never answers
     blocks the calling thread forever. The scheduler polls sources one
     after another, so a single such source silently stalled polling for
     EVERY source, not just itself.
  2. It never raises. A 404, a DNS failure, a refused connection or an
     HTML page all come back as an empty entry list with a `bozo` flag
     set — which the scheduler recorded as last_status 'ok'. A dead feed
     looked exactly like a quiet one.

So: fetch the bytes here (bounded by a per-read timeout, an overall
deadline and a size cap), raise FeedFetchError with a short
human-readable reason on any failure, and only then hand the bytes to
feedparser purely as a parser. Same conventions as article_fetcher.py and
enrichment.py (urllib, explicit timeout, capped read) rather than adding
an HTTP client dependency. The scheduler stores str(FeedFetchError) as
the source's last_status, so the messages are written for the Sources
table, not for a log file.
"""
import http.client
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

import feedparser
from feedparser.http import ACCEPT_HEADER

FEED_READ_TIMEOUT = 15  # seconds per connect/read — how long a silent server can stall us
FEED_TOTAL_DEADLINE = 45  # seconds for the whole download — stops slow-drip servers
MAX_FEED_BYTES = 10 * 1024 * 1024  # real feeds are KBs; even very large ones are a few MB
# Backstop enforced by the connector around the executor call. The limits
# above can't cover DNS resolution (urllib has no timeout for it), which on
# a host with a broken resolver can hang for minutes.
FETCH_HARD_LIMIT = FEED_TOTAL_DEADLINE + FEED_READ_TIMEOUT + 5

# Keep sending feedparser's own User-Agent and Accept header (ACCEPT_HEADER,
# imported above): they're what every publisher has seen from Pantomath so
# far, so any site that allowed it before still allows it now.
USER_AGENT = feedparser.USER_AGENT


class FeedFetchError(Exception):
    """A feed couldn't be retrieved or isn't a feed. str() is shown in the UI."""


def _describe_url_error(reason) -> str:
    if isinstance(reason, socket.gaierror):
        return "could not resolve the host name (DNS lookup failed)"
    if isinstance(reason, ConnectionRefusedError):
        return "connection refused by the server"
    if isinstance(reason, TimeoutError):
        return f"no response from the server within {FEED_READ_TIMEOUT}s"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"TLS certificate verification failed ({reason.verify_message})"
    if isinstance(reason, ssl.SSLError):
        return "TLS handshake failed"
    return str(reason) or reason.__class__.__name__


def _read_capped(resp) -> bytes:
    """
    read1() rather than read(n): read(n) on an HTTP response keeps
    reading until it has n bytes, so a server dripping one byte at a time
    would never trip either the per-read timeout or the deadline check.
    """
    deadline = time.monotonic() + FEED_TOTAL_DEADLINE
    chunks, total = [], 0
    while True:
        if time.monotonic() > deadline:
            raise FeedFetchError(f"download did not finish within {FEED_TOTAL_DEADLINE}s")
        chunk = resp.read1(64 * 1024)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_FEED_BYTES:
            raise FeedFetchError(f"feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB")
        chunks.append(chunk)


def _decompress(body: bytes, content_encoding: str) -> bytes:
    encoding = (content_encoding or "").strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding in ("gzip", "x-gzip"):
        attempts = [16 + zlib.MAX_WBITS]
    elif encoding == "deflate":
        attempts = [zlib.MAX_WBITS, -zlib.MAX_WBITS]  # zlib-wrapped, then raw (both exist in the wild)
    else:
        raise FeedFetchError(f"unsupported Content-Encoding '{encoding}'")
    for wbits in attempts:
        try:
            # max_length caps the decompressed size too, so a small
            # compressed response can't inflate into gigabytes.
            out = zlib.decompressobj(wbits).decompress(body, MAX_FEED_BYTES + 1)
        except zlib.error:
            continue
        if len(out) > MAX_FEED_BYTES:
            raise FeedFetchError(f"feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB")
        return out
    raise FeedFetchError(f"response is not valid {encoding} data")


def fetch_raw(url: str):
    """
    Blocking fetch + parse of a feed URL. Run via loop.run_in_executor().
    Returns a feedparser result; raises FeedFetchError on any failure.
    """
    # Only http(s). feedparser.parse() also accepts local file paths and
    # even raw XML strings, so a "URL" like /etc/passwd used to be read
    # straight off the server's disk.
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        raise FeedFetchError("only http:// and https:// feed URLs are supported")

    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT_HEADER,
        "Accept-Encoding": "gzip, deflate",
    })
    try:
        with urllib.request.urlopen(request, timeout=FEED_READ_TIMEOUT) as resp:
            body = _read_capped(resp)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = resp.geturl()
            status = resp.status
    except urllib.error.HTTPError as e:
        raise FeedFetchError(f"HTTP {e.code} {e.reason}".strip()) from e
    except urllib.error.URLError as e:
        raise FeedFetchError(_describe_url_error(e.reason)) from e
    except TimeoutError as e:
        raise FeedFetchError(f"no response from the server within {FEED_READ_TIMEOUT}s") from e
    except (http.client.HTTPException, ConnectionError) as e:
        raise FeedFetchError(f"connection dropped by the server ({e.__class__.__name__})") from e

    body = _decompress(body, headers.pop("content-encoding", ""))
    # content-location tells feedparser the document's base URL, so
    # relative <link>s still resolve exactly as when feedparser fetched
    # the URL itself.
    headers["content-location"] = final_url
    feed = feedparser.parse(body, response_headers=headers)
    feed["href"], feed["status"] = final_url, status

    # feedparser tolerates a lot (bozo feeds with a stray bad character
    # still parse fine), so only reject what yields nothing usable: no
    # entries AND no recognised feed format. A real feed that's simply
    # empty right now still has a version ("rss20", "atom10", ...).
    if not feed.entries and not feed.get("version"):
        if "html" in headers.get("content-type", ""):
            raise FeedFetchError("URL returned a web page, not an RSS/Atom feed")
        raise FeedFetchError("response is not a valid RSS/Atom feed")
    return feed
