"""
IOC feeds added by URL, the way an RSS source is: any list published as
plain text (one value per line) or CSV, from a public site, a vendor or an
internal mirror. No reader has to be written for a list like that; the
built-in readers for well-known feeds are in readers.py.

Each download:
  - asks the server whether the list changed (ETag / Last-Modified) and
    skips it if not, so a large unchanged list costs almost nothing;
  - is bounded like the KEV download: a timeout per read, a deadline for
    the whole download and a size limit (raised per feed for big lists);
  - is read off the event loop, and stored in batches (store.ingest).

A feed's key (for lists that need one, such as abuse.ch's Auth-Key) is
sent as the header the feed names. It is never returned by the API and
never written to a log or to last_status.
"""
import asyncio
import re
import socket
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass

from pantomath.ioc.parsing import IocFeedError, ParseResult, decode, parse_list
from pantomath.ioc.readers import READERS
from pantomath.ioc.store import Source, end_snapshot, ingest

READ_TIMEOUT = 30             # seconds per network read, as for the KEV catalog
DOWNLOAD_DEADLINE = 120       # seconds for the whole download
HARD_LIMIT = DOWNLOAD_DEADLINE + READ_TIMEOUT + 5   # backstop around the executor call (covers DNS)
DEFAULT_MAX_MB = 30
MAX_MB_LIMIT = 500
MIN_INTERVAL = 900            # at least 15 minutes between downloads of one feed
USER_AGENT = "Pantomath (+https://github.com/dzidulajubilee/Pantomath)"
HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
FORMATS = ("text", "csv", *READERS)


@dataclass
class Download:
    body: bytes = b""
    not_modified: bool = False
    etag: str = ""
    last_modified: str = ""


# ------------------------------------------------------------------ download

def check_key_header(name: str, value: str) -> None:
    if name and not HEADER_NAME_RE.fullmatch(name):
        raise IocFeedError("the key header name can only use letters, digits and '-'")
    if any(c in (value or "") for c in "\r\n"):
        raise IocFeedError("the key can't contain line breaks")


def fetch_list_sync(url: str, key_header: str = "", key_value: str = "", etag: str = "",
                    last_modified: str = "", max_mb: int = DEFAULT_MAX_MB, accept: str = "") -> Download:
    """Blocking download of a list. Run via loop.run_in_executor()."""
    if not url.lower().startswith(("http://", "https://")):
        raise IocFeedError("only http:// and https:// URLs are supported")
    check_key_header(key_header, key_value)
    max_bytes = max(1, min(int(max_mb or DEFAULT_MAX_MB), MAX_MB_LIMIT)) * 1024 * 1024
    headers = {"User-Agent": USER_AGENT, "Accept": accept or "text/plain, text/csv, application/json, */*",
               "Accept-Encoding": "gzip"}
    if key_header and key_value:
        headers[key_header] = key_value
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=READ_TIMEOUT) as response:
            body = _read_capped(response, max_bytes)
            encoding = (response.headers.get("Content-Encoding") or "").strip().lower()
            new_etag = response.headers.get("ETag") or ""
            new_modified = response.headers.get("Last-Modified") or ""
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return Download(not_modified=True, etag=etag, last_modified=last_modified)
        if e.code in (401, 403):
            raise IocFeedError(f"HTTP {e.code} {e.reason}: the server refused the request (is a key needed, or wrong?)") from None
        raise IocFeedError(f"HTTP {e.code} {e.reason}".strip()) from None
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.gaierror):
            raise IocFeedError("could not resolve the host name (no internet access?)") from None
        raise IocFeedError(f"could not connect: {reason}") from None
    except TimeoutError:
        raise IocFeedError(f"no response within {READ_TIMEOUT}s") from None
    except ConnectionError as e:
        raise IocFeedError(f"connection dropped by the server ({e.__class__.__name__})") from None
    if encoding in ("gzip", "x-gzip"):
        try:
            body = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, max_bytes + 1)
        except zlib.error:
            raise IocFeedError("the response is not valid gzip data") from None
        if len(body) > max_bytes:
            raise IocFeedError(f"the list is larger than {max_bytes // (1024 * 1024)} MB (raise the feed's size limit)")
    return Download(body=body, etag=new_etag, last_modified=new_modified)


def _read_capped(response, max_bytes: int) -> bytes:
    deadline = time.monotonic() + DOWNLOAD_DEADLINE
    chunks, total = [], 0
    while True:
        if time.monotonic() > deadline:
            raise IocFeedError(f"the download did not finish within {DOWNLOAD_DEADLINE}s")
        chunk = response.read1(256 * 1024)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise IocFeedError(f"the list is larger than {max_bytes // (1024 * 1024)} MB (raise the feed's size limit)")
        chunks.append(chunk)


# ------------------------------------------------------------- running feeds

async def download_and_parse(feed: dict, conditional: bool = True) -> tuple[Download, ParseResult | None, float]:
    """(download, parsed list or None when unchanged, seconds taken). Raises IocFeedError."""
    loop = asyncio.get_running_loop()
    started = time.monotonic()
    reader = READERS.get(feed.get("format") or "")
    try:
        download = await asyncio.wait_for(loop.run_in_executor(
            None, fetch_list_sync, feed["url"], feed.get("key_header") or "", feed.get("key_value") or "",
            (feed.get("etag") or "") if conditional else "", (feed.get("last_modified") or "") if conditional else "",
            feed.get("max_mb") or DEFAULT_MAX_MB, reader.accept if reader else "",
        ), timeout=HARD_LIMIT)
    except asyncio.TimeoutError:
        raise IocFeedError(f"no complete response within {HARD_LIMIT}s") from None
    if download.not_modified:
        return download, None, time.monotonic() - started

    def read():
        text = decode(download.body)
        if reader:
            return reader.parse(text)
        return parse_list(text, feed.get("format") or "text", feed.get("default_type") or "",
                          feed.get("value_column") or "", feed.get("date_column") or "", feed.get("malware_column") or "")
    parsed = await loop.run_in_executor(None, read)
    return download, parsed, time.monotonic() - started


def reader_for_url(url: str):
    """The built-in reader made for this URL, if any (ignoring the query string)."""
    base = (url or "").split("?", 1)[0].rstrip("/").lower()
    return next((r for r in READERS.values() if r.url.split("?", 1)[0].rstrip("/").lower() == base), None)


def nothing_readable(feed: dict, parsed: ParseResult) -> str:
    """Why a download gave no values, worded for the feed's status line."""
    message = f"none of the {parsed.rejected:,} values could be read"
    if parsed.rejected_samples:
        value, reason = parsed.rejected_samples[0]
        message += f' (for example "{value[:40]}": {reason})'
    reader = reader_for_url(feed.get("url", ""))
    if reader and feed.get("format") != reader.name:
        return message + f". This is {reader.label}'s address: set Format to the {reader.label} reader"
    return message + ". Check the format, the CSV column and the indicator type"


def source_for(feed: dict) -> Source:
    return Source(id=feed["id"], name=feed["name"], confidence=int(feed.get("confidence") or 0),
                  lifetime_days=int(feed.get("lifetime_days") or 0), threat_type=feed.get("threat_type") or "",
                  reference=feed["url"])


async def run_feed(db, feed: dict, now: float | None = None) -> dict:
    """
    One scheduled download of one feed, start to finish. Never raises: the
    outcome is written to the feed's row the way Sources records RSS health.
    """
    now = now or time.time()
    started = time.monotonic()
    try:
        download, parsed, _ = await download_and_parse(feed)
        if parsed is None:
            await db.execute(
                """UPDATE ioc_feeds SET last_fetched = ?, last_success = ?, last_status = 'ok', last_duration_ms = ?,
                                         last_count = 0, last_new = 0, last_dropped = 0 WHERE id = ?""",
                (now, now, int((time.monotonic() - started) * 1000), feed["id"]),
            )
            await db.commit()
            return {"ok": True, "unchanged": True}
        if not parsed.arrivals and parsed.rejected:
            # Every line refused is a wrong format or type, not a quiet list.
            raise IocFeedError(nothing_readable(feed, parsed))
        if not parsed.arrivals and (feed.get("last_count") or feed.get("last_success")):
            # An empty download from a list that had values is far more
            # likely a broken mirror than a clean bill of health; dropping
            # everything (snapshot feeds) on its word would be worse.
            raise IocFeedError("the list came back empty, so nothing was changed")
        result = await ingest(db, source_for(feed), parsed.arrivals, now)
        dropped = await end_snapshot(db, feed["id"], result.seen_ids, now) if feed.get("snapshot") else 0
        await db.execute(
            """UPDATE ioc_feeds SET last_fetched = ?, last_success = ?, last_status = 'ok', last_duration_ms = ?,
                                     last_count = ?, last_new = ?, last_dropped = ?, last_rejected = ?,
                                     etag = ?, last_modified = ? WHERE id = ?""",
            (now, now, int((time.monotonic() - started) * 1000), len(parsed.arrivals), result.new, dropped,
             parsed.rejected, download.etag, download.last_modified, feed["id"]),
        )
        await db.commit()
        return {"ok": True, "values": len(parsed.arrivals), "rejected": parsed.rejected, "dropped": dropped, **result.as_dict()}
    except Exception as e:
        message = str(e)[:200] if isinstance(e, IocFeedError) else (str(e)[:160] or e.__class__.__name__)
        await db.execute(
            "UPDATE ioc_feeds SET last_fetched = ?, last_status = ?, last_duration_ms = ? WHERE id = ?",
            (now, f"error: {message}", int((time.monotonic() - started) * 1000), feed["id"]),
        )
        await db.commit()
        return {"ok": False, "error": message}
