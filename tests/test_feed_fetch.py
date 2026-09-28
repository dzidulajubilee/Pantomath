"""
Feed retrieval failure handling (pantomath/feeds/rss.py) — against a real
local HTTP server, not mocks, same approach as the webhook tests.

Guards two shipped bugs:
  - a 404 / DNS failure / HTML page was recorded as last_status 'ok'
    (feedparser never raises, it just returns zero entries), so a dead
    feed looked identical to a quiet one;
  - feed fetches had no timeout, and the scheduler polls sources one
    after another, so one unresponsive server stalled polling of every
    source.
"""
import asyncio
import gzip
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pantomath.connectors.rss import RSSConnector
from pantomath.database.sqlite import get_db
from pantomath.feeds import rss as feed_rss
from pantomath.feeds.rss import FeedFetchError, fetch_raw
from pantomath.feeds.scheduler import Scheduler

RSS = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Test feed</title><link>http://example.test/</link>
<item><title>First advisory</title><link>/advisories/1</link><guid>adv-1</guid></item>
<item><title>Second advisory</title><link>http://example.test/advisories/2</link><guid>adv-2</guid></item>
</channel></rss>"""

EMPTY_RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Quiet feed</title></channel></rss>"""


class _FeedHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep pytest output clean
        pass

    def _send(self, code, body, content_type="application/rss+xml", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/feed.xml":
            self._send(200, RSS)
        elif self.path == "/empty.xml":
            self._send(200, EMPTY_RSS)
        elif self.path == "/gzip.xml":
            self._send(200, gzip.compress(RSS), extra={"Content-Encoding": "gzip"})
        elif self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/feed.xml")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/missing.xml":
            self._send(404, b"not here", content_type="text/plain")
        elif self.path == "/homepage":
            self._send(200, b"<!doctype html><html><body><h1>Welcome</h1></body></html>", content_type="text/html")
        elif self.path == "/big.xml":
            self._send(200, RSS + b"<!--" + b"x" * 5000 + b"-->")
        elif self.path == "/hang":
            time.sleep(3)  # longer than the (patched) read timeout
            try:
                self._send(200, RSS)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client correctly gave up long ago
        elif self.path == "/drip":
            # Headers promptly, then one byte at a time: every single read
            # succeeds well within the per-read timeout, so only the
            # overall deadline can stop this.
            self.send_response(200)
            self.send_header("Content-Type", "application/rss+xml")
            self.send_header("Content-Length", str(len(RSS)))
            self.end_headers()
            try:
                for i in range(len(RSS)):
                    self.wfile.write(RSS[i:i + 1])
                    self.wfile.flush()
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self._send(404, b"", content_type="text/plain")


@pytest.fixture(scope="module")
def feed_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FeedHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def short_limits(monkeypatch):
    monkeypatch.setattr(feed_rss, "FEED_READ_TIMEOUT", 0.5)
    monkeypatch.setattr(feed_rss, "FEED_TOTAL_DEADLINE", 1.0)


# ------------------------------------------------------------ happy paths


def test_valid_feed_parses_and_resolves_relative_links(feed_server):
    feed = fetch_raw(f"{feed_server}/feed.xml")
    assert [e.title for e in feed.entries] == ["First advisory", "Second advisory"]
    # Relative links must still resolve against the feed URL, exactly as
    # when feedparser fetched the URL itself.
    assert feed.entries[0].link == f"{feed_server}/advisories/1"
    assert feed.status == 200


def test_empty_but_valid_feed_is_not_an_error(feed_server):
    feed = fetch_raw(f"{feed_server}/empty.xml")
    assert feed.entries == []  # quiet, not broken


def test_gzip_encoded_feed_is_decompressed(feed_server):
    assert len(fetch_raw(f"{feed_server}/gzip.xml").entries) == 2


def test_redirect_is_followed(feed_server):
    feed = fetch_raw(f"{feed_server}/redirect")
    assert len(feed.entries) == 2
    assert feed.href.endswith("/feed.xml")


# ------------------------------------------------------ failures now raise


def test_http_404_raises_with_status(feed_server):
    with pytest.raises(FeedFetchError, match="HTTP 404"):
        fetch_raw(f"{feed_server}/missing.xml")


def test_html_page_is_reported_as_not_a_feed(feed_server):
    with pytest.raises(FeedFetchError, match="web page, not an RSS/Atom feed"):
        fetch_raw(f"{feed_server}/homepage")


def test_unresolvable_host_raises():
    with pytest.raises(FeedFetchError):
        fetch_raw("http://no-such-host.invalid/feed.xml")


def test_connection_refused_raises():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listening on this port now
    with pytest.raises(FeedFetchError, match="refused"):
        fetch_raw(f"http://127.0.0.1:{port}/feed.xml")


@pytest.mark.parametrize("url", ["/etc/passwd", "file:///etc/passwd", "ftp://example.com/feed.xml", "<rss/>"])
def test_non_http_urls_are_refused(url):
    with pytest.raises(FeedFetchError, match="only http"):
        fetch_raw(url)


def test_oversized_feed_is_refused(feed_server, monkeypatch):
    monkeypatch.setattr(feed_rss, "MAX_FEED_BYTES", 2000)
    with pytest.raises(FeedFetchError, match="larger than"):
        fetch_raw(f"{feed_server}/big.xml")


# --------------------------------------------------------------- timeouts


def test_unresponsive_server_times_out(feed_server, short_limits):
    start = time.monotonic()
    with pytest.raises(FeedFetchError, match="no response"):
        fetch_raw(f"{feed_server}/hang")
    assert time.monotonic() - start < 2.5


def test_slow_drip_server_hits_overall_deadline(feed_server, short_limits):
    start = time.monotonic()
    with pytest.raises(FeedFetchError, match="did not finish"):
        fetch_raw(f"{feed_server}/drip")
    assert time.monotonic() - start < 2.5


async def test_connector_hard_limit_backstops_a_stuck_fetch(monkeypatch):
    """Covers what fetch_raw can't bound itself, e.g. a hung DNS lookup."""
    import pantomath.connectors.rss as connector_module

    monkeypatch.setattr(connector_module, "fetch_raw", lambda url: time.sleep(3))
    monkeypatch.setattr(connector_module, "FETCH_HARD_LIMIT", 0.3)
    connector = RSSConnector({"id": "x", "url": "http://example.test/feed.xml"})
    start = time.monotonic()
    with pytest.raises(FeedFetchError, match="no response within"):
        await connector.fetch()
    assert time.monotonic() - start < 1.5


# ------------------------------------------------- end to end: the scheduler


async def _add_source(db, sid, url):
    await db.execute(
        "INSERT INTO sources (id, name, url, color, category) VALUES (?,?,?,?,?)",
        (sid, sid, url, "#5eead4", "news"),
    )
    await db.commit()


async def _status(db, sid):
    cur = await db.execute("SELECT last_status FROM sources WHERE id = ?", (sid,))
    return (await cur.fetchone())["last_status"]


async def test_scheduler_records_real_error_status_for_broken_feeds(fresh_db, feed_server):
    async def broadcast(_):
        pass

    db = await get_db()
    await _add_source(db, "good", f"{feed_server}/feed.xml")
    await _add_source(db, "gone", f"{feed_server}/missing.xml")
    await _add_source(db, "html", f"{feed_server}/homepage")
    await db.close()

    await Scheduler(broadcast).poll_all()

    db = await get_db()
    assert await _status(db, "good") == "ok"
    assert (await _status(db, "gone")).startswith("error: HTTP 404")
    assert (await _status(db, "html")).startswith("error: URL returned a web page")
    await db.close()


async def test_one_hanging_source_does_not_stall_the_others(fresh_db, feed_server, short_limits):
    async def broadcast(_):
        pass

    db = await get_db()
    await _add_source(db, "a-hangs", f"{feed_server}/hang")  # inserted first, so normally polled first
    await _add_source(db, "b-good", f"{feed_server}/feed.xml")
    await db.close()

    await asyncio.wait_for(Scheduler(broadcast).poll_all(), timeout=5)

    db = await get_db()
    assert (await _status(db, "a-hangs")).startswith("error: no response")
    assert await _status(db, "b-good") == "ok"
    cur = await db.execute("SELECT COUNT(*) AS c FROM items WHERE source_id = 'b-good'")
    assert (await cur.fetchone())["c"] == 2
    await db.close()
