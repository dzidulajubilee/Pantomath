"""
0.6.0 API additions behind the redesigned Sources, Indicators and
Analytics pages: source health history recorded by the scheduler, the
feed test used before saving a source, per-source item counts, the
opt-in detail view of /api/iocs, and /api/analytics.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from pantomath.app import app
from pantomath.database.sqlite import get_db
from pantomath.feeds.scheduler import Scheduler

client = TestClient(app)
HOUR = 3600
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title>
<item><title>Flaw CVE-2099-1234 exploited</title><link>http://example.test/1</link><guid>1</guid>
<pubDate>Mon, 01 Jan 2029 10:00:00 GMT</pubDate></item>
<item><title>Quiet news</title><link>http://example.test/2</link><guid>2</guid></item></channel></rss>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body, code = (RSS, 200) if self.path == "/feed.xml" else (b"gone", 404)
        self.send_response(code)
        self.send_header("Content-Type", "application/rss+xml" if code == 200 else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def feed_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(autouse=True)
async def seeded(fresh_db):
    resp = client.post("/api/settings/auth/setup", json={"password": "test-password-123"})
    client.headers["X-Settings-Token"] = resp.json()["token"]
    now = time.time()
    db = await get_db()
    for sid, name, cat in (("s1", "Advisories", "vulnerability"), ("s2", "Research", "malware")):
        await db.execute("INSERT INTO sources (id, name, url, category) VALUES (?,?,?,?)", (sid, name, "http://x.test/" + sid, cat))
    rows = [
        # id, source, severity, published, fetched, cves, ips, vendors
        ("a", "s1", "high", now - 2 * HOUR, now - HOUR, "CVE-2099-1,CVE-2099-2", "192.0.2.1", "Cisco"),
        ("b", "s2", "medium", now - 3 * HOUR, now - HOUR, "CVE-2099-1", "", "Cisco"),
        ("c", "s1", "low", now - 40 * 86400, now - HOUR, "", "", ""),  # backlog: outside a 30-day window
    ]
    for iid, sid, sev, pub, fetched, cves, ips, vendors in rows:
        await db.execute(
            """INSERT INTO items (id, source_id, guid, title, link, summary, published, fetched_at, severity, cves, ips, vendors)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (iid, sid, iid, "t-" + iid, "http://x.test/i/" + iid, "", pub, fetched, sev, cves, ips, vendors),
        )
    await db.commit()
    await db.close()
    yield


# ------------------------------------------------------------- /api/iocs detail

def test_iocs_default_shape_is_unchanged():
    assert client.get("/api/iocs?type=cve").json() == [{"name": "CVE-2099-1", "count": 2}, {"name": "CVE-2099-2", "count": 1}]


def test_iocs_detail_adds_sources_severity_and_seen_times():
    top = client.get("/api/iocs?type=cve&detail=1").json()[0]
    assert (top["name"], top["count"], top["sources"], top["severity"]) == ("CVE-2099-1", 2, 2, "high")
    assert top["first_seen"] <= top["last_seen"]


def test_iocs_detail_filter():
    assert [r["name"] for r in client.get("/api/iocs?type=cve&detail=1&q=2099-2").json()] == ["CVE-2099-2"]


# ------------------------------------------------------------------ /api/sources

def test_sources_list_includes_item_counts():
    by_id = {s["id"]: s for s in client.get("/api/sources").json()}
    assert (by_id["s1"]["items_total"], by_id["s1"]["items_today"]) == (2, 2) or by_id["s1"]["items_total"] == 2
    assert by_id["s2"]["items_total"] == 1


def test_feed_test_reports_a_valid_feed(feed_server):
    result = client.post("/api/sources/test", json={"url": f"{feed_server}/feed.xml"}).json()
    assert result["ok"] is True
    assert (result["format"], result["items"], result["items_with_cve"]) == ("RSS 2.0", 2, 1)
    assert result["newest_published"] > 0


def test_feed_test_reports_why_a_feed_fails(feed_server):
    assert client.post("/api/sources/test", json={"url": f"{feed_server}/missing"}).json() == {
        "ok": False, "error": "HTTP 404 Not Found"}
    assert "only http" in client.post("/api/sources/test", json={"url": "file:///etc/passwd"}).json()["error"]


def test_feed_test_requires_the_settings_password(feed_server):
    assert TestClient(app).post("/api/sources/test", json={"url": f"{feed_server}/feed.xml"}).status_code == 401


async def test_scheduler_records_health_history(feed_server):
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('ok', 'OK', ?, 'news')", (f"{feed_server}/feed.xml",))
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('bad', 'Bad', ?, 'news')", (f"{feed_server}/missing",))
    await db.commit()

    async def broadcast(_):
        pass

    scheduler = Scheduler(broadcast)
    for sid in ("ok", "bad"):
        cur = await db.execute("SELECT * FROM sources WHERE id = ?", (sid,))
        await scheduler.poll_source(db, dict(await cur.fetchone()))
    cur = await db.execute("SELECT failing_since FROM sources WHERE id = 'bad'")
    first_failure = (await cur.fetchone())[0]
    cur = await db.execute("SELECT * FROM sources WHERE id = 'bad'")
    await scheduler.poll_source(db, dict(await cur.fetchone()))  # fails again: failing_since must not move

    cur = await db.execute("SELECT id, last_success, failing_since, last_duration_ms FROM sources WHERE id IN ('ok','bad')")
    rows = {r["id"]: dict(r) for r in await cur.fetchall()}
    await db.close()
    assert rows["ok"]["last_success"] > 0 and rows["ok"]["failing_since"] == 0
    assert rows["bad"]["last_success"] == 0
    assert rows["bad"]["failing_since"] == first_failure > 0
    assert rows["ok"]["last_duration_ms"] >= 0


# ---------------------------------------------------------------- /api/analytics

def test_analytics_counts_by_published_date_and_compares_periods():
    a = client.get("/api/analytics?days=30").json()
    assert a["totals"] == {"high": 1, "medium": 1, "low": 0, "items": 2}  # the 40-day-old backlog item is excluded
    assert a["previous"]["items"] == 1                                    # ...and lands in the previous 30 days
    assert len(a["by_day"]) == 30 and a["by_day"][-1]["date"] == time.strftime("%Y-%m-%d")
    assert a["active_sources"] == 2
    assert a["indicators"] == {"cve": 2, "ip": 1, "hash": 0, "email": 0}
    assert a["top_vendors"] == [{"name": "Cisco", "count": 2}]
    assert {c["name"] for c in a["by_category"]} == {"vulnerability", "malware"}


def test_analytics_heatmap_is_weekday_by_hour():
    heat = client.get("/api/analytics").json()["heatmap"]
    assert len(heat) == 7 and all(len(row) == 24 for row in heat)
    assert sum(map(sum, heat)) == 2


def test_analytics_days_is_clamped():
    assert client.get("/api/analytics?days=0").json()["days"] == 1
    assert client.get("/api/analytics?days=9999").json()["days"] == 365
