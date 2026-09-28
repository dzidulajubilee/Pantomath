"""
GET /api/overview — the dashboard's single data source (0.5.0).

The behaviors that matter most are the ones the old dashboard got wrong:
counts must follow each item's *published* date (a newly added source's
two-week backlog is not "today"), a failing source must show as failing,
and — because this endpoint is public like the rest of the dashboard —
feed URLs must never appear in it (they can carry API keys).
"""
import time

import pytest
from fastapi.testclient import TestClient

from pantomath.app import app
from pantomath.database.sqlite import get_db

client = TestClient(app)
HOUR = 3600
SECRET_URL = "https://feeds.example.test/rss?api_key=SUPERSECRET123"


@pytest.fixture(autouse=True)
async def seeded(fresh_db):
    now = time.time()
    db = await get_db()
    sources = [
        # id, name, enabled, last_status, last_fetched, url
        ("s-ok", "Healthy feed", 1, "ok", now - 120, SECRET_URL),
        ("s-bad", "Broken feed", 1, "error: HTTP 404 Not Found", now - 60, "https://x.example.test/a"),
        ("s-new", "New feed", 1, "pending", 0, "https://x.example.test/b"),
        ("s-off", "Paused feed", 0, "ok", now - 999, "https://x.example.test/c"),
    ]
    for sid, name, enabled, status, fetched, url in sources:
        await db.execute(
            "INSERT INTO sources (id, name, url, category, enabled, last_status, last_fetched) VALUES (?,?,?,?,?,?,?)",
            (sid, name, url, "news", enabled, status, fetched),
        )
    items = [
        # id, title, severity, published, fetched_at, cves, ips
        ("i-fresh-high", "Fresh high", "high", now - 2 * HOUR, now - 1 * HOUR, "CVE-2026-1111", "198.51.100.1"),
        ("i-backlog-high", "Backlog high", "high", now - 10 * 86400, now - 1 * HOUR, "CVE-2026-2222", ""),
        ("i-future-high", "Future-dated high", "high", now + 5 * 86400, now - 3 * HOUR, "", ""),
        ("i-old-low", "Old low", "low", now - 30 * HOUR, now - 30 * HOUR, "", ""),
        ("i-med", "Recent medium", "medium", now - 5 * HOUR, now - 5 * HOUR, "", "203.0.113.9"),
    ]
    for iid, title, sev, published, fetched, cves, ips in items:
        await db.execute(
            """INSERT INTO items (id, source_id, guid, title, link, summary, published, fetched_at, severity, cves, ips)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (iid, "s-ok", iid, title, "https://example.test/" + iid, "", published, fetched, sev, cves, ips),
        )
    await db.commit()
    await db.close()
    yield


def _overview(**params):
    resp = client.get("/api/overview", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_is_public_like_the_rest_of_the_dashboard():
    assert TestClient(app).get("/api/overview").status_code == 200  # no settings token


def test_never_exposes_feed_urls():
    body = client.get("/api/overview").text
    assert "SUPERSECRET123" not in body
    assert "example.test/a" not in body
    assert '"url"' not in body


def test_high_count_uses_published_date_not_fetch_time():
    ov = _overview(hours=24)
    titles = [i["title"] for i in ov["attention"]]
    # fetched an hour ago but published ten days ago: backlog, not "today"
    assert "Backlog high" not in titles
    assert "Fresh high" in titles
    # a publish date in the future isn't trusted; fetch time is used instead
    assert "Future-dated high" in titles
    assert ov["high_in_window"] == 2


def test_attention_is_newest_published_first_and_carries_indicators():
    ov = _overview(hours=24)
    assert [i["title"] for i in ov["attention"]] == ["Fresh high", "Future-dated high"]
    assert ov["attention"][0]["cves"] == ["CVE-2026-1111"]
    assert ov["attention"][0]["source_name"] == "Healthy feed"


def test_wider_window_includes_older_items():
    assert _overview(hours=24 * 30)["high_in_window"] == 3


def test_hours_is_clamped():
    assert _overview(hours=0)["hours"] == 1
    assert _overview(hours=999999)["hours"] == 24 * 90


def test_new_since_counts_by_when_pantomath_stored_items():
    now = time.time()
    assert _overview(since=now - 2 * HOUR)["new_since"] == 2  # both fetched an hour ago
    assert _overview(since=now + 999)["new_since"] == 4       # future `since` falls back to 24 h


def test_source_health_states_order_and_counts():
    src = _overview()["sources"]
    assert (src["total"], src["healthy"], src["failing"], src["pending"], src["paused"]) == (4, 1, 1, 1, 1)
    assert [s["state"] for s in src["list"]] == ["failing", "pending", "healthy", "paused"]
    assert src["list"][0]["name"] == "Broken feed"
    assert src["list"][0]["error"] == "HTTP 404 Not Found"


def test_by_day_has_seven_days_ending_today_with_severity_split():
    days = _overview()["by_day"]
    assert len(days) == 7
    assert days[-1]["date"] == time.strftime("%Y-%m-%d")
    assert sum(d["high"] + d["medium"] + d["low"] for d in days) == 4  # the backlog item is older than 7 days


def test_indicators_week_counts_distinct_values_by_published_date():
    ind = _overview()["indicators_week"]
    assert ind["cve"] == 1   # CVE-2026-2222 belongs to the 10-day-old backlog item
    assert ind["ip"] == 2


def test_existing_stats_endpoint_is_unchanged():
    stats = client.get("/api/stats").json()
    for key in ("total_articles", "new_today", "critical_alerts", "sources_active", "articles_by_day"):
        assert key in stats
