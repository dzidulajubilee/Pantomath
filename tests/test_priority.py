"""
0.8.0 priority: Critical / High / Medium / Low from the article's wording,
CISA KEV (Exploited) and Our stack (Affects us) — see intelligence/priority.py.
"""
import time

import pytest
from fastapi.testclient import TestClient

from pantomath.alerts.matcher import matches_webhook
from pantomath.app import app
from pantomath.database.sqlite import get_db, init_db
from pantomath.intelligence.priority import compute_priority, explain_priority
from pantomath.intelligence.scoring import score_severity_detail

client = TestClient(app)


@pytest.mark.parametrize(("content", "ours", "exploited", "expected"), [
    # the table agreed for 0.8.0
    ("low", False, True, "high"), ("low", True, True, "critical"),
    ("high", False, False, "high"), ("high", True, False, "critical"),
    ("medium", False, False, "medium"), ("medium", True, False, "high"),
    ("low", False, False, "low"), ("low", True, False, "medium"),
    # and the combinations around it
    ("medium", False, True, "high"), ("high", True, True, "critical"), ("high", False, True, "high"),
])
def test_priority_table(content, ours, exploited, expected):
    assert compute_priority(content, ours, exploited) == expected


def test_bare_critical_no_longer_rates_high():
    assert score_severity_detail("Critical infrastructure operators meet in Accra", "") == ("low", "")
    assert score_severity_detail("App gets a critical update", "") == ("low", "")
    assert score_severity_detail("Critical flaw in gateway", "") == ("high", "critical flaw")
    assert score_severity_detail("Bug under active exploitation", "") == ("high", "under active exploitation")
    assert score_severity_detail("New CVE-2099-1 advisory", "")[0] == "medium"


def test_reasons_are_plain_and_ordered():
    assert explain_priority("high", "zero-day", ["FortiGate"], ["CVE-2099-1"]) == [
        "Exploited: CVE-2099-1 on CISA's list", "Affects us: FortiGate", "Wording: mentions \u201czero-day\u201d"]
    assert explain_priority("low", "", [], []) == ["No warning words found"]
    assert explain_priority("medium", "", [], []) == ["Wording rated medium"]


def test_webhook_thresholds_include_critical():
    assert matches_webhook({"min_severity": "high"}, {"severity": "critical"})
    assert not matches_webhook({"min_severity": "critical"}, {"severity": "high"})


@pytest.fixture(autouse=True)
async def seeded(fresh_db):
    resp = client.post("/api/settings/auth/setup", json={"password": "test-password-123"})
    client.headers["X-Settings-Token"] = resp.json()["token"]
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'A', 'http://x.test/s1', 'news')")
    now = time.time()
    await db.execute(
        """INSERT INTO items (id, source_id, guid, title, link, summary, published, fetched_at,
                              severity, content_severity, content_keyword, cves)
           VALUES ('a', 's1', 'a', 'Vulnerability in FortiGate VPN', 'http://x.test/a', '', ?, ?, 'medium', 'medium', 'vulnerability', 'CVE-2099-7')""",
        (now, now),
    )
    await db.commit()
    await db.close()
    yield


def _item():
    return next(i for i in client.get("/api/items").json() if i["id"] == "a")


async def test_priority_follows_our_stack_and_the_catalog():
    assert _item()["severity"] == "medium"
    wid = client.post("/api/watchlist", json={"name": "FortiGate"}).json()["id"]
    assert _item()["severity"] == "high"                      # medium + ours
    db = await get_db()
    await db.execute("INSERT INTO kev (cve) VALUES ('CVE-2099-7')")
    await db.commit()
    from pantomath.intelligence.kev import recompute_item_kev
    await recompute_item_kev(db)
    await db.commit()
    await db.close()
    item = _item()
    assert item["severity"] == "critical"                     # exploited + ours
    assert item["priority_reasons"][:2] == ["Exploited: CVE-2099-7 on CISA's list", "Affects us: FortiGate"]
    assert client.get("/api/items/count", params={"severity": "critical"}).json() == {"total": 1}
    client.delete(f"/api/watchlist/{wid}")
    assert _item()["severity"] == "high"                      # exploited, not ours


async def test_items_stored_before_0_8_get_their_priority_on_upgrade():
    db = await get_db()
    await db.execute("UPDATE items SET content_severity = '', severity = 'high', watch_hits = 'FortiGate' WHERE id = 'a'")
    await db.commit()
    await db.close()
    await init_db()
    db = await get_db()
    cur = await db.execute("SELECT content_severity, severity FROM items WHERE id = 'a'")
    row = tuple(await cur.fetchone())
    await db.close()
    assert row == ("high", "critical")
