"""
Integration-level tests against the real FastAPI app via TestClient.
Deliberately covers the behaviors that have actually broken before in
this project's history — fresh installs must start with zero sources,
unsupported connector types must be rejected, dedup must hold — rather
than re-testing every endpoint exhaustively.
"""
import pytest
from fastapi.testclient import TestClient

from pantomath.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


def test_fresh_install_has_zero_sources():
    resp = client.get("/api/sources")
    assert resp.status_code == 200
    assert resp.json() == []


def test_add_source_defaults_to_rss():
    resp = client.post("/api/sources", json={"name": "Test", "url": "http://example.com/feed.xml"})
    assert resp.status_code == 200
    sources = client.get("/api/sources").json()
    assert sources[0]["connector_type"] == "rss"


def test_unsupported_connector_type_rejected():
    resp = client.post("/api/sources", json={
        "name": "Bad", "url": "http://example.com/bad", "connector_type": "taxii",
    })
    assert resp.status_code == 400


def test_duplicate_source_url_rejected():
    client.post("/api/sources", json={"name": "A", "url": "http://example.com/dup.xml"})
    resp = client.post("/api/sources", json={"name": "B", "url": "http://example.com/dup.xml"})
    assert resp.status_code == 400


def test_deleting_source_removes_it():
    add_resp = client.post("/api/sources", json={"name": "ToDelete", "url": "http://example.com/del.xml"})
    source_id = add_resp.json()["id"]
    client.delete(f"/api/sources/{source_id}")
    sources = client.get("/api/sources").json()
    assert all(s["id"] != source_id for s in sources)


def test_edit_source_updates_only_provided_fields():
    """
    Regression test for a real reported gap: editing a source used to
    require deleting and re-adding it. name/url/category/interval should
    all be independently editable in place now.
    """
    add_resp = client.post("/api/sources", json={
        "name": "Original Name", "url": "http://example.com/original.xml",
        "category": "news", "interval_seconds": 300,
    })
    source_id = add_resp.json()["id"]

    resp = client.patch(f"/api/sources/{source_id}", json={"name": "Renamed", "interval_seconds": 600})
    assert resp.status_code == 200

    sources = client.get("/api/sources").json()
    source = next(s for s in sources if s["id"] == source_id)
    assert source["name"] == "Renamed"
    assert source["interval_seconds"] == 600
    assert source["url"] == "http://example.com/original.xml"  # untouched
    assert source["category"] == "news"  # untouched


def test_edit_source_can_change_url_without_delete_and_readd():
    add_resp = client.post("/api/sources", json={"name": "T", "url": "http://example.com/old.xml"})
    source_id = add_resp.json()["id"]
    resp = client.patch(f"/api/sources/{source_id}", json={"url": "http://example.com/new.xml"})
    assert resp.status_code == 200
    source = client.get("/api/sources").json()[0]
    assert source["url"] == "http://example.com/new.xml"
    assert source["id"] == source_id  # same source, not a new one


def test_edit_source_rejects_unsupported_connector_type():
    add_resp = client.post("/api/sources", json={"name": "T", "url": "http://example.com/x.xml"})
    source_id = add_resp.json()["id"]
    resp = client.patch(f"/api/sources/{source_id}", json={"connector_type": "taxii"})
    assert resp.status_code == 400


def test_edit_nonexistent_source_returns_404():
    resp = client.patch("/api/sources/does-not-exist", json={"name": "X"})
    assert resp.status_code == 404


def test_toggle_source_enabled_still_works_via_json_body():
    add_resp = client.post("/api/sources", json={"name": "T", "url": "http://example.com/toggle.xml"})
    source_id = add_resp.json()["id"]
    resp = client.patch(f"/api/sources/{source_id}", json={"enabled": False})
    assert resp.status_code == 200
    source = client.get("/api/sources").json()[0]
    assert source["enabled"] == 0


def test_settings_default_retention_is_forever():
    resp = client.get("/api/settings")
    assert resp.json()["retention_days"] == 0


def test_settings_can_be_updated():
    client.post("/api/settings", json={"retention_days": 90})
    resp = client.get("/api/settings")
    assert resp.json()["retention_days"] == 90


def test_connectors_endpoint_reports_only_rss():
    resp = client.get("/api/connectors")
    types = [c["type"] for c in resp.json()]
    assert types == ["rss"]


def test_iocs_summary_empty_on_fresh_install():
    resp = client.get("/api/iocs/summary")
    assert resp.status_code == 200
    assert resp.json() == {"cve": 0, "ip": 0, "hash": 0, "email": 0}


def test_iocs_endpoint_rejects_unknown_type():
    resp = client.get("/api/iocs?type=bogus")
    assert resp.status_code == 400


def test_items_ioc_filter_rejects_unknown_type():
    resp = client.get("/api/items?ioc_type=bogus&ioc_value=x")
    assert resp.status_code == 400


async def test_has_cve_filter_finds_cve_bearing_items_regardless_of_source_category():
    """
    Regression test for a real reported bug: a source categorized as
    'news' (not 'vulnerability') that posts an article containing a CVE
    was invisible on the Vulnerabilities page, since that page only
    filtered by the source's manually-assigned category. has_cve=true
    finds it by content instead.
    """
    from pantomath.database.sqlite import get_db

    db = await get_db()
    await db.execute(
        "INSERT INTO sources (id, name, url, category) VALUES ('s1', 'News Source', 'http://x.com/feed', 'news')"
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves)
           VALUES ('i1', 's1', 'Cisco patches flaw', 'g1', 1000, 'CVE-2026-12345')"""
    )
    await db.commit()
    await db.close()

    # Old behavior: filtering by category=vulnerability finds nothing (the bug)
    resp = client.get("/api/items?category=vulnerability")
    assert resp.json() == []

    # Fixed behavior: has_cve=true finds it regardless of source category
    resp = client.get("/api/items?has_cve=true")
    results = resp.json()
    assert len(results) == 1
    assert results[0]["cves"] == ["CVE-2026-12345"]


async def test_has_actor_filter_finds_actor_bearing_items_regardless_of_source_category():
    """Same fix, applied to Malware: a detected threat actor is a content signal, not a source-category one."""
    from pantomath.database.sqlite import get_db

    db = await get_db()
    await db.execute(
        "INSERT INTO sources (id, name, url, category) VALUES ('s2', 'General News', 'http://y.com/feed', 'news')"
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, actors)
           VALUES ('i2', 's2', 'LockBit strikes again', 'g2', 1000, 'LockBit')"""
    )
    await db.commit()
    await db.close()

    resp = client.get("/api/items?category=malware")
    assert resp.json() == []
    resp = client.get("/api/items?has_actor=true")
    results = resp.json()
    assert len(results) == 1
    assert results[0]["actors"] == ["LockBit"]


async def test_reprocess_endpoint_backfills_legacy_item_via_api():
    from pantomath.database.sqlite import get_db

    db = await get_db()
    await db.execute(
        "INSERT INTO sources (id, name, url, category) VALUES ('s3', 'Legacy', 'http://z.com/feed', 'news')"
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, summary, guid, fetched_at, cves, vendors, actors)
           VALUES ('i3', 's3', 'Microsoft flaw exploited by LockBit', 'CVE-2026-77777 details', 'g3', 1000, '', '', '')"""
    )
    await db.commit()
    await db.close()

    resp = client.post("/api/reprocess", json={"deep_extraction": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["processed"] == 1

    items = client.get("/api/items").json()
    assert "CVE-2026-77777" in items[0]["cves"]
    assert "Microsoft" in items[0]["vendors"]
    assert "LockBit" in items[0]["actors"]


def test_poll_all_endpoint_reports_source_count():
    resp = client.post("/api/sources/poll-all")
    assert resp.status_code == 200
    assert resp.json()["sources_polled"] == 0  # no sources configured in this clean test db


async def test_items_count_matches_items_list_length_for_same_filters():
    from pantomath.database.sqlite import get_db

    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('sc1', 'S', 'http://c.com/f', 'news')")
    for i in range(5):
        await db.execute(
            "INSERT INTO items (id, source_id, title, guid, fetched_at, severity) VALUES (?,?,?,?,?,?)",
            (f"c{i}", "sc1", f"Item {i}", f"g{i}", 1000 + i, "high" if i % 2 == 0 else "low"),
        )
    await db.commit()
    await db.close()

    count_resp = client.get("/api/items/count")
    assert count_resp.json()["total"] == 5

    count_high = client.get("/api/items/count?severity=high")
    list_high = client.get("/api/items?severity=high&limit=100")
    assert count_high.json()["total"] == len(list_high.json())
    assert count_high.json()["total"] == 3


def test_severity_filter_accepts_comma_separated_multiple_values():
    resp = client.get("/api/items?severity=high,medium")
    assert resp.status_code == 200
    count_resp = client.get("/api/items/count?severity=high,medium")
    assert count_resp.status_code == 200
