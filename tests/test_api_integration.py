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
