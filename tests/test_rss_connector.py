import pytest

from pantomath.connectors.rss import RSSConnector
from pantomath.database.sqlite import get_db


@pytest.fixture
async def sample_source(fresh_db):
    db = await get_db()
    source = {
        "id": "src-1", "name": "Test Source", "url": "http://example.com/feed.xml",
        "color": "#5eead4", "category": "general", "icon_url": None,
    }
    await db.execute(
        "INSERT INTO sources (id, name, url, color, category) VALUES (?,?,?,?,?)",
        (source["id"], source["name"], source["url"], source["color"], source["category"]),
    )
    await db.commit()
    await db.close()
    return source


async def test_store_inserts_new_items(sample_source):
    connector = RSSConnector(sample_source)
    db = await get_db()
    items = [
        {"guid": "g1", "title": "Item One", "link": "http://x.com/1", "summary": "s1", "published": 0},
        {"guid": "g2", "title": "Item Two", "link": "http://x.com/2", "summary": "s2", "published": 0},
    ]
    inserted = await connector.store(db, items)
    await db.close()
    assert len(inserted) == 2


async def test_store_skips_duplicates_by_guid(sample_source):
    connector = RSSConnector(sample_source)
    db = await get_db()
    items = [{"guid": "dup-1", "title": "Same Item", "link": "http://x.com/1", "summary": "s", "published": 0}]

    first_pass = await connector.store(db, items)
    assert len(first_pass) == 1

    second_pass = await connector.store(db, items)  # identical items, second poll
    await db.close()
    assert len(second_pass) == 0  # nothing new — already on disk


async def test_store_applies_severity_and_tags(sample_source):
    connector = RSSConnector(sample_source)
    db = await get_db()
    items = [{
        "guid": "g-critical", "title": "LockBit exploits Microsoft flaw",
        "link": "http://x.com", "summary": "Actively exploited zero-day", "published": 0,
    }]
    inserted = await connector.store(db, items)
    await db.close()
    assert inserted[0]["severity"] == "high"
    assert "Microsoft" in inserted[0]["vendors"]
    assert "LockBit" in inserted[0]["actors"]
