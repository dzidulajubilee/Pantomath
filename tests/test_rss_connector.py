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


async def test_deep_extraction_defaults_to_enabled_when_no_setting_row_exists(sample_source):
    connector = RSSConnector(sample_source)
    db = await get_db()
    await db.execute("DELETE FROM settings WHERE key = 'deep_extraction'")
    await db.commit()
    assert await connector._deep_extraction_enabled(db) is True
    await db.close()


async def test_deep_extraction_respects_explicit_off_setting(sample_source):
    connector = RSSConnector(sample_source)
    db = await get_db()
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('deep_extraction', '0') "
        "ON CONFLICT(key) DO UPDATE SET value = '0'"
    )
    await db.commit()
    assert await connector._deep_extraction_enabled(db) is False
    await db.close()


async def test_deep_extraction_surfaces_iocs_missing_from_summary_alone(sample_source, tmp_path):
    """
    The core value proposition: a CVE mentioned only in the full article
    body (not in the short RSS summary) should still be detected when
    deep extraction is enabled — and should NOT be detected when it's off.
    """
    article_html = (
        "<html><body><p>Full incident writeup.</p>"
        "<p>Indicators: CVE-2026-99999, hash d41d8cd98f00b204e9800998ecf8427e, "
        "contact abuse@malicious-example.com</p></body></html>"
    )
    article_file = tmp_path / "article.html"
    article_file.write_text(article_html)
    article_url = f"file://{article_file}"

    db = await get_db()

    # Deep extraction ON — should find the CVE that's only in the article body
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('deep_extraction', '1') "
        "ON CONFLICT(key) DO UPDATE SET value = '1'"
    )
    await db.commit()
    connector = RSSConnector(sample_source)
    items = [{
        "guid": "deep-1", "title": "Short teaser title only",
        "link": article_url, "summary": "No indicators in this short teaser at all.",
        "published": 0,
    }]
    inserted = await connector.store(db, items)
    assert "CVE-2026-99999" in inserted[0]["cves"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in inserted[0]["hashes"]
    assert "abuse@malicious-example.com" in inserted[0]["emails"]

    # Deep extraction OFF — same article, but now only the teaser is visible,
    # so none of those indicators should be found.
    await db.execute("UPDATE settings SET value = '0' WHERE key = 'deep_extraction'")
    await db.commit()
    connector2 = RSSConnector(sample_source)
    items2 = [{
        "guid": "deep-2", "title": "Short teaser title only",
        "link": article_url, "summary": "No indicators in this short teaser at all.",
        "published": 0,
    }]
    inserted2 = await connector2.store(db, items2)
    await db.close()
    assert inserted2[0]["cves"] == []
    assert inserted2[0]["hashes"] == []
    assert inserted2[0]["emails"] == []


async def test_duplicate_items_are_not_refetched_for_deep_extraction(sample_source, tmp_path, monkeypatch):
    """
    feedparser re-returns the same recent entries on every poll. Items
    already on disk must be filtered out BEFORE any full-page fetch is
    attempted, or every poll cycle would re-fetch every already-stored
    article's page forever.
    """
    import pantomath.connectors.rss as rss_module

    fetch_calls = []
    original = rss_module.fetch_article_text_sync

    def counting_fetch(url):
        fetch_calls.append(url)
        return original(url)

    monkeypatch.setattr(rss_module, "fetch_article_text_sync", counting_fetch)

    article_file = tmp_path / "dup_article.html"
    article_file.write_text("<p>Some content, no indicators.</p>")
    article_url = f"file://{article_file}"

    db = await get_db()
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('deep_extraction', '1') "
        "ON CONFLICT(key) DO UPDATE SET value = '1'"
    )
    await db.commit()

    connector = RSSConnector(sample_source)
    items = [{"guid": "dup-guid", "title": "T", "link": article_url, "summary": "s", "published": 0}]

    first_pass = await connector.store(db, items)
    assert len(first_pass) == 1
    assert len(fetch_calls) == 1  # fetched once for the genuinely new item

    second_pass = await connector.store(db, items)  # identical items, second poll
    await db.close()
    assert len(second_pass) == 0  # already stored, correctly skipped
    assert len(fetch_calls) == 1  # NOT re-fetched for the duplicate
