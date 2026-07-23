"""
Regression coverage for /api/tags, /api/iocs, /api/iocs/summary, and the
vendor/day-bucket parts of /api/stats after moving their aggregation from
Python (load every matching row's full text column into memory, split on
commas, count in a dict) to a SQL recursive CTE that does the same job
inside SQLite itself.

These endpoints had no existing test coverage before this change, so
these tests exist specifically to prove the SQL rewrite produces
identical results to the original Python implementation — not just that
it runs without error. Covers: basic counts, the count-descending/
name-ascending tiebreak ordering, pagination (limit/offset), items with
multiple comma-joined values, empty-column exclusion, and an item that
repeats a value that also appears in other items (to catch any
off-by-one in the recursive split around the last segment of the list).
"""
import pytest
from fastapi.testclient import TestClient

from pantomath.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


async def _insert_item(db, item_id, vendors="", actors="", cves="", fetched_at=1000):
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, vendors, actors, cves, ips, hashes, emails)
           VALUES (?, 's1', 'title', ?, ?, ?, ?, ?, '', '', '')""",
        (item_id, item_id + "-guid", fetched_at, vendors, actors, cves),
    )


async def _seed(db):
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    # last value in a comma list ("Zoho" in item 4, "Apple" in item 3) exercises the
    # recursive CTE's final-segment handling, not just the first split.
    await _insert_item(db, "1", vendors="Microsoft,Cisco")
    await _insert_item(db, "2", vendors="Microsoft")
    await _insert_item(db, "3", vendors="Cisco,Apple")
    await _insert_item(db, "4", vendors="Cisco,Microsoft,Zoho")
    await _insert_item(db, "5", vendors="")  # empty column must be excluded entirely
    await db.commit()


async def test_list_tags_counts_and_orders_by_count_desc_name_asc():
    from pantomath.database.sqlite import get_db
    db = await get_db()
    await _seed(db)
    await db.close()

    resp = client.get("/api/tags?type=vendor&limit=20")
    assert resp.status_code == 200
    # Microsoft:3, Cisco:3 (tied -> name ascending: Cisco before Microsoft), Apple:1, Zoho:1 (tied -> Apple before Zoho)
    assert resp.json() == [
        {"name": "Cisco", "count": 3},
        {"name": "Microsoft", "count": 3},
        {"name": "Apple", "count": 1},
        {"name": "Zoho", "count": 1},
    ]


async def test_list_tags_respects_limit():
    from pantomath.database.sqlite import get_db
    db = await get_db()
    await _seed(db)
    await db.close()

    resp = client.get("/api/tags?type=vendor&limit=2")
    assert resp.status_code == 200
    assert resp.json() == [{"name": "Cisco", "count": 3}, {"name": "Microsoft", "count": 3}]


async def test_list_iocs_pagination_offset_matches_full_list():
    from pantomath.database.sqlite import get_db
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    await _insert_item(db, "1", cves="CVE-2026-1,CVE-2026-2")
    await _insert_item(db, "2", cves="CVE-2026-1")
    await _insert_item(db, "3", cves="CVE-2026-3")
    await db.commit()
    await db.close()

    full = client.get("/api/iocs?type=cve&limit=20&offset=0").json()
    page1 = client.get("/api/iocs?type=cve&limit=1&offset=0").json()
    page2 = client.get("/api/iocs?type=cve&limit=1&offset=1").json()
    page3 = client.get("/api/iocs?type=cve&limit=1&offset=2").json()

    assert full == [
        {"name": "CVE-2026-1", "count": 2},
        {"name": "CVE-2026-2", "count": 1},
        {"name": "CVE-2026-3", "count": 1},
    ]
    assert page1 + page2 + page3 == full


async def test_iocs_summary_counts_distinct_values_per_type():
    from pantomath.database.sqlite import get_db
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves, ips, hashes, emails)
           VALUES ('1', 's1', 't', 'g1', 1000, 'CVE-2026-1,CVE-2026-2', '1.1.1.1', '', '')"""
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves, ips, hashes, emails)
           VALUES ('2', 's1', 't', 'g2', 1000, 'CVE-2026-1', '1.1.1.1,2.2.2.2', '', '')"""
    )
    await db.commit()
    await db.close()

    resp = client.get("/api/iocs/summary")
    assert resp.status_code == 200
    assert resp.json() == {"cve": 2, "ip": 2, "hash": 0, "email": 0}


async def test_items_filtered_by_ioc_type_alone_matches_any_value_of_that_type():
    """
    ioc_type without ioc_value should mean 'has at least one IOC of this
    type' — this is what the calendar's day-drilldown uses (all CVEs
    mentioned that day, not one specific CVE).
    """
    from pantomath.database.sqlite import get_db
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves, ips)
           VALUES ('1', 's1', 'has cve', 'g1', 1000, 'CVE-2026-1', '')"""
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves, ips)
           VALUES ('2', 's1', 'has ip only', 'g2', 1000, '', '1.1.1.1')"""
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, guid, fetched_at, cves, ips)
           VALUES ('3', 's1', 'has neither', 'g3', 1000, '', '')"""
    )
    await db.commit()
    await db.close()

    resp = client.get("/api/items?ioc_type=cve")
    ids = {i["id"] for i in resp.json()}
    assert ids == {"1"}

    resp = client.get("/api/items?ioc_type=ip")
    ids = {i["id"] for i in resp.json()}
    assert ids == {"2"}


async def test_iocs_and_summary_respect_date_range():
    import datetime
    from pantomath.database.sqlite import get_db
    day1 = datetime.datetime.strptime("2026-07-01", "%Y-%m-%d").timestamp()
    day2 = datetime.datetime.strptime("2026-07-15", "%Y-%m-%d").timestamp()
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('1', 's1', 't', 'g1', ?, 'CVE-2026-1')",
        (day1,),
    )
    # outside the queried range below
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('2', 's1', 't', 'g2', ?, 'CVE-2026-2')",
        (day2,),
    )
    await db.commit()
    await db.close()

    resp = client.get("/api/iocs?type=cve&date_from=2026-07-01&date_to=2026-07-01")
    assert resp.json() == [{"name": "CVE-2026-1", "count": 1}]

    resp = client.get("/api/iocs/summary?date_from=2026-07-01&date_to=2026-07-01")
    assert resp.json()["cve"] == 1

    resp = client.get("/api/iocs/summary")  # unscoped — should see both
    assert resp.json()["cve"] == 2


async def test_iocs_calendar_buckets_counts_by_day_and_respects_range():
    import datetime
    from pantomath.database.sqlite import get_db
    day1 = datetime.datetime.strptime("2026-07-01", "%Y-%m-%d").timestamp()
    day1_later = day1 + 3600  # same day, an hour later
    day2 = datetime.datetime.strptime("2026-07-02", "%Y-%m-%d").timestamp()
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    # Two items on 2026-07-01, one on 2026-07-02, one with no CVE at all (must be excluded).
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('1', 's1', 't', 'g1', ?, 'CVE-2026-1')",
        (day1,),
    )
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('2', 's1', 't', 'g2', ?, 'CVE-2026-2')",
        (day1_later,),
    )
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('3', 's1', 't', 'g3', ?, 'CVE-2026-3')",
        (day2,),
    )
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at, cves) VALUES ('4', 's1', 't', 'g4', ?, '')",
        (day1,),
    )
    await db.commit()
    await db.close()

    resp = client.get("/api/iocs/calendar?type=cve")
    assert resp.status_code == 200
    assert resp.json() == [
        {"date": "2026-07-01", "count": 2},
        {"date": "2026-07-02", "count": 1},
    ]

    # Range-bounded to just the 1st should exclude the 2nd entirely.
    resp = client.get("/api/iocs/calendar?type=cve&date_from=2026-07-01&date_to=2026-07-01")
    assert resp.json() == [{"date": "2026-07-01", "count": 2}]


async def test_stats_top_vendors_and_articles_by_day_reflect_seeded_items():
    import time
    from pantomath.database.sqlite import get_db
    db = await get_db()
    now = time.time()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Source', 'http://x.com/feed', 'news')")
    await _insert_item(db, "1", vendors="Microsoft,Cisco", fetched_at=now)
    await _insert_item(db, "2", vendors="Microsoft", fetched_at=now)
    await db.commit()
    await db.close()

    resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert {"name": "Microsoft", "count": 2} in body["top_vendors"]
    assert {"name": "Cisco", "count": 1} in body["top_vendors"]
    assert sum(body["articles_by_day"].values()) == 2
