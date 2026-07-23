import pytest

from pantomath.database.sqlite import get_db
from pantomath.intelligence.reprocessor import reprocess_items


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


async def _insert_legacy_source_and_item(db, item_id="legacy-1", title=None, summary=None):
    """
    Simulates an item stored by an OLDER version of Pantomath, before
    tagging/IOC extraction existed — empty vendors/actors/cves/etc, even
    though the title/summary clearly contain detectable content. This is
    the exact real-world scenario reprocessing exists to fix.
    """
    await db.execute(
        "INSERT INTO sources (id, name, url, category) VALUES ('src-legacy', 'Legacy Source', 'http://x.com/feed', 'news')"
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, summary, guid, fetched_at, severity, vendors, actors, cves, ips, hashes, emails)
           VALUES (?, 'src-legacy', ?, ?, ?, 1000, 'low', '', '', '', '', '', '')""",
        (item_id, title or "LockBit exploits Microsoft flaw",
         summary or "Actively exploited zero-day CVE-2026-11111 found in the wild", item_id + "-guid"),
    )
    await db.commit()


async def test_reprocess_backfills_previously_undetected_data():
    db = await get_db()
    await _insert_legacy_source_and_item(db)

    # Before reprocessing: exactly what an old, pre-tagging install would have on disk
    cur = await db.execute("SELECT * FROM items WHERE id = 'legacy-1'")
    before = dict(await cur.fetchone())
    assert before["vendors"] == "" and before["actors"] == "" and before["cves"] == ""

    result = await reprocess_items(db, use_deep_extraction=False)
    assert result["processed"] == 1
    assert result["sources"] == 1

    cur = await db.execute("SELECT * FROM items WHERE id = 'legacy-1'")
    after = dict(await cur.fetchone())
    await db.close()

    assert "Microsoft" in after["vendors"]
    assert "LockBit" in after["actors"]
    assert "CVE-2026-11111" in after["cves"]
    assert after["severity"] == "high"


async def test_reprocess_does_not_touch_title_link_summary_guid():
    db = await get_db()
    await _insert_legacy_source_and_item(db)
    cur = await db.execute("SELECT title, summary, guid FROM items WHERE id = 'legacy-1'")
    before = dict(await cur.fetchone())

    await reprocess_items(db, use_deep_extraction=False)

    cur = await db.execute("SELECT title, summary, guid FROM items WHERE id = 'legacy-1'")
    after = dict(await cur.fetchone())
    await db.close()
    assert before == after


async def test_reprocess_can_be_scoped_to_one_source():
    db = await get_db()
    await _insert_legacy_source_and_item(db, item_id="legacy-1")
    await db.execute(
        "INSERT INTO sources (id, name, url, category) VALUES ('src-other', 'Other Source', 'http://y.com/feed', 'news')"
    )
    await db.execute(
        """INSERT INTO items (id, source_id, title, summary, guid, fetched_at, cves)
           VALUES ('other-1', 'src-other', 'Cisco patches CVE-2026-99999', 'desc', 'other-guid', 1000, '')"""
    )
    await db.commit()

    result = await reprocess_items(db, source_id="src-legacy", use_deep_extraction=False)
    assert result["processed"] == 1
    assert result["sources"] == 1

    cur = await db.execute("SELECT cves FROM items WHERE id = 'other-1'")
    other_row = dict(await cur.fetchone())
    await db.close()
    assert other_row["cves"] == ""  # untouched — reprocessing was scoped to src-legacy only


async def test_reprocess_empty_database_is_a_safe_noop():
    db = await get_db()
    result = await reprocess_items(db, use_deep_extraction=False)
    await db.close()
    assert result == {"processed": 0, "sources": 0}


async def test_reprocess_batches_correctly_across_a_batch_boundary():
    """
    reprocess_items now pages through items in fixed-size batches
    (BATCH_SIZE) instead of loading the whole table at once. This proves
    an item count that spans multiple batches still gets every row
    processed exactly once — not skipped, not duplicated — by seeding
    more rows than one batch holds and checking both the returned count
    and that every single row actually got backfilled.
    """
    from pantomath.intelligence.reprocessor import BATCH_SIZE

    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('src-legacy', 'Legacy Source', 'http://x.com/feed', 'news')")
    n = BATCH_SIZE + 25  # deliberately spans two batches
    for i in range(n):
        await db.execute(
            """INSERT INTO items (id, source_id, title, summary, guid, fetched_at, severity, vendors, actors, cves, ips, hashes, emails)
               VALUES (?, 'src-legacy', ?, 'desc', ?, 1000, 'low', '', '', '', '', '', '')""",
            (f"item-{i}", f"Cisco flaw CVE-2026-{10000+i}", f"item-{i}-guid"),
        )
    await db.commit()

    result = await reprocess_items(db, use_deep_extraction=False)
    assert result["processed"] == n
    assert result["sources"] == 1

    cur = await db.execute("SELECT COUNT(*) AS c FROM items WHERE cves = ''")
    still_empty = (await cur.fetchone())["c"]
    await db.close()
    assert still_empty == 0, "every row across both batches should have been backfilled, none skipped"
