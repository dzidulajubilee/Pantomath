"""
Re-runs severity/tagging/IOC extraction against items ALREADY on disk,
without re-fetching their RSS feed.

Why this exists: parsing/extraction logic evolves over time (new IOC
types, better tagging, deep extraction landing after items were already
stored) — but a schema migration that adds a new column only gives it an
empty default; it never goes back and re-computes values for rows that
predate the column. An install that's been running since before IOC
extraction shipped will have plenty of items with genuinely empty
`cves`/`vendors`/`actors`, not because nothing was ever detected, but
because detection didn't exist yet when they were stored. This is the
retroactive fix for that gap — it re-parses what's already stored (and
optionally re-fetches the full article page, same as new items get)
without touching the source's RSS feed at all.
"""
import asyncio

from pantomath.feeds.article_fetcher import fetch_article_text_sync
from pantomath.intelligence.ioc_extraction import extract_iocs
from pantomath.intelligence.scoring import score_severity
from pantomath.intelligence.tagging import extract_tags

MAX_CONCURRENT_FETCHES = 5


async def _deep_extraction_enabled(db) -> bool:
    cur = await db.execute("SELECT value FROM settings WHERE key = 'deep_extraction'")
    row = await cur.fetchone()
    return row is None or row["value"] != "0"


async def _fetch_article_texts(rows: list[dict]) -> dict[str, str]:
    if not rows:
        return {}
    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    async def fetch_one(row):
        async with semaphore:
            text = await loop.run_in_executor(None, fetch_article_text_sync, row.get("link") or "")
            return row["id"], text

    results = await asyncio.gather(*(fetch_one(row) for row in rows))
    return {rid: text for rid, text in results if text}


async def reprocess_items(db, source_id: str | None = None, use_deep_extraction: bool | None = None) -> dict:
    """
    Re-runs extraction against stored items and updates their severity/
    vendors/actors/cves/ips/hashes/emails columns in place. Never touches
    title/link/summary/published/guid — only the derived fields.

    `source_id=None` reprocesses every item in the database. Pass
    `use_deep_extraction` to override the global Settings toggle for
    this run specifically (e.g. force it on for a one-time backfill even
    if it's normally off); leave as None to respect the current setting.

    Returns {"processed": N, "sources": N} — the number of items updated
    and how many distinct sources they spanned.
    """
    query = "SELECT id, title, summary, link, source_id FROM items"
    params = []
    if source_id:
        query += " WHERE source_id = ?"
        params.append(source_id)
    cur = await db.execute(query, params)
    rows = [dict(r) for r in await cur.fetchall()]

    if use_deep_extraction is None:
        use_deep_extraction = await _deep_extraction_enabled(db)

    article_texts = await _fetch_article_texts(rows) if use_deep_extraction else {}

    for row in rows:
        extraction_text = " ".join(filter(None, [row["summary"] or "", article_texts.get(row["id"], "")]))
        severity = score_severity(row["title"], extraction_text)
        vendors, actors = extract_tags(row["title"], extraction_text)
        iocs = extract_iocs(row["title"], extraction_text)

        await db.execute(
            """UPDATE items SET severity=?, vendors=?, actors=?, cves=?, ips=?, hashes=?, emails=?
               WHERE id=?""",
            (
                severity, ",".join(vendors), ",".join(actors),
                ",".join(iocs["cve"]), ",".join(iocs["ip"]),
                ",".join(iocs["hash"]), ",".join(iocs["email"]),
                row["id"],
            ),
        )

    await db.commit()
    distinct_sources = {row["source_id"] for row in rows}
    return {"processed": len(rows), "sources": len(distinct_sources)}
