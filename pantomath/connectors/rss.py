"""
RSS/Atom connector — the only connector shipped in v1.0.

Retrieval (feedparser) and entry-shaping live as plain functions in
pantomath/feeds/ (retrieval vs. parsing stay separate files on purpose).
This class just implements the BaseConnector contract on top of them and
owns the storage step, so the scheduler never has to know it's RSS
specifically — it only ever talks to BaseConnector.
"""
import asyncio
import time
import uuid

from pantomath.connectors.base import BaseConnector
from pantomath.feeds.article_fetcher import fetch_article_text_sync
from pantomath.feeds.parser import normalize_entry
from pantomath.feeds.rss import FETCH_HARD_LIMIT, FeedFetchError, fetch_raw
from pantomath.intelligence.ioc_extraction import extract_iocs
from pantomath.intelligence.kev import kev_hits, load_kev_set
from pantomath.intelligence.priority import compute_priority
from pantomath.intelligence.scoring import score_severity_detail
from pantomath.intelligence.tagging import extract_tags
from pantomath.intelligence.watchlist import load_watchlist, match_watchlist

MAX_CONCURRENT_ARTICLE_FETCHES = 5


class RSSConnector(BaseConnector):
    connector_type = "rss"

    async def fetch(self):
        loop = asyncio.get_running_loop()
        try:
            # fetch_raw bounds its own connect/read/download time, but not
            # DNS resolution — this is the backstop that guarantees one
            # source can never hold up the scheduler's poll of the others.
            # (The worker thread is left to finish on its own; the poll
            # loop just stops waiting for it.)
            feed = await asyncio.wait_for(
                loop.run_in_executor(None, fetch_raw, self.source["url"]),
                timeout=FETCH_HARD_LIMIT,
            )
        except asyncio.TimeoutError as e:
            raise FeedFetchError(f"no response within {FETCH_HARD_LIMIT}s") from e
        return feed.entries[:50]

    def normalize(self, raw) -> list[dict]:
        return [normalize_entry(entry) for entry in raw]

    async def _deep_extraction_enabled(self, db) -> bool:
        cur = await db.execute("SELECT value FROM settings WHERE key = 'deep_extraction'")
        row = await cur.fetchone()
        # Enabled by default — it's what makes IOC extraction actually
        # useful, since RSS summaries are usually too short to contain
        # real indicators. Opt out in Settings if you'd rather not have
        # Pantomath fetch every new article's full page.
        return row is None or row["value"] != "0"

    async def _fetch_article_texts(self, items: list[dict]) -> dict[str, str]:
        """Bounded-concurrency full-page fetch, keyed by guid. Best-effort, never raises."""
        if not items:
            return {}
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_ARTICLE_FETCHES)

        async def fetch_one(item):
            async with semaphore:
                text = await loop.run_in_executor(None, fetch_article_text_sync, item.get("link", ""))
                return item["guid"], text

        results = await asyncio.gather(*(fetch_one(item) for item in items))
        return {guid: text for guid, text in results if text}

    async def store(self, db, items: list[dict]) -> list[dict]:
        # Filter to items not already on disk BEFORE doing any full-page
        # fetching — feedparser re-returns the same ~50 recent entries on
        # every poll regardless of dedup state, so without this filter
        # we'd re-fetch and re-parse the full article page for the same
        # already-stored items on every single poll cycle, forever.
        guids = [item["guid"] for item in items]
        existing_guids: set[str] = set()
        if guids:
            placeholders = ",".join("?" * len(guids))
            cur = await db.execute(
                f"SELECT guid FROM items WHERE source_id = ? AND guid IN ({placeholders})",
                [self.source["id"], *guids],
            )
            existing_guids = {row["guid"] for row in await cur.fetchall()}
        new_items = [item for item in items if item["guid"] not in existing_guids]

        deep_extraction = await self._deep_extraction_enabled(db)
        article_texts = await self._fetch_article_texts(new_items) if deep_extraction else {}

        watchlist = await load_watchlist(db)
        kev_set = await load_kev_set(db)

        inserted = []
        for item in new_items:
            item_id = str(uuid.uuid4())
            # Full article text (when available) is used ONLY to widen
            # what severity/tagging/IOC extraction can see — the stored
            # and displayed summary stays the original RSS teaser.
            extraction_text = " ".join(filter(None, [item["summary"], article_texts.get(item["guid"], "")]))

            content_severity, content_keyword = score_severity_detail(item["title"], extraction_text)
            vendors, actors = extract_tags(item["title"], extraction_text)
            iocs = extract_iocs(item["title"], extraction_text)
            watch_hits = match_watchlist(watchlist, item["title"], item["summary"])
            kev_cves = kev_hits(iocs["cve"], kev_set)
            severity = compute_priority(content_severity, bool(watch_hits), bool(kev_cves))

            # INSERT OR IGNORE + rowcount is still the final "only new
            # items stored" safety net (e.g. a concurrent poll), even
            # though the pre-filter above already handles the common case.
            cursor = await db.execute(
                """INSERT OR IGNORE INTO items
                   (id, source_id, title, link, summary, published, fetched_at, guid,
                    severity, vendors, actors, cves, ips, hashes, emails, watch_hits, kev_cves,
                    content_severity, content_keyword)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item_id, self.source["id"], item["title"], item["link"],
                    item["summary"], item["published"], time.time(),
                    item["guid"], severity, ",".join(vendors), ",".join(actors),
                    ",".join(iocs["cve"]), ",".join(iocs["ip"]),
                    ",".join(iocs["hash"]), ",".join(iocs["email"]),
                    ",".join(watch_hits), ",".join(kev_cves),
                    content_severity, content_keyword,
                ),
            )
            if cursor.rowcount == 0:
                continue  # already stored — not new

            inserted.append({
                "id": item_id,
                "source_id": self.source["id"],
                "source_name": self.source["name"],
                "source_color": self.source["color"],
                "source_icon": self.source.get("icon_url"),
                "category": self.source["category"],
                "title": item["title"],
                "link": item["link"],
                "summary": item["summary"][:400],
                "published": item["published"],
                "severity": severity,
                "content_severity": content_severity,
                "content_keyword": content_keyword,
                "vendors": vendors,
                "actors": actors,
                "cves": iocs["cve"],
                "ips": iocs["ip"],
                "hashes": iocs["hash"],
                "emails": iocs["email"],
                "watch_hits": watch_hits,
                "kev_cves": kev_cves,
                "bookmarked": False,
            })

        await db.commit()
        return inserted
