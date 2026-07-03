"""
RSS/Atom connector — the only connector shipped in v1.0.

Retrieval (feedparser) and entry-shaping live as plain functions in
backend/feeds/ (retrieval vs. parsing stay separate files on purpose).
This class just implements the BaseConnector contract on top of them and
owns the storage step, so the scheduler never has to know it's RSS
specifically — it only ever talks to BaseConnector.
"""
import asyncio
import time
import uuid

from backend.connectors.base import BaseConnector
from backend.feeds.rss import fetch_raw
from backend.feeds.parser import normalize_entry
from backend.intelligence.scoring import score_severity
from backend.intelligence.tagging import extract_tags


class RSSConnector(BaseConnector):
    connector_type = "rss"

    async def fetch(self):
        loop = asyncio.get_event_loop()
        feed = await loop.run_in_executor(None, fetch_raw, self.source["url"])
        return feed.entries[:50]

    def normalize(self, raw) -> list[dict]:
        return [normalize_entry(entry) for entry in raw]

    async def store(self, db, items: list[dict]) -> list[dict]:
        inserted = []
        for item in items:
            item_id = str(uuid.uuid4())
            severity = score_severity(item["title"], item["summary"])
            vendors, actors = extract_tags(item["title"], item["summary"])

            # INSERT OR IGNORE + rowcount is the "only new items stored"
            # guarantee: the UNIQUE(source_id, guid) constraint makes the
            # database the single source of truth for what's already been
            # seen. rowcount == 0 means this exact item is already on disk
            # — nothing else happens for it, it's just skipped.
            cursor = await db.execute(
                """INSERT OR IGNORE INTO items
                   (id, source_id, title, link, summary, published, fetched_at, guid,
                    severity, vendors, actors)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item_id, self.source["id"], item["title"], item["link"],
                    item["summary"], item["published"], time.time(),
                    item["guid"], severity, ",".join(vendors), ",".join(actors),
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
                "vendors": vendors,
                "actors": actors,
                "bookmarked": False,
            })

        await db.commit()
        return inserted
