"""
Abstract interface every intelligence-source connector must implement.

v1.0 ships exactly one connector: RSS/Atom (backend/connectors/rss.py).
The interface exists so a *future* source — a TAXII feed, a vendor API
poller, a paid intel feed, whatever — can be added later by:

    1. implementing BaseConnector in a new backend/connectors/<name>.py
    2. registering it in backend/connectors/registry.py

No changes to the scheduler, the database layer, or the API layer are
required to add a connector. This is the boundary the "Extensibility"
requirement asks for — retrieval, parsing/normalization, and storage are
each a distinct step, and only RSS is implemented in this version.
"""
from abc import ABC, abstractmethod


class BaseConnector(ABC):
    # Matches a `sources.connector_type` value. Subclasses override this.
    connector_type: str = "base"

    def __init__(self, source: dict):
        # `source` is a row from the `sources` table (as a dict): id, url,
        # name, category, interval_seconds, etc. A connector should never
        # need external state beyond this.
        self.source = source

    @abstractmethod
    async def fetch(self):
        """
        Retrieve raw records from the external source. Pure I/O — no
        parsing or shaping happens here.
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw) -> list[dict]:
        """
        Turn raw records into the common item shape used everywhere else
        in the app: {guid, title, link, summary, published}.
        """
        raise NotImplementedError

    def validate(self, item: dict) -> bool:
        """
        Reject malformed/incomplete items before they reach storage.
        Default implementation covers the common case; override for
        source-specific validation.
        """
        return bool(item.get("title")) and bool(item.get("guid"))

    @abstractmethod
    async def store(self, db, items: list[dict]) -> list[dict]:
        """
        Persist items, silently skipping ones already on disk (matched on
        source_id + guid). Must return ONLY the items that were actually
        newly inserted, so callers (the scheduler, WebSocket broadcast)
        know exactly what's new — nothing already-seen should ever be
        re-emitted.
        """
        raise NotImplementedError

    async def update(self, db) -> list[dict]:
        """Full retrieval cycle: fetch -> normalize -> validate -> store."""
        raw = await self.fetch()
        normalized = self.normalize(raw)
        valid = [item for item in normalized if self.validate(item)]
        return await self.store(db, valid)
