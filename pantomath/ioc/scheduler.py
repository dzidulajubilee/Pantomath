"""
The IOC feeds' own timer, a separate task from the RSS scheduler, so a
slow or failing list download never delays RSS polling (and the other way
round). Downloads one due feed at a time, writes the SIEM hit counts
every 30 seconds, and once an hour expires indicators that no source
has reported for their lifetime.
"""
import asyncio
import time

from pantomath.ioc.db import IocUnavailable, get_ioc_db
from pantomath.ioc.feeds import run_feed
from pantomath.ioc.hits import hit_counter
from pantomath.ioc.store import expire_due

EXPIRY_CHECK_INTERVAL = 3600


class IocScheduler:
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self._running = False
        self._task = None
        self._last_expiry_check = 0.0
        self._busy: set[str] = set()   # feeds downloading now, so "Update now" can't run one twice

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False

    async def _loop(self):
        while self._running:
            try:
                await self.flush_hits()
                await self.run_due()
                await self.flush_hits()
                await self._maybe_expire()
            except IocUnavailable as e:
                print(f"[ioc] {e}")
            except Exception as e:
                print(f"[ioc] scheduler error: {e}")
            await asyncio.sleep(self.check_interval)

    async def flush_hits(self) -> None:
        db = await get_ioc_db()
        try:
            await hit_counter.flush(db)
        finally:
            await db.close()

    async def shutdown(self) -> None:
        """Stops the loop and writes the hit counts still in memory."""
        self.stop()
        try:
            await self.flush_hits()
        except Exception as e:
            print(f"[ioc] could not write SIEM hit counts on shutdown: {e}")

    async def run_due(self) -> None:
        db = await get_ioc_db()
        try:
            cur = await db.execute("SELECT * FROM ioc_feeds WHERE enabled = 1")
            feeds = [dict(r) for r in await cur.fetchall()]
            now = time.time()
            for feed in feeds:
                if now - (feed["last_fetched"] or 0) < feed["interval_seconds"] or feed["id"] in self._busy:
                    continue
                await self._run(db, feed)
        finally:
            await db.close()

    async def run_now(self, feed_id: str) -> dict:
        db = await get_ioc_db()
        try:
            cur = await db.execute("SELECT * FROM ioc_feeds WHERE id = ?", (feed_id,))
            row = await cur.fetchone()
            if not row:
                return {"ok": False, "error": "no such feed"}
            if feed_id in self._busy:
                return {"ok": False, "error": "this feed is downloading already"}
            return await self._run(db, dict(row))
        finally:
            await db.close()

    async def _run(self, db, feed: dict) -> dict:
        self._busy.add(feed["id"])
        try:
            return await run_feed(db, feed)
        finally:
            self._busy.discard(feed["id"])

    async def _maybe_expire(self):
        now = time.time()
        if now - self._last_expiry_check < EXPIRY_CHECK_INTERVAL:
            return
        self._last_expiry_check = now
        db = await get_ioc_db()
        try:
            expired, deleted = await expire_due(db, now)
            if expired or deleted:
                print(f"[ioc] expiry: {expired} indicator(s) expired, {deleted} long-expired removed")
        finally:
            await db.close()
