"""
Polls every enabled source on its own interval, through whatever
connector its `connector_type` maps to. This file has no RSS-specific
code in it — it only knows about BaseConnector's `update()` contract, so
it doesn't change when new connector types are added later.

Also runs the retention cleanup pass (see `_maybe_run_retention`) — off
by default (retention_days = 0 means "keep forever"), throttled to at
most once an hour so it's not re-scanning the whole items table on every
20-second tick.
"""
import asyncio
import time

from pantomath.alerts.dispatcher import dispatch_webhooks_for_items
from pantomath.connectors.registry import get_connector
from pantomath.database.sqlite import get_db

RETENTION_CHECK_INTERVAL = 3600  # seconds


class Scheduler:
    def __init__(self, broadcast_fn, check_interval: int = 20):
        self.broadcast = broadcast_fn
        self.check_interval = check_interval
        self._running = False
        self._last_retention_check = 0

    async def start(self):
        self._running = True
        asyncio.create_task(self._loop())

    def stop(self):
        self._running = False

    async def _loop(self):
        while self._running:
            try:
                await self.poll_all()
                await self._maybe_run_retention()
            except Exception as e:
                print(f"[scheduler] error: {e}")
            await asyncio.sleep(self.check_interval)

    async def poll_all(self):
        db = await get_db()
        try:
            cur = await db.execute("SELECT * FROM sources WHERE enabled = 1")
            sources = await cur.fetchall()
            now = time.time()
            for src in sources:
                if now - (src["last_fetched"] or 0) < src["interval_seconds"]:
                    continue
                await self.poll_source(db, dict(src))
        finally:
            await db.close()

    async def poll_source(self, db, src: dict):
        try:
            connector = get_connector(src)
            new_items = await connector.update(db)  # fetch -> normalize -> validate -> store

            await db.execute(
                "UPDATE sources SET last_fetched = ?, last_status = 'ok' WHERE id = ?",
                (time.time(), src["id"]),
            )
            await db.commit()

            if new_items:
                await self.broadcast({"type": "new_items", "items": new_items})
                await dispatch_webhooks_for_items(db, new_items)

        except Exception as e:
            await db.execute(
                "UPDATE sources SET last_fetched = ?, last_status = ? WHERE id = ?",
                (time.time(), f"error: {str(e)[:100]}", src["id"]),
            )
            await db.commit()

    async def _maybe_run_retention(self):
        now = time.time()
        if now - self._last_retention_check < RETENTION_CHECK_INTERVAL:
            return
        self._last_retention_check = now

        db = await get_db()
        try:
            cur = await db.execute("SELECT value FROM settings WHERE key = 'retention_days'")
            row = await cur.fetchone()
            retention_days = int(row["value"]) if row and row["value"] else 0
            if retention_days <= 0:
                return  # 0 = keep forever, the default — nothing to prune

            cutoff = now - (retention_days * 86400)
            cursor = await db.execute("DELETE FROM items WHERE fetched_at < ?", (cutoff,))
            await db.commit()
            if cursor.rowcount:
                print(f"[scheduler] retention cleanup: removed {cursor.rowcount} item(s) older than {retention_days}d")
        finally:
            await db.close()
