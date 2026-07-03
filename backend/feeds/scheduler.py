"""
Polls every enabled source on its own interval, through whatever
connector its `connector_type` maps to. This file has no RSS-specific
code in it — it only knows about BaseConnector's `update()` contract, so
it doesn't change when new connector types are added later.
"""
import asyncio
import time

from backend.database.sqlite import get_db
from backend.connectors.registry import get_connector


class Scheduler:
    def __init__(self, broadcast_fn, check_interval: int = 20):
        self.broadcast = broadcast_fn
        self.check_interval = check_interval
        self._running = False

    async def start(self):
        self._running = True
        asyncio.create_task(self._loop())

    def stop(self):
        self._running = False

    async def _loop(self):
        while self._running:
            try:
                await self.poll_all()
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

        except Exception as e:
            await db.execute(
                "UPDATE sources SET last_fetched = ?, last_status = ? WHERE id = ?",
                (time.time(), f"error: {str(e)[:100]}", src["id"]),
            )
            await db.commit()
