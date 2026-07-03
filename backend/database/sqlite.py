import aiosqlite
import os
import json
import uuid
import pathlib

from backend.database.models import SCHEMA

DB_PATH = os.environ.get("PANTOMATH_DB", "/var/lib/pantomath/pantomath.db")

# Optional starter list. Ships EMPTY by default so no source ever appears
# that the user didn't explicitly add or opt into. If you want a curated
# starter pack, add entries here yourself before first install.
CONFIG_PATH = os.environ.get(
    "PANTOMATH_FEEDS_CONFIG",
    str(pathlib.Path(__file__).resolve().parents[2] / "config" / "feeds.json"),
)


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    return db


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await get_db()
    await db.executescript(SCHEMA)
    await db.commit()

    # Only seed from config/feeds.json on a genuinely empty database, and only
    # if the file actually has entries. An empty/missing file means: start
    # with zero sources, exactly as the user configures them from the UI.
    cur = await db.execute("SELECT COUNT(*) as c FROM sources")
    row = await cur.fetchone()
    if row["c"] == 0 and os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                seed = json.load(f).get("sources", [])
        except Exception:
            seed = []
        for s in seed:
            await db.execute(
                """INSERT OR IGNORE INTO sources
                   (id, name, url, category, color, icon_url, connector_type, interval_seconds)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    s["name"],
                    s["url"],
                    s.get("category", "general"),
                    s.get("color", "#5eead4"),
                    s.get("icon_url"),
                    s.get("connector_type", "rss"),
                    s.get("interval_seconds", 300),
                ),
            )
        await db.commit()

    await db.close()
