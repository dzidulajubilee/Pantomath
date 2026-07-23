import json
import os
import pathlib
import uuid

import aiosqlite

from pantomath.database.models import MIGRATIONS, SCHEMA

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
    # WAL lets readers (API requests) proceed while the scheduler's
    # background poll is mid-write, instead of blocking behind SQLite's
    # default rollback-journal exclusive lock — this app has exactly that
    # pattern (one continuous background writer + many concurrent API
    # reads) so it matters here, not just as a generic best practice.
    # busy_timeout is the backstop for the remaining moments two writers
    # do overlap (e.g. "poll all now" plus the scheduler tick): retry
    # for up to 5s instead of immediately raising "database is locked".
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA busy_timeout = 5000")
    return db


async def _existing_columns(db, table: str) -> set[str]:
    cur = await db.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in await cur.fetchall()}


async def _run_migrations(db):
    """
    Brings an existing database up to date with columns added after its
    original creation. Safe to run on every startup — each column is only
    added if it's actually missing, so this is a no-op on an up-to-date
    database and on a freshly-created one (SCHEMA already has everything).
    """
    tables_checked: dict[str, set[str]] = {}
    for table, column, definition in MIGRATIONS:
        if table not in tables_checked:
            tables_checked[table] = await _existing_columns(db, table)
        if column not in tables_checked[table]:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            tables_checked[table].add(column)
    await db.commit()


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await get_db()
    await db.executescript(SCHEMA)
    await db.commit()
    await _run_migrations(db)

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
