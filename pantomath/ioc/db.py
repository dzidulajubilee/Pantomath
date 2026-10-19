"""
Opening ioc.db.

The IOC database is its own SQLite file, next to pantomath.db
(/var/lib/pantomath/ioc.db) rather than more tables inside it:

  - SQLite allows one writer per file. A 200,000-line feed import holds
    only ioc.db's lock, so RSS polling, sign-ins and settings saves on
    pantomath.db never wait for it.
  - The existing backup stays the size it is. Most of ioc.db is feed data
    that can be downloaded again.
  - If ioc.db is damaged or can't be opened, the IOC tab and /api/v1 say
    so (IocUnavailable) and every other tab keeps working.

Same engine, driver and pragmas as pantomath.db, so no new dependency.
"""
import os

import aiosqlite

from pantomath.database.sqlite import DB_PATH, _configure, _existing_columns
from pantomath.ioc.models import IOC_INDEX_SCHEMA, IOC_MIGRATIONS, IOC_TABLE_SCHEMA

IOC_DB_PATH = os.environ.get("PANTOMATH_IOC_DB", os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "ioc.db"))


class IocUnavailable(Exception):
    """ioc.db couldn't be opened. str() is shown on the IOC tab and returned by /api/v1."""


async def get_ioc_db():
    try:
        db = await aiosqlite.connect(IOC_DB_PATH)
    except Exception as e:
        raise IocUnavailable(f"The IOC database ({IOC_DB_PATH}) can't be opened: {e}") from e
    try:
        await _configure(db)
    except BaseException as e:
        # Same reason as get_db(): never leave aiosqlite's thread running.
        await db.close()
        if isinstance(e, Exception):
            raise IocUnavailable(f"The IOC database ({IOC_DB_PATH}) can't be opened: {e}") from e
        raise
    return db


async def init_ioc_db() -> None:
    """Creates ioc.db empty on first start and brings an existing one up to date."""
    os.makedirs(os.path.dirname(IOC_DB_PATH), exist_ok=True)
    db = await get_ioc_db()
    try:
        await db.executescript(IOC_TABLE_SCHEMA)
        await db.commit()
        checked: dict[str, set[str]] = {}
        for table, column, definition in IOC_MIGRATIONS:
            if table not in checked:
                checked[table] = await _existing_columns(db, table)
            if column not in checked[table]:
                await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                checked[table].add(column)
        await db.commit()
        await db.executescript(IOC_INDEX_SCHEMA)
        await db.commit()
    finally:
        await db.close()
