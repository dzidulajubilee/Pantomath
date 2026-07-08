"""
Sets PANTOMATH_DB / PANTOMATH_ICON_CACHE to a temp directory BEFORE any
`pantomath.*` module is imported anywhere in the test suite. This has to
happen at conftest module-load time, not inside a fixture — several
pantomath modules read these as module-level constants
(pantomath/database/sqlite.py: DB_PATH, pantomath/intelligence/enrichment.py:
ICON_CACHE_DIR), so once one is imported with the wrong path, it's stuck
that way for the rest of the process. pytest guarantees conftest.py loads
before it collects any test module, which is what makes this reliable.
"""
import os
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="pantomath-test-")
os.environ["PANTOMATH_DB"] = os.path.join(_tmpdir, "test.db")
os.environ["PANTOMATH_ICON_CACHE"] = os.path.join(_tmpdir, "icons")

import pytest  # noqa: E402


@pytest.fixture
async def fresh_db():
    """Ensures a clean schema (no leftover rows) before each test that needs one."""
    from pantomath.database.sqlite import get_db, init_db

    await init_db()
    db = await get_db()
    await db.execute("DELETE FROM items")
    await db.execute("DELETE FROM sources")
    await db.execute("DELETE FROM settings")
    await db.execute("DELETE FROM webhooks")
    # deep_extraction defaults ON in production (it's what makes IOC
    # extraction useful), but that means fetching each new item's link —
    # tests that don't care about this feature use fake http://example.com
    # style URLs as item links, which would otherwise mean every test run
    # attempts real network calls. Off by default here; tests that
    # specifically exercise deep extraction turn it on explicitly and use
    # safe file:// URLs (see tests/test_rss_connector.py).
    await db.execute("INSERT INTO settings (key, value) VALUES ('deep_extraction', '0')")
    await db.commit()
    await db.close()
    yield
