"""
Tests for POST /api/restore, the counterpart to GET /api/backup.

This is the single most destructive endpoint in the app — a bad restore
replaces every item, source, setting, and webhook currently stored. These
tests are correspondingly stricter than most: rejection tests confirm the
live database is genuinely untouched (not just that the response is a
400), and the success test verifies the swap by re-opening a fresh
connection to the live DB_PATH afterward (proving the file on disk
actually changed, not just that the endpoint claimed it did) and by
reading the safety-backup file directly off disk to confirm the
pre-restore data is really recoverable there.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pantomath.app import app
from pantomath.database.models import SCHEMA
from pantomath.database.sqlite import DB_PATH, get_db

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


def _build_valid_replacement_db(tmp_path, source_id="replacement-src", item_id="replacement-item"):
    """Builds a standalone, schema-valid Pantomath .db file with one distinctive item, to upload as a restore."""
    path = tmp_path / "replacement.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO sources (id, name, url, category) VALUES (?, ?, ?, ?)",
        (source_id, "Replacement Source", "http://replacement.example.com/feed", "news"),
    )
    conn.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at) VALUES (?, ?, ?, ?, 1000)",
        (item_id, source_id, "Item from the restored database", item_id + "-guid"),
    )
    conn.commit()
    conn.close()
    return path


async def _seed_live_db_with_marker_item(marker_id="original-item"):
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('orig-src', 'Original', 'http://orig.example.com/feed', 'news')")
    await db.execute(
        "INSERT INTO items (id, source_id, title, guid, fetched_at) VALUES (?, 'orig-src', 'Original pre-restore item', ?, 1000)",
        (marker_id, marker_id + "-guid"),
    )
    await db.commit()
    await db.close()


async def test_restore_rejects_a_non_sqlite_file_and_leaves_live_db_untouched():
    await _seed_live_db_with_marker_item()

    resp = client.post("/api/restore", files={"file": ("not-a-db.db", b"this is definitely not a sqlite file", "application/octet-stream")})
    assert resp.status_code == 400
    assert "SQLite database" in resp.json()["detail"]

    # The live database must be completely unaffected by a rejected upload.
    db = await get_db()
    cur = await db.execute("SELECT id FROM items")
    ids = {r["id"] for r in await cur.fetchall()}
    await db.close()
    assert ids == {"original-item"}


async def test_restore_rejects_a_valid_sqlite_file_missing_required_tables():
    await _seed_live_db_with_marker_item()

    # A real, valid SQLite file — just not a Pantomath one. Built on disk
    # (not :memory:) since the endpoint validates the actual file header,
    # not just table names.
    import os as _os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = _os.path.join(d, "unrelated.db")
        conn = sqlite3.connect(p)
        conn.executescript("CREATE TABLE unrelated_stuff (x INTEGER);")
        conn.commit()
        conn.close()
        with open(p, "rb") as f:
            resp = client.post("/api/restore", files={"file": ("unrelated.db", f.read(), "application/octet-stream")})

    assert resp.status_code == 400
    assert "missing table" in resp.json()["detail"]

    db = await get_db()
    cur = await db.execute("SELECT id FROM items")
    ids = {r["id"] for r in await cur.fetchall()}
    await db.close()
    assert ids == {"original-item"}, "a rejected restore must never touch the live database"


async def test_restore_rejects_an_empty_file():
    resp = client.post("/api/restore", files={"file": ("empty.db", b"", "application/octet-stream")})
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


async def test_restore_successfully_swaps_live_data_and_creates_a_recoverable_safety_backup(tmp_path):
    await _seed_live_db_with_marker_item(marker_id="original-item")

    replacement_path = _build_valid_replacement_db(tmp_path)
    with open(replacement_path, "rb") as f:
        resp = client.post("/api/restore", files={"file": ("replacement.db", f.read(), "application/octet-stream")})

    assert resp.status_code == 200
    body = resp.json()
    assert body["restored"] is True
    assert body["safety_backup"], "a safety backup path must always be returned when a live database existed"

    # Prove the swap is real: open a BRAND NEW connection to the live
    # DB_PATH (not reusing any handle from before the restore) and
    # confirm it now serves the replacement data, not the original.
    db = await get_db()
    cur = await db.execute("SELECT id FROM items")
    ids = {r["id"] for r in await cur.fetchall()}
    await db.close()
    assert ids == {"replacement-item"}, "live database must now contain the restored data"

    # Prove the safety backup is real and actually recoverable — read it
    # directly off disk, independent of the app, the way an admin would
    # if they needed to undo a bad restore.
    backup_conn = sqlite3.connect(body["safety_backup"])
    backup_ids = {row[0] for row in backup_conn.execute("SELECT id FROM items")}
    backup_conn.close()
    assert backup_ids == {"original-item"}, "the pre-restore safety backup must contain the ORIGINAL data, not the new data"


async def test_restore_enforces_an_upload_size_cap(tmp_path, monkeypatch):
    import pantomath.database.restore as restore_module
    monkeypatch.setattr(restore_module, "MAX_UPLOAD_BYTES", 10)  # tiny cap so the test doesn't need a huge file

    oversized = b"SQLite format 3\x00" + b"x" * 100  # starts with a valid-looking header but exceeds the cap
    resp = client.post("/api/restore", files={"file": ("big.db", oversized, "application/octet-stream")})
    assert resp.status_code == 400
    assert "limit" in resp.json()["detail"].lower()


async def test_restore_leaves_no_dangling_temp_files_after_a_rejection(tmp_path):
    from pantomath.database.restore import _db_dir

    before = set(_db_dir().glob(".restore-upload-*.tmp"))
    resp = client.post("/api/restore", files={"file": ("bad.db", b"not sqlite", "application/octet-stream")})
    assert resp.status_code == 400
    after = set(_db_dir().glob(".restore-upload-*.tmp"))
    assert after == before, "a rejected upload must not leave its temp file behind"


async def test_restore_rejects_upload_when_insufficient_disk_space(monkeypatch):
    import shutil as _shutil
    import pantomath.database.restore as restore_module

    fake_usage = _shutil.disk_usage(".")._replace(free=1024)  # 1KB free — nowhere near enough
    monkeypatch.setattr(restore_module.shutil, "disk_usage", lambda path: fake_usage)

    resp = client.post("/api/restore", files={"file": ("backup.db", b"SQLite format 3\x00" + b"x" * 100, "application/octet-stream")})
    assert resp.status_code == 400
    assert "disk space" in resp.json()["detail"].lower()


async def test_restore_temp_file_is_created_with_owner_only_permissions():
    """
    The temp file holding (potentially very sensitive — a full database)
    upload contents must never be readable by anything other than the
    owning process while it exists, regardless of the process umask.
    """
    import stat
    from pantomath.database.restore import save_upload_to_temp

    class FakeUploadFile:
        def __init__(self, data):
            self._data = data
            self._sent = False

        async def read(self, n):
            if self._sent:
                return b""
            self._sent = True
            return self._data

    tmp = await save_upload_to_temp(FakeUploadFile(b"some file contents"))
    try:
        mode = stat.S_IMODE(tmp.stat().st_mode)
        assert mode == 0o600, f"expected temp upload file to be 0600, got {oct(mode)}"
    finally:
        tmp.unlink(missing_ok=True)
