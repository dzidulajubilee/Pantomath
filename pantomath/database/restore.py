"""
Restoring from a database backup (the counterpart to GET /api/backup).

This is one of the few genuinely destructive operations in the app — a
bad restore replaces every item, source, setting, and webhook currently
on disk. The sequence below is built around one rule: never touch the
live database until the uploaded file has been fully validated on its
own, and always keep a safety copy of what was live immediately before
the swap, so a bad restore is always recoverable.

High-level flow, in order:
  1. Stream the upload to a temp file on the SAME filesystem as the live
     database (required for the final swap to be atomic — os.replace()
     is only atomic within a single filesystem) with a hard size cap, so
     a huge/malicious upload can't fill the disk before validation even
     runs.
  2. Validate the temp file in complete isolation from the live database:
     SQLite magic header, PRAGMA integrity_check, and the presence of
     the core tables a real Pantomath database must have. Any failure
     here deletes the temp file and raises — nothing live is touched.
  3. Only once validation passes: checkpoint the WAL on the LIVE database
     (folds any not-yet-persisted data into the main file) and copy that
     now fully-consistent live file to a timestamped safety-backup path.
  4. Atomically swap the validated temp file into place over the live
     path, then remove any leftover -wal/-shm sidecar files so the next
     connection opens a clean, unambiguous file rather than replaying
     stale WAL frames that belonged to the database that just got
     replaced.
"""
import os
import pathlib
import shutil
import sqlite3
import time
import uuid

from pantomath.database.sqlite import DB_PATH

MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2GB — generous for a SQLite file this app produces, still finite
SQLITE_MAGIC = b"SQLite format 3\x00"
REQUIRED_TABLES = {"items", "sources", "settings", "webhooks"}


class RestoreValidationError(Exception):
    """The uploaded file failed validation — the live database was never touched."""


def _db_dir() -> pathlib.Path:
    return pathlib.Path(DB_PATH).resolve().parent


async def save_upload_to_temp(file) -> pathlib.Path:
    """
    Streams an UploadFile to a temp file in the same directory as the
    live database, enforcing MAX_UPLOAD_BYTES while writing rather than
    reading the whole thing into memory first — a multi-hundred-MB (or
    deliberately huge) upload should never be fully buffered in the
    process just to find out afterward that it's too large or invalid.
    """
    _db_dir().mkdir(parents=True, exist_ok=True)

    free_bytes = shutil.disk_usage(_db_dir()).free
    # Require headroom for the upload itself, PLUS the safety backup that
    # restore_database() makes of the current live database before
    # swapping — both can briefly coexist on disk. Without this check, a
    # large upload on a nearly-full volume could fill the disk before
    # validation even gets a chance to reject a bad file.
    live_size = pathlib.Path(DB_PATH).stat().st_size if pathlib.Path(DB_PATH).exists() else 0
    if free_bytes < MAX_UPLOAD_BYTES + live_size:
        raise RestoreValidationError(
            f"Not enough free disk space to safely accept this upload. "
            f"Available: {free_bytes // (1024*1024)}MB, need headroom for up to "
            f"{(MAX_UPLOAD_BYTES + live_size) // (1024*1024)}MB (upload limit plus a safety backup of the current database)."
        )

    tmp_path = _db_dir() / f".restore-upload-{uuid.uuid4().hex}.tmp"
    written = 0
    try:
        # 0600 from the moment the file exists, before any (potentially
        # sensitive — this is a full database) bytes are written into it.
        # The default os.open mode would leave it world-readable
        # (subject to umask) for the duration of the upload.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise RestoreValidationError(
                        f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024*1024*1024)}GB limit."
                    )
                out.write(chunk)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    if written == 0:
        tmp_path.unlink(missing_ok=True)
        raise RestoreValidationError("Uploaded file is empty.")
    return tmp_path


def validate_sqlite_backup(path: pathlib.Path) -> None:
    """
    Blocking. Call via loop.run_in_executor() from the API route — for a
    large database, PRAGMA integrity_check can take real time, and this
    must never block the event loop (every other request, the WebSocket,
    and the scheduler's next poll tick would stall for the duration).

    Raises RestoreValidationError with a specific, user-facing reason if
    `path` isn't a usable Pantomath database. Never mutates `path` or
    anything else — read-only checks only.
    """
    with open(path, "rb") as f:
        header = f.read(16)
    if header != SQLITE_MAGIC:
        raise RestoreValidationError("That file isn't a SQLite database (bad file header).")

    # Open read-only (mode=ro) so this can never accidentally create WAL/
    # journal side-effects next to the uploaded temp file.
    uri = f"file:{path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise RestoreValidationError(f"SQLite integrity check failed: {integrity}")

            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            missing = REQUIRED_TABLES - tables
            if missing:
                raise RestoreValidationError(
                    f"This doesn't look like a Pantomath database — missing table(s): {', '.join(sorted(missing))}."
                )
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        raise RestoreValidationError(f"SQLite couldn't open this file: {e}")


def _checkpoint_live_database() -> None:
    """Folds any pending WAL data into the live .db file before it gets copied/replaced."""
    if not pathlib.Path(DB_PATH).exists():
        return  # fresh install, nothing to checkpoint yet
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()


def _remove_wal_sidecars(db_path: str) -> None:
    for suffix in ("-wal", "-shm"):
        p = pathlib.Path(db_path + suffix)
        p.unlink(missing_ok=True)


def restore_database(validated_tmp_path: pathlib.Path) -> dict:
    """
    Blocking. Call via loop.run_in_executor() from the API route — this
    does a WAL checkpoint plus a full safety-backup file copy (shutil.copy2)
    of the live database, which for a large database is real, non-trivial
    I/O time that must not stall the event loop.

    Performs the actual swap. Caller must have already run
    validate_sqlite_backup() successfully on this exact path — this
    function assumes that's done and focuses purely on the live-data
    side: safety-backup, then atomic replace, then sidecar cleanup.
    """
    _checkpoint_live_database()

    safety_backup_path = None
    if pathlib.Path(DB_PATH).exists():
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        safety_backup_path = _db_dir() / f"pantomath-pre-restore-{timestamp}.db"
        shutil.copy2(DB_PATH, safety_backup_path)

    # os.replace is atomic as long as both paths are on the same
    # filesystem — guaranteed here since save_upload_to_temp() wrote the
    # temp file into the same directory as DB_PATH specifically for this.
    os.replace(validated_tmp_path, DB_PATH)
    _remove_wal_sidecars(DB_PATH)

    return {
        "restored": True,
        "safety_backup": str(safety_backup_path) if safety_backup_path else None,
    }
