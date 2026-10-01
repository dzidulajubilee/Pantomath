"""
Tests for the pantomath-admin command line and the database-connection
cleanup behind it.

Real bugs these cover:
  - Run without sudo, pantomath-admin printed a SQLite traceback and then never
    exited: get_db()/init_db() didn't close the connection on error, and
    aiosqlite's non-daemon thread kept the process alive.
  - After `setup-https` the setup code still pointed at http://host:7373,
    which no longer answers once the service is restricted to 127.0.0.1.
"""
import os
import subprocess
import sys

import aiosqlite
import pytest

from pantomath import cli, https_setup
from pantomath.database import sqlite as db_module


async def test_get_db_closes_the_connection_when_setup_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "x.db"))
    closed = []
    real_connect = aiosqlite.connect

    async def tracking_connect(*args, **kwargs):
        conn = await real_connect(*args, **kwargs)
        original_close = conn.close

        async def close():
            closed.append(True)
            await original_close()

        conn.close = close
        return conn

    async def boom(db):
        raise RuntimeError("pragma failed")

    monkeypatch.setattr(db_module.aiosqlite, "connect", tracking_connect)
    monkeypatch.setattr(db_module, "_configure", boom)

    with pytest.raises(RuntimeError, match="pragma failed"):
        await db_module.get_db()
    assert closed == [True], "a connection whose setup failed must be closed, or its thread keeps the process alive"


async def test_init_db_closes_the_connection_when_a_step_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "x.db"))
    monkeypatch.setattr(db_module, "CONFIG_PATH", str(tmp_path / "none.json"))
    seen = []
    real_get_db = db_module.get_db

    async def spying_get_db():
        conn = await real_get_db()
        seen.append(conn)
        return conn

    async def boom(db):
        raise RuntimeError("migration failed")

    monkeypatch.setattr(db_module, "get_db", spying_get_db)
    monkeypatch.setattr(db_module, "_run_migrations", boom)

    with pytest.raises(RuntimeError, match="migration failed"):
        await db_module.init_db()
    assert seen and not seen[0]._running, "init_db must close its connection even when it fails"


def test_a_damaged_database_ends_the_process_instead_of_hanging(tmp_path):
    """The real symptom: after the error the process must END, not sit there forever."""
    damaged = tmp_path / "pantomath.db"
    damaged.write_bytes(b"this is not a sqlite database" * 100)
    script = (
        "import asyncio, sys\n"
        "from pantomath.database import sqlite as m\n"
        "m.DB_PATH = sys.argv[1]\n"
        "try:\n"
        "    asyncio.run(m.init_db())\n"
        "except Exception as e:\n"
        "    print('failed:', type(e).__name__)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(damaged)],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "PYTHONPATH": os.getcwd()},
    )
    assert result.returncode == 0
    assert "failed:" in result.stdout


def test_admin_command_without_access_says_to_use_sudo(tmp_path, monkeypatch, capsys):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setattr(db_module, "DB_PATH", str(folder / "pantomath.db"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.os, "access", lambda path, mode: False)

    with pytest.raises(SystemExit) as exit_info:
        cli._require_database_access("setup-code")

    assert exit_info.value.code == 1
    out = capsys.readouterr().out
    assert "Run it with sudo: sudo pantomath-admin setup-code" in out
    assert "Traceback" not in out


def test_admin_command_is_allowed_for_root_and_for_a_writable_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "pantomath.db"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cli._require_database_access("setup-code")  # root: fine
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    cli._require_database_access("setup-code")  # owner of a writable folder: fine


def test_dashboard_url_is_https_once_nginx_is_set_up(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "panther")
    monkeypatch.setattr(https_setup, "SITE_ENABLED", tmp_path / "pantomath")
    assert cli._dashboard_url() == "http://panther:7373"

    (tmp_path / "pantomath").write_text("site")
    assert cli._dashboard_url() == "https://panther"
