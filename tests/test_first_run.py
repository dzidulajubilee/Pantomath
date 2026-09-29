"""
0.8.1: first-run and recovery. The first-run screen needs the one-time
setup code from the server; a lost Settings password can be reset with the
recovery code on the sign-in page, or on the server with pantomath-admin.
"""
import os
import stat

import pytest
from fastapi.testclient import TestClient

from pantomath import cli
from pantomath.app import app
from pantomath.auth import setup_code, sign_in
from pantomath.database.sqlite import get_db

PW = "settings-pass-123"


@pytest.fixture(autouse=True)
async def signed_out(fresh_db, monkeypatch):
    monkeypatch.delenv("PANTOMATH_OPEN_DASHBOARD", raising=False)
    yield


def _code() -> str:
    TestClient(app).get("/api/auth/status")
    return setup_code.read_code()


def _set_up() -> tuple[TestClient, str]:
    browser = TestClient(app)
    body = browser.post("/api/auth/setup", json={"password": PW, "setup_code": _code()}).json()
    return browser, body["recovery_code"]


def test_first_run_needs_the_setup_code():
    status = TestClient(app).get("/api/auth/status").json()
    assert status["setup_needed"] is True
    code = setup_code.read_code()
    assert len(setup_code.normalize(code)) == 12
    assert stat.S_IMODE(os.stat(setup_code.code_path()).st_mode) == 0o600
    c = TestClient(app)
    assert c.post("/api/auth/setup", json={"password": PW}).status_code == 401
    assert c.post("/api/auth/setup", json={"password": PW, "setup_code": "AAAA-BBBB-CCCC"}).status_code == 401
    typed = f"  {code.lower().replace('-', ' ')} "                  # forgiving about case, spaces and dashes
    resp = c.post("/api/auth/setup", json={"password": PW, "setup_code": typed})
    assert resp.status_code == 200 and resp.json()["recovery_code"]
    assert setup_code.read_code() is None and not os.path.exists(setup_code.code_path())
    assert TestClient(app).get("/api/auth/status").json()["setup_needed"] is False


def test_wrong_setup_codes_count_toward_the_attempt_limit():
    _code()
    c = TestClient(app)
    for _ in range(sign_in.MAX_FAILURES):
        c.post("/api/auth/setup", json={"password": PW, "setup_code": "WRONG-CODE-0000"})
    assert c.post("/api/auth/setup", json={"password": PW, "setup_code": setup_code.read_code()}).status_code == 429


async def test_a_configured_install_has_no_setup_code():
    _set_up()
    db = await get_db()
    try:
        assert await setup_code.ensure_setup_code(db) is None
    finally:
        await db.close()
    assert not os.path.exists(setup_code.code_path())


def test_recovery_code_on_the_sign_in_page():
    first_browser, recovery = _set_up()
    c = TestClient(app)
    assert c.post("/api/auth/recover", json={"recovery_code": "NOPE-NOPE", "new_password": "new-pass-4567"}).status_code == 401
    resp = c.post("/api/auth/recover", json={"recovery_code": recovery, "new_password": "new-pass-4567"})
    body = resp.json()
    assert resp.status_code == 200 and body["role"] == "admin" and body["recovery_code"] != recovery
    assert c.get("/api/items").status_code == 200                     # signed in straight away
    assert first_browser.get("/api/items").status_code == 401         # old Settings-password sign-ins end
    assert TestClient(app).post("/api/auth/login", json={"password": PW}).status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"password": "new-pass-4567"}).json()["role"] == "admin"
    again = TestClient(app).post("/api/auth/recover", json={"recovery_code": recovery, "new_password": "other-pass-890"})
    assert again.status_code == 401                                   # a recovery code works once


def test_recovery_refuses_the_team_password():
    admin, recovery = _set_up()
    admin.headers["X-Settings-Token"] = admin.post("/api/auth/login", json={"password": PW}).json()["settings_token"]
    admin.put("/api/auth/team-password", json={"password": "team-pass-4567"})
    resp = TestClient(app).post("/api/auth/recover", json={"recovery_code": recovery, "new_password": "team-pass-4567"})
    assert resp.status_code == 400


async def test_cli_reset_sets_the_password_in_the_terminal(capsys):
    admin, _ = _set_up()
    assert await cli.reset_settings_password("terminal-pass-1") == 0
    out = capsys.readouterr().out
    assert "New recovery code" in out and "Signed out 1 device" in out
    assert admin.get("/api/items").status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"password": "terminal-pass-1"}).status_code == 200
    assert TestClient(app).get("/api/auth/status").json()["setup_needed"] is False  # no first-run window opened
    assert await cli.reset_settings_password("short") == 1


async def test_cli_clear_goes_back_to_setup_with_a_new_code(capsys):
    _set_up()
    assert await cli.reset_settings_password(None, clear=True) == 0
    assert setup_code.read_code() in capsys.readouterr().out
    assert await cli.show_setup_code(bare=True) == 0
    assert capsys.readouterr().out.strip() == setup_code.read_code()


async def test_cli_sign_out_everyone(capsys):
    admin, _ = _set_up()
    admin.headers["X-Settings-Token"] = admin.post("/api/auth/login", json={"password": PW}).json()["settings_token"]
    key = admin.post("/api/auth/api-keys", json={"label": "script"}).json()["key"]
    await cli.sign_out_everyone(include_api_keys=False)
    sign_in._cache.clear()
    del admin.headers["X-Settings-Token"]
    assert admin.get("/api/items").status_code == 401
    script = TestClient(app)
    script.headers["Authorization"] = f"Bearer {key}"
    assert script.get("/api/items").status_code == 200                 # keys survive unless asked
    await cli.sign_out_everyone(include_api_keys=True)
    sign_in._cache.clear()
    assert script.get("/api/items").status_code == 401


async def test_clear_signs_everyone_out_and_the_setup_code_is_needed_everywhere(capsys):
    admin, _ = _set_up()
    admin.headers["X-Settings-Token"] = admin.post("/api/auth/login", json={"password": PW}).json()["settings_token"]
    admin.put("/api/auth/team-password", json={"password": "team-pass-4567"})
    team = TestClient(app)
    team.post("/api/auth/login", json={"password": "team-pass-4567"})
    await cli.reset_settings_password(None, clear=True)
    sign_in._cache.clear()
    assert team.get("/api/items").status_code == 401            # back to first run: nobody is signed in
    # and even a signed-in viewer couldn't claim the Settings password without the code
    viewer = TestClient(app)
    key = None
    db = await get_db()
    try:
        key, _ = await sign_in.create_session(db, "team", False, "127.0.0.1", "")
    finally:
        await db.close()
    viewer.cookies.set(sign_in.COOKIE_NAME, key)
    assert viewer.post("/api/settings/auth/setup", json={"password": "claimed-pass-1"}).status_code == 401
    code = setup_code.read_code()
    assert viewer.post("/api/settings/auth/setup", json={"password": "claimed-pass-1", "setup_code": code}).status_code == 200
    assert setup_code.read_code() is None
