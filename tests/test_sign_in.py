"""
0.8.0: signing in to Pantomath. Every data endpoint needs a session (a
cookie from the sign-in page, an API key, or an unlocked Settings token);
the team password views, the Settings password views and administers.
"""
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pantomath.app import app
from pantomath.auth import setup_code, sign_in
from pantomath.database.sqlite import get_db

SETTINGS_PW = "settings-pass-123"
TEAM_PW = "team-pass-4567"


@pytest.fixture(autouse=True)
async def signed_out(fresh_db, monkeypatch):
    monkeypatch.delenv("PANTOMATH_OPEN_DASHBOARD", raising=False)
    yield


def _setup() -> TestClient:
    """A fresh install set up through the sign-in page; returns that (admin) browser."""
    admin = TestClient(app)
    admin.get("/api/auth/status")                               # creates the setup code, as the service does
    code = setup_code.read_code()                               # what `pantomath-admin setup-code` shows
    resp = admin.post("/api/auth/setup", json={"password": SETTINGS_PW, "setup_code": code})
    assert resp.status_code == 200 and resp.json()["recovery_code"]
    admin.headers["X-Settings-Token"] = resp.json()["settings_token"]
    assert admin.put("/api/auth/team-password", json={"password": TEAM_PW}).status_code == 200
    del admin.headers["X-Settings-Token"]
    return admin


def _signed_in(password=TEAM_PW, remember=False) -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"password": password, "remember": remember}).status_code == 200
    return c


def test_every_data_endpoint_needs_sign_in():
    from pantomath.api.routes import protected_router, router

    anonymous = TestClient(app)
    checked = 0
    for route in [*router.routes, *protected_router.routes]:
        path, methods = getattr(route, "path", ""), getattr(route, "methods", None) or set()
        if not path.startswith("/api/") or "GET" not in methods or "{" in path or path.startswith("/api/auth/"):
            continue
        assert anonymous.get(path).status_code == 401, path
        checked += 1
    assert checked >= 15   # the walk really covered the routers
    assert anonymous.get("/api/items").headers["X-Pantomath-Sign-In"] == "required"
    assert anonymous.get("/").status_code == 200           # the page shell (no data) still loads
    assert anonymous.get("/api/auth/status").json()["signed_in"] is False


def test_first_run_setup_signs_in_as_admin():
    anonymous = TestClient(app)
    assert anonymous.get("/api/auth/status").json()["setup_needed"] is True
    assert anonymous.post("/api/auth/login", json={"password": "anything1"}).status_code == 409
    admin = _setup()
    status = admin.get("/api/auth/status").json()
    assert (status["signed_in"], status["role"], status["setup_needed"], status["team_password"]) == (True, "admin", False, True)
    assert admin.get("/api/items").status_code == 200
    assert TestClient(app).post("/api/auth/setup", json={"password": "another-pass", "setup_code": "x"}).status_code == 409


def test_passwords_decide_the_role():
    _setup()
    team = TestClient(app)
    resp = team.post("/api/auth/login", json={"password": TEAM_PW})
    assert resp.json() == {"ok": True, "role": "team"}
    assert team.get("/api/items").status_code == 200
    assert team.get("/api/watchlist").status_code == 401     # viewing isn't administering
    admin = TestClient(app)
    resp = admin.post("/api/auth/login", json={"password": SETTINGS_PW}).json()
    assert resp["role"] == "admin" and resp["settings_token"]
    admin.headers["X-Settings-Token"] = resp["settings_token"]
    assert admin.get("/api/watchlist").status_code == 200
    assert TestClient(app).post("/api/auth/login", json={"password": "wrong-password"}).status_code == 401


def test_remember_sets_a_90_day_cookie_otherwise_a_session_cookie():
    _setup()
    remembered = TestClient(app).post("/api/auth/login", json={"password": TEAM_PW, "remember": True}).headers["set-cookie"]
    assert "Max-Age=7776000" in remembered and "HttpOnly" in remembered and "SameSite=strict" in remembered
    session = TestClient(app).post("/api/auth/login", json={"password": TEAM_PW}).headers["set-cookie"]
    assert "Max-Age" not in session


def test_repeated_failures_lock_out_that_address_only():
    _setup()
    c = TestClient(app)
    for _ in range(sign_in.MAX_FAILURES):
        assert c.post("/api/auth/login", json={"password": "nope-nope"}).status_code == 401
    assert c.post("/api/auth/login", json={"password": TEAM_PW}).status_code == 429
    # the Settings password's own lockout is untouched by sign-in guesses
    sign_in._failures.clear()
    assert _signed_in(SETTINGS_PW).get("/api/items").status_code == 200


def test_team_password_rules_and_changing_it_signs_team_out():
    admin = _setup()
    token = admin.post("/api/auth/login", json={"password": SETTINGS_PW}).json()["settings_token"]
    admin.headers["X-Settings-Token"] = token
    assert admin.put("/api/auth/team-password", json={"password": "short"}).status_code == 400
    assert admin.put("/api/auth/team-password", json={"password": SETTINGS_PW}).status_code == 400
    team = _signed_in()
    admin.put("/api/auth/team-password", json={"password": "new-team-pass-1"})
    assert team.get("/api/items").status_code == 401
    assert admin.get("/api/items").status_code == 200          # admin sessions stay
    admin.delete("/api/auth/team-password")
    assert TestClient(app).post("/api/auth/login", json={"password": "new-team-pass-1"}).status_code == 401


def test_devices_can_be_listed_and_signed_out():
    admin = _setup()
    admin.headers["X-Settings-Token"] = admin.post("/api/auth/login", json={"password": SETTINGS_PW}).json()["settings_token"]
    wall = _signed_in(remember=True)
    devices = admin.get("/api/auth/sessions").json()["devices"]
    assert sum(d["current"] for d in devices) == 1 and len(devices) == 3
    wall_id = next(d["id"] for d in devices if d["remember"])
    assert admin.delete(f"/api/auth/sessions/{wall_id}").status_code == 200
    assert wall.get("/api/items").status_code == 401
    other = _signed_in()
    assert admin.post("/api/auth/sessions/sign-out-others").json()["signed_out"] >= 1
    assert other.get("/api/items").status_code == 401 and admin.get("/api/items").status_code == 200


def test_api_keys_read_but_do_not_administer():
    admin = _setup()
    admin.headers["X-Settings-Token"] = admin.post("/api/auth/login", json={"password": SETTINGS_PW}).json()["settings_token"]
    assert admin.post("/api/auth/api-keys", json={"label": " "}).status_code == 400
    created = admin.post("/api/auth/api-keys", json={"label": "SIEM export"}).json()
    assert created["key"].startswith("pmk_")
    script = TestClient(app)
    script.headers["Authorization"] = f"Bearer {created['key']}"
    assert script.get("/api/items").status_code == 200
    assert script.get("/api/watchlist").status_code == 401
    admin.delete(f"/api/auth/sessions/{created['id']}")
    assert script.get("/api/items").status_code == 401


async def test_sessions_survive_a_restart_and_expire():
    _setup()
    c = _signed_in()
    sign_in._cache.clear()                                    # a restart forgets everything in memory
    assert c.get("/api/items").status_code == 200
    db = await get_db()
    await db.execute("UPDATE sessions SET expires_at = ? WHERE role = 'team'", (time.time() - 1,))
    await db.commit()
    await db.close()
    sign_in._cache.clear()
    assert c.get("/api/items").status_code == 401


def test_sign_out():
    _setup()
    c = _signed_in()
    assert c.post("/api/auth/logout").status_code == 200
    assert c.get("/api/items").status_code == 401


def test_live_updates_need_sign_in_too():
    _setup()
    with pytest.raises(WebSocketDisconnect) as closed:
        with TestClient(app).websocket_connect("/ws") as ws:
            ws.receive_text()
    assert closed.value.code == 4401
    c = TestClient(app)
    cookie = c.post("/api/auth/login", json={"password": TEAM_PW}).cookies[sign_in.COOKIE_NAME]
    with c.websocket_connect("/ws", headers={"cookie": f"{sign_in.COOKIE_NAME}={cookie}"}) as ws:
        ws.send_text("ping")                                   # accepted and kept open
