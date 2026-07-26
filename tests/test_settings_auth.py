"""
Tests for pantomath/auth/settings_auth.py and the /api/settings/auth/*
endpoints — the password gate added specifically for the Settings and
Sources pages (see routes.py's `protected_router`), while the rest of
the app (Dashboard, Live Feed, IOCs, etc.) stays completely open by
design.
"""
import pytest
from fastapi.testclient import TestClient

from pantomath.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


def test_fresh_install_reports_no_password_configured():
    resp = client.get("/api/settings/auth/status")
    assert resp.status_code == 200
    assert resp.json() == {"configured": False}


def test_first_time_setup_succeeds_and_returns_token_and_recovery_code():
    resp = client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"]
    assert body["recovery_code"]
    # Grouped alphanumeric format, e.g. XXXX-XXXX-XXXX
    assert len(body["recovery_code"].split("-")) == 3

    status = client.get("/api/settings/auth/status").json()
    assert status["configured"] is True


def test_setup_rejects_too_short_password():
    resp = client.post("/api/settings/auth/setup", json={"password": "short"})
    assert resp.status_code == 400


def test_setup_is_rejected_once_a_password_already_exists():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.post("/api/settings/auth/setup", json={"password": "another-password-here"})
    assert resp.status_code == 409


def test_login_with_correct_password_succeeds():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.post("/api/settings/auth/login", json={"password": "correct-horse-battery"})
    assert resp.status_code == 200
    assert resp.json()["token"]


def test_login_with_wrong_password_is_rejected():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.post("/api/settings/auth/login", json={"password": "wrong-password"})
    assert resp.status_code == 401


def test_repeated_wrong_passwords_trigger_a_lockout():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    for _ in range(5):
        resp = client.post("/api/settings/auth/login", json={"password": "wrong"})
        assert resp.status_code == 401

    # Even the CORRECT password must now be rejected during the lockout window.
    resp = client.post("/api/settings/auth/login", json={"password": "correct-horse-battery"})
    assert resp.status_code == 401
    assert "attempts" in resp.json()["detail"].lower()


def test_a_valid_token_authorizes_a_protected_endpoint():
    setup = client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"}).json()
    resp = client.get("/api/settings", headers={"X-Settings-Token": setup["token"]})
    assert resp.status_code == 200


def test_protected_endpoint_rejects_missing_token():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.get("/api/settings")  # module-level client has no default headers here
    assert resp.status_code == 401


def test_protected_endpoint_rejects_garbage_token():
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.get("/api/settings", headers={"X-Settings-Token": "not-a-real-token"})
    assert resp.status_code == 401


@pytest.mark.parametrize("path,method", [
    ("/api/sources", "get"),
    ("/api/settings", "get"),
    ("/api/webhooks", "get"),
    ("/api/backup", "get"),
    ("/api/reprocess", "post"),
    ("/api/restore", "post"),
])
def test_every_settings_and_sources_route_requires_a_token(path, method):
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = getattr(client, method)(path)
    assert resp.status_code == 401, f"{method.upper()} {path} should require settings auth but returned {resp.status_code}"


@pytest.mark.parametrize("path", ["/api/items", "/api/tags", "/api/iocs", "/api/stats", "/api/iocs/summary"])
def test_the_rest_of_the_app_stays_open_with_no_token_at_all(path):
    """
    The whole point of scoping this to Settings/Sources rather than the
    entire app: a SOC/NOC 'notification board' use case where viewing
    stays open. A password being configured must never affect these.
    """
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.get(path)
    assert resp.status_code == 200, f"{path} should remain accessible with no token, got {resp.status_code}"


def test_source_icon_route_stays_open_even_though_source_management_is_gated():
    """/api/sources/{id}/icon is used by feed cards across the whole open dashboard, not just the gated Sources page."""
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.get("/api/sources/some-nonexistent-id/icon")
    # 404 (source not found) is fine — the point is it must NOT be 401 (auth-gated).
    assert resp.status_code != 401


def test_recovery_code_resets_password_and_issues_a_new_recovery_code():
    setup = client.post("/api/settings/auth/setup", json={"password": "old-password-here"}).json()
    old_recovery_code = setup["recovery_code"]

    resp = client.post("/api/settings/auth/recover", json={
        "recovery_code": old_recovery_code,
        "new_password": "brand-new-password",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"]
    assert body["recovery_code"] and body["recovery_code"] != old_recovery_code, "recovery code must be single-use and rotated"

    # Old password must no longer work.
    resp = client.post("/api/settings/auth/login", json={"password": "old-password-here"})
    assert resp.status_code == 401
    # New password must work.
    resp = client.post("/api/settings/auth/login", json={"password": "brand-new-password"})
    assert resp.status_code == 200


def test_recovery_code_is_single_use():
    setup = client.post("/api/settings/auth/setup", json={"password": "old-password-here"}).json()
    code = setup["recovery_code"]

    first = client.post("/api/settings/auth/recover", json={"recovery_code": code, "new_password": "password-one-here"})
    assert first.status_code == 200

    # The database's fail-count/lockout tracking is shared between the
    # password and recovery-code paths, and the previous successful
    # recovery already reset it — so a second attempt with the now-dead
    # old code is a clean, unlocked check of single-use-ness, not a
    # lockout artifact.
    second = client.post("/api/settings/auth/recover", json={"recovery_code": code, "new_password": "password-two-here"})
    assert second.status_code == 401


def test_recovery_rejects_a_wrong_code():
    client.post("/api/settings/auth/setup", json={"password": "old-password-here"})
    resp = client.post("/api/settings/auth/recover", json={
        "recovery_code": "WRONG-CODE-HERE",
        "new_password": "brand-new-password",
    })
    assert resp.status_code == 401


def test_recovery_code_is_normalized_case_and_whitespace_insensitively():
    """Someone hand-transcribing a recovery code onto paper is exactly the scenario this format is designed for — case/whitespace shouldn't matter."""
    setup = client.post("/api/settings/auth/setup", json={"password": "old-password-here"}).json()
    messy_code = "  " + setup["recovery_code"].lower() + "  "
    resp = client.post("/api/settings/auth/recover", json={"recovery_code": messy_code, "new_password": "brand-new-password"})
    assert resp.status_code == 200


def test_logout_invalidates_the_token():
    setup = client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"}).json()
    token = setup["token"]

    resp = client.get("/api/settings", headers={"X-Settings-Token": token})
    assert resp.status_code == 200

    logout = client.post("/api/settings/auth/logout", headers={"X-Settings-Token": token})
    assert logout.status_code == 200

    resp = client.get("/api/settings", headers={"X-Settings-Token": token})
    assert resp.status_code == 401


def test_expired_session_is_rejected():
    """
    Directly exercises the expiry logic rather than sleeping for a real
    hour: a token that IS present in the session store but whose expiry
    has already passed must be treated exactly like an invalid one.
    """
    import time
    from pantomath.auth import settings_auth

    setup = client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"}).json()
    token = setup["token"]
    assert settings_auth.validate_session(token) is True

    settings_auth._sessions[token] = time.time() - 1  # force it into the past
    assert settings_auth.validate_session(token) is False

    resp = client.get("/api/settings", headers={"X-Settings-Token": token})
    assert resp.status_code == 401


def test_poll_all_sources_route_is_gated():
    """The dynamically-registered (not decorator-based) Sources routes must be gated too, not just the decorator-defined ones."""
    client.post("/api/settings/auth/setup", json={"password": "correct-horse-battery"})
    resp = client.post("/api/sources/poll-all")
    assert resp.status_code == 401
