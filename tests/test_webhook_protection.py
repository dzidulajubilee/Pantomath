import pytest
from fastapi.testclient import TestClient

from pantomath.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


def _add_protected(key="hunter2", url="http://example.com/hook"):
    resp = client.post("/api/webhooks", json={"name": "Protected", "url": url, "key": key})
    assert resp.status_code == 200
    return resp.json()["id"]


def test_add_webhook_without_a_key_behaves_exactly_as_before():
    resp = client.post("/api/webhooks", json={"name": "Plain", "url": "http://example.com/hook"})
    assert resp.status_code == 200
    webhook = client.get("/api/webhooks").json()[0]
    assert webhook["protected"] == 0
    assert webhook["url"] == "http://example.com/hook"  # full URL, unmasked


def test_add_webhook_rejects_a_blank_key():
    resp = client.post("/api/webhooks", json={"name": "Bad", "url": "http://example.com/hook", "key": "   "})
    assert resp.status_code == 400


def test_listing_masks_the_url_for_a_protected_webhook():
    _add_protected(url="https://hooks.slack.com/services/T000/B000/supersecrettoken")
    webhook = client.get("/api/webhooks").json()[0]
    assert webhook["protected"] == 1
    assert webhook["url"] != "https://hooks.slack.com/services/T000/B000/supersecrettoken"
    assert "supersecrettoken" not in webhook["url"]


def test_listing_never_leaks_key_hash_or_salt_or_attempt_counters():
    _add_protected()
    webhook = client.get("/api/webhooks").json()[0]
    for leaky_field in ("key_hash", "key_salt", "key_fail_count", "key_locked_until"):
        assert leaky_field not in webhook


def test_reveal_unprotected_webhook_needs_no_key():
    resp = client.post("/api/webhooks", json={"name": "Plain", "url": "http://example.com/hook"})
    wid = resp.json()["id"]
    reveal = client.post(f"/api/webhooks/{wid}/reveal", json={"key": ""})
    assert reveal.status_code == 200
    assert reveal.json()["url"] == "http://example.com/hook"


def test_reveal_protected_webhook_with_correct_key_returns_real_url():
    wid = _add_protected(key="hunter2", url="http://example.com/real-hook")
    reveal = client.post(f"/api/webhooks/{wid}/reveal", json={"key": "hunter2"})
    assert reveal.status_code == 200
    assert reveal.json()["url"] == "http://example.com/real-hook"


def test_reveal_protected_webhook_with_wrong_key_is_rejected():
    wid = _add_protected(key="hunter2")
    reveal = client.post(f"/api/webhooks/{wid}/reveal", json={"key": "wrong"})
    assert reveal.status_code == 401


def test_reveal_nonexistent_webhook_404s():
    resp = client.post("/api/webhooks/does-not-exist/reveal", json={"key": "anything"})
    assert resp.status_code == 404


def test_editing_a_protected_webhook_without_the_key_is_rejected():
    wid = _add_protected(key="hunter2")
    resp = client.patch(f"/api/webhooks/{wid}", json={"name": "Renamed"})
    assert resp.status_code == 401
    # and the change did NOT apply
    assert client.get("/api/webhooks").json()[0]["name"] == "Protected"


def test_editing_a_protected_webhook_with_the_correct_key_succeeds():
    wid = _add_protected(key="hunter2")
    resp = client.patch(f"/api/webhooks/{wid}", json={"name": "Renamed", "key": "hunter2"})
    assert resp.status_code == 200
    assert client.get("/api/webhooks").json()[0]["name"] == "Renamed"


def test_editing_an_unprotected_webhook_needs_no_key():
    resp = client.post("/api/webhooks", json={"name": "Plain", "url": "http://example.com/hook"})
    wid = resp.json()["id"]
    resp = client.patch(f"/api/webhooks/{wid}", json={"name": "Renamed"})
    assert resp.status_code == 200


def test_adding_protection_to_a_previously_unprotected_webhook_needs_no_prior_key():
    resp = client.post("/api/webhooks", json={"name": "Plain", "url": "http://example.com/hook"})
    wid = resp.json()["id"]
    resp = client.patch(f"/api/webhooks/{wid}", json={"set_key": "new-key"})
    assert resp.status_code == 200

    webhook = client.get("/api/webhooks").json()[0]
    assert webhook["protected"] == 1
    # now that it's protected, the new key is required to reveal/edit it
    assert client.post(f"/api/webhooks/{wid}/reveal", json={"key": "new-key"}).status_code == 200
    assert client.post(f"/api/webhooks/{wid}/reveal", json={"key": "wrong"}).status_code == 401


def test_changing_the_key_on_a_protected_webhook_requires_the_old_key():
    wid = _add_protected(key="old-key")
    resp = client.patch(f"/api/webhooks/{wid}", json={"set_key": "new-key"})  # no `key` supplied
    assert resp.status_code == 401

    resp = client.patch(f"/api/webhooks/{wid}", json={"key": "old-key", "set_key": "new-key"})
    assert resp.status_code == 200

    assert client.post(f"/api/webhooks/{wid}/reveal", json={"key": "old-key"}).status_code == 401
    assert client.post(f"/api/webhooks/{wid}/reveal", json={"key": "new-key"}).status_code == 200


def test_removing_protection_requires_the_current_key():
    wid = _add_protected(key="hunter2", url="http://example.com/real-hook")

    resp = client.patch(f"/api/webhooks/{wid}", json={"remove_protection": True})  # no key
    assert resp.status_code == 401

    resp = client.patch(f"/api/webhooks/{wid}", json={"key": "hunter2", "remove_protection": True})
    assert resp.status_code == 200

    webhook = client.get("/api/webhooks").json()[0]
    assert webhook["protected"] == 0
    assert webhook["url"] == "http://example.com/real-hook"  # unmasked now that protection is off


def test_deleting_a_protected_webhook_needs_no_key():
    """The stated fallback for a lost key: delete and recreate, no gate on delete itself."""
    wid = _add_protected(key="hunter2")
    resp = client.delete(f"/api/webhooks/{wid}")
    assert resp.status_code == 200
    assert client.get("/api/webhooks").json() == []


def test_testing_a_protected_webhook_needs_no_key():
    """Test-fire doesn't expose the URL to the caller, so it isn't gated."""
    wid = _add_protected(key="hunter2", url="http://127.0.0.1:1/nowhere")
    resp = client.post(f"/api/webhooks/{wid}/test")
    assert resp.status_code == 502  # dead URL, but crucially NOT a 401 — no key was required to attempt it


def test_repeated_wrong_keys_lock_out_further_attempts():
    wid = _add_protected(key="hunter2")
    for _ in range(5):
        resp = client.post(f"/api/webhooks/{wid}/reveal", json={"key": "wrong"})
        assert resp.status_code == 401
    # even the CORRECT key is now rejected while locked out
    locked = client.post(f"/api/webhooks/{wid}/reveal", json={"key": "hunter2"})
    assert locked.status_code == 401
    assert "attempts" in locked.json()["detail"].lower()
