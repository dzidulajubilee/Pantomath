import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from pantomath.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    yield


def test_fresh_install_has_no_webhooks():
    resp = client.get("/api/webhooks")
    assert resp.status_code == 200
    assert resp.json() == []


def test_add_webhook():
    resp = client.post("/api/webhooks", json={
        "name": "Test Webhook", "url": "http://example.com/hook", "keyword": "ransomware",
    })
    assert resp.status_code == 200
    webhooks = client.get("/api/webhooks").json()
    assert webhooks[0]["name"] == "Test Webhook"
    assert webhooks[0]["enabled"] == 1


def test_add_webhook_rejects_invalid_severity():
    resp = client.post("/api/webhooks", json={
        "name": "Bad", "url": "http://example.com/hook", "min_severity": "extreme",
    })
    assert resp.status_code == 400


def test_toggle_webhook_enabled():
    add = client.post("/api/webhooks", json={"name": "T", "url": "http://example.com/hook"})
    wid = add.json()["id"]
    client.patch(f"/api/webhooks/{wid}", json={"enabled": False})
    webhooks = client.get("/api/webhooks").json()
    assert webhooks[0]["enabled"] == 0


def test_delete_webhook():
    add = client.post("/api/webhooks", json={"name": "T", "url": "http://example.com/hook"})
    wid = add.json()["id"]
    client.delete(f"/api/webhooks/{wid}")
    assert client.get("/api/webhooks").json() == []


def test_edit_webhook_updates_only_provided_fields():
    add = client.post("/api/webhooks", json={
        "name": "Original", "url": "http://example.com/hook", "keyword": "ransomware",
    })
    wid = add.json()["id"]

    resp = client.patch(f"/api/webhooks/{wid}", json={"name": "Renamed"})
    assert resp.status_code == 200

    webhook = client.get("/api/webhooks").json()[0]
    assert webhook["name"] == "Renamed"
    assert webhook["url"] == "http://example.com/hook"  # untouched
    assert webhook["keyword"] == "ransomware"  # untouched


def test_edit_webhook_rejects_invalid_severity():
    add = client.post("/api/webhooks", json={"name": "T", "url": "http://example.com/hook"})
    wid = add.json()["id"]
    resp = client.patch(f"/api/webhooks/{wid}", json={"min_severity": "extreme"})
    assert resp.status_code == 400


def test_edit_nonexistent_webhook_returns_404():
    resp = client.patch("/api/webhooks/does-not-exist", json={"name": "X"})
    assert resp.status_code == 404


class _CapturingHandler(BaseHTTPRequestHandler):
    """Minimal local HTTP server that records the last POST body it received."""
    received_payloads = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CapturingHandler.received_payloads.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass  # silence default request logging


@pytest.fixture
def local_webhook_server():
    _CapturingHandler.received_payloads = []
    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/hook"
    server.shutdown()


def test_webhook_test_endpoint_actually_delivers_http_post(local_webhook_server):
    add = client.post("/api/webhooks", json={"name": "Real Delivery Test", "url": local_webhook_server})
    wid = add.json()["id"]

    resp = client.post(f"/api/webhooks/{wid}/test")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    assert len(_CapturingHandler.received_payloads) == 1
    payload = _CapturingHandler.received_payloads[0]
    assert "Pantomath test alert" in payload["text"]
    assert payload["pantomath"]["title"] == "Pantomath test alert"

    webhook_after = client.get("/api/webhooks").json()[0]
    assert webhook_after["last_status"].startswith("ok")
    assert webhook_after["last_triggered"] > 0


def test_webhook_test_endpoint_reports_failure_for_dead_url():
    add = client.post("/api/webhooks", json={"name": "Dead", "url": "http://127.0.0.1:1/nowhere"})
    wid = add.json()["id"]
    resp = client.post(f"/api/webhooks/{wid}/test")
    assert resp.status_code == 502
