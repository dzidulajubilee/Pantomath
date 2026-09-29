"""
0.7.0: "Our stack" (watchlist) and CISA's Known Exploited Vulnerabilities
catalog — matching rules, the Settings API, re-marking stored items when
either changes, marking new items at ingest, and webhook filters.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from pantomath.alerts.matcher import matches_webhook
from pantomath.app import app
from pantomath.database.sqlite import get_db
from pantomath.feeds.scheduler import Scheduler
from pantomath.intelligence.watchlist import compile_watchlist, match_watchlist

client = TestClient(app)
HOUR = 3600
KEV = {"catalogVersion": "test", "vulnerabilities": [
    {"cveID": "CVE-2099-0001", "vendorProject": "Example", "product": "Gateway", "vulnerabilityName": "Example Gateway RCE",
     "dateAdded": "2099-01-02", "dueDate": "2099-01-23", "knownRansomwareCampaignUse": "Known", "shortDescription": "RCE."},
    {"cveID": "CVE-2099-0003", "vendorProject": "Other", "product": "Thing", "vulnerabilityName": "Other bug",
     "dateAdded": "2099-01-05", "dueDate": "2099-01-26", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "Bug."},
]}
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>FortiGate flaw CVE-2099-0001 under attack</title><link>http://x.test/n1</link><guid>n1</guid></item>
<item><title>Unrelated news</title><link>http://x.test/n2</link><guid>n2</guid></item></channel></rss>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        routes = {"/kev.json": (json.dumps(KEV).encode(), "application/json"), "/feed.xml": (RSS, "application/rss+xml"),
                  "/notjson": (b"<html></html>", "text/html")}
        body, ctype = routes.get(self.path, (b"missing", "text/plain"))
        self.send_response(200 if self.path in routes else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture(autouse=True)
async def seeded(fresh_db):
    resp = client.post("/api/settings/auth/setup", json={"password": "test-password-123"})
    client.headers["X-Settings-Token"] = resp.json()["token"]
    now = time.time()
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Advisories', 'http://x.test/s1', 'vulnerability')")
    for iid, title, summary, cves in (
        ("a", "Critical flaw in FortiGate firewalls", "<p>Patch now.</p>", "CVE-2099-0001"),
        ("b", "Vendor ships knowledge base update", "Edge cases fixed.", ""),
        ("c", "APC UPS management card bug", "Affects the network card.", "CVE-2099-0002"),
        ("d", "Apc is a word here", "lowercase apc should not match", ""),
    ):
        await db.execute(
            """INSERT INTO items (id, source_id, guid, title, link, summary, published, fetched_at, severity, cves)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (iid, "s1", iid, title, "http://x.test/" + iid, summary, now - HOUR, now - HOUR, "high", cves),
        )
    await db.commit()
    await db.close()
    yield


def _ids(**params):
    return sorted(i["id"] for i in client.get("/api/items", params=params).json())


# ------------------------------------------------------------- matching rules

def test_matching_is_whole_word_case_insensitive_with_aliases():
    compiled = compile_watchlist([{"name": "FortiGate", "aliases": "FortiOS, Fortinet firewall"}])
    assert match_watchlist(compiled, "fortigate bug", "") == ["FortiGate"]
    assert match_watchlist(compiled, "Patch for FortiOS 7.4", "") == ["FortiGate"]
    assert match_watchlist(compiled, "A Fortinet   firewall issue", "") == ["FortiGate"]  # any whitespace in a phrase
    assert match_watchlist(compiled, "MyFortiGateClone", "") == []                           # not a substring match


def test_short_all_capital_terms_match_exactly():
    compiled = compile_watchlist([{"name": "APC", "aliases": ""}, {"name": "Edge", "aliases": ""}])
    assert match_watchlist(compiled, "APC UPS", "") == ["APC"]
    assert match_watchlist(compiled, "apc is a word", "") == []
    assert match_watchlist(compiled, "knowledge base", "") == []
    assert match_watchlist(compiled, "Microsoft Edge", "<b>x</b>") == ["Edge"]


def test_summary_html_is_ignored():
    compiled = compile_watchlist([{"name": "img", "aliases": ""}])
    assert match_watchlist(compiled, "title", '<img src="x">text') == []


# --------------------------------------------------------------- watchlist API

def test_adding_an_entry_marks_stored_items_and_can_be_filtered():
    resp = client.post("/api/watchlist", json={"name": "FortiGate", "aliases": "FortiOS"})
    assert resp.status_code == 200 and resp.json()["items_marked"] == 1
    client.post("/api/watchlist", json={"name": "APC"})
    assert _ids(affects_us=True) == ["a", "c"]
    assert client.get("/api/items/count", params={"affects_us": True}).json() == {"total": 2}
    item = next(i for i in client.get("/api/items").json() if i["id"] == "a")
    assert item["watch_hits"] == ["FortiGate"]
    listed = {e["name"]: e["items"] for e in client.get("/api/watchlist").json()}
    assert listed == {"APC": 1, "FortiGate": 1}


def test_editing_and_removing_entries_rematch_everything():
    wid = client.post("/api/watchlist", json={"name": "Gateway"}).json()["id"]
    assert _ids(affects_us=True) == []
    assert client.patch(f"/api/watchlist/{wid}", json={"aliases": "firewalls"}).json()["items_marked"] == 1
    assert _ids(affects_us=True) == ["a"]
    assert client.delete(f"/api/watchlist/{wid}").json()["items_marked"] == 0
    assert _ids(affects_us=True) == []


def test_watchlist_validation():
    assert client.post("/api/watchlist", json={"name": "  "}).status_code == 400
    assert client.post("/api/watchlist", json={"name": "A,B"}).status_code == 400
    assert client.post("/api/watchlist", json={"name": "OK", "aliases": "x"}).status_code == 400  # 1-char term
    assert client.post("/api/watchlist", json={"name": "Cisco"}).status_code == 200
    assert client.post("/api/watchlist", json={"name": "cisco"}).status_code == 409


def test_watchlist_needs_the_settings_password():
    anonymous = TestClient(app)
    assert anonymous.get("/api/watchlist").status_code == 401
    assert anonymous.post("/api/watchlist", json={"name": "X1"}).status_code == 401
    assert anonymous.post("/api/kev/refresh").status_code == 401


def test_public_endpoints_get_counts_not_the_watchlist():
    # An item shows which entry it matched (that's the reason it's marked),
    # but the list itself (what else the organisation runs) never leaves
    # Settings.
    client.post("/api/watchlist", json={"name": "FortiGate"})
    client.post("/api/watchlist", json={"name": "SecretBox"})
    overview = client.get("/api/overview")
    assert overview.json()["affects_us"] == {"items": 1, "exploited": 0, "watchlist": 2}
    for body in (overview.text, client.get("/api/items").text, client.get("/api/analytics").text):
        assert "SecretBox" not in body


# --------------------------------------------------------------------- KEV

def test_kev_refresh_marks_exploited_items(server):
    client.patch("/api/kev/settings", json={"url": f"{server}/kev.json"})
    status = client.post("/api/kev/refresh").json()
    assert (status["count"], status["error"]) == (2, "") and status["updated_at"]
    assert _ids(exploited=True) == ["a"]
    assert next(i for i in client.get("/api/items").json() if i["id"] == "a")["kev_cves"] == ["CVE-2099-0001"]
    detail = client.get("/api/kev", params={"cves": "cve-2099-0001,CVE-2099-9999"}).json()
    assert [(d["cve"], d["due_date"], d["ransomware"]) for d in detail] == [("CVE-2099-0001", "2099-01-23", "Known")]
    client.post("/api/watchlist", json={"name": "FortiGate"})
    assert client.get("/api/overview").json()["affects_us"]["exploited"] == 1


def test_a_failed_refresh_keeps_the_previous_catalog(server):
    client.patch("/api/kev/settings", json={"url": f"{server}/kev.json"})
    client.post("/api/kev/refresh")
    client.patch("/api/kev/settings", json={"url": f"{server}/notjson"})
    status = client.post("/api/kev/refresh").json()
    assert status["error"] == "the URL did not return JSON" and status["count"] == 2
    client.patch("/api/kev/settings", json={"url": f"{server}/missing"})
    assert client.post("/api/kev/refresh").json()["error"] == "HTTP 404 Not Found"
    assert _ids(exploited=True) == ["a"]


def test_kev_settings_validation():
    assert client.patch("/api/kev/settings", json={"url": "file:///etc/passwd"}).status_code == 400
    assert client.patch("/api/kev/settings", json={"enabled": False}).json()["enabled"] is False


# ------------------------------------------------------ ingest and webhooks

async def test_new_items_are_marked_as_they_arrive(server):
    client.post("/api/watchlist", json={"name": "FortiGate"})
    client.patch("/api/kev/settings", json={"url": f"{server}/kev.json"})
    client.post("/api/kev/refresh")
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('live', 'Live', ?, 'news')", (f"{server}/feed.xml",))
    await db.commit()
    cur = await db.execute("SELECT * FROM sources WHERE id = 'live'")
    source = dict(await cur.fetchone())

    async def broadcast(_):
        pass

    await Scheduler(broadcast).poll_source(db, source)
    cur = await db.execute("SELECT title, watch_hits, kev_cves FROM items WHERE source_id = 'live' ORDER BY title")
    rows = [tuple(r) for r in await cur.fetchall()]
    await db.close()
    assert rows == [("FortiGate flaw CVE-2099-0001 under attack", "FortiGate", "CVE-2099-0001"), ("Unrelated news", "", "")]


def test_webhook_filters_for_our_stack_and_exploited():
    ours = {"watch_hits": ["FortiGate"], "kev_cves": [], "severity": "low"}
    exploited = {"watch_hits": [], "kev_cves": ["CVE-2099-0001"], "severity": "low"}
    assert matches_webhook({"only_affects_us": 1}, ours) and not matches_webhook({"only_affects_us": 1}, exploited)
    assert matches_webhook({"only_exploited": 1}, exploited) and not matches_webhook({"only_exploited": 1}, ours)
    wid = client.post("/api/webhooks", json={"name": "n", "url": "http://x.test/h", "only_exploited": True}).json()["id"]
    hook = next(w for w in client.get("/api/webhooks").json() if w["id"] == wid)
    assert (hook["only_exploited"], hook["only_affects_us"]) == (1, 0)
    client.patch(f"/api/webhooks/{wid}", json={"only_affects_us": True})
    assert next(w for w in client.get("/api/webhooks").json() if w["id"] == wid)["only_affects_us"] == 1
