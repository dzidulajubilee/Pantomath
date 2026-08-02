"""
Regression coverage for a real reported bug: clicking "Restore from
file..." and having it fail with a confusing, opaque error —

    Restore failed: Unexpected token '<', "<html> h"... is not valid JSON

This happens whenever something between the browser and the Pantomath
app returns a non-JSON error body for the /api/restore POST — most
commonly a reverse proxy (nginx) rejecting the upload with its own
generic HTML error page (e.g. a 413 when the proxy's body-size limit is
below Pantomath's own) before the request ever reaches the app. The old
handler called `await res.json()` unconditionally, which throws a raw
SyntaxError on non-JSON input; that SyntaxError's message ("Unexpected
token '<'...") is what a user is left staring at, with no indication of
what actually happened.

Fixed by reading the response as text first and parsing it manually,
falling back to an explicit, legible message (including the HTTP status,
and a specific hint for 413) instead of letting a JSON.parse SyntaxError
propagate to the user as the entire error message.

Plain regex/text checks against the source, not a real JS runtime — same
tradeoff already made throughout this test suite for this dependency-free
frontend (see test_ioc_drilldown_persistence.py, test_xss_link_sanitization.py).
"""
import re
from pathlib import Path

APP_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "app.js").read_text()


def _restore_handler_body() -> str:
    match = re.search(
        r"document\.getElementById\('restoreFileInput'\)\.onchange = async \(e\) => \{",
        APP_JS,
    )
    assert match, "could not find the restoreFileInput onchange handler in app.js"
    start = match.end() - 1
    depth = 0
    for i in range(start, len(APP_JS)):
        if APP_JS[i] == "{":
            depth += 1
        elif APP_JS[i] == "}":
            depth -= 1
            if depth == 0:
                return APP_JS[start:i + 1]
    raise AssertionError("could not find the end of the restore handler")


def test_restore_handler_does_not_call_res_json_directly():
    body = _restore_handler_body()
    assert "await res.json()" not in body, (
        "the restore handler must not call res.json() directly on the fetch response — "
        "a non-JSON error body (e.g. an HTML error page from a reverse proxy) makes this "
        "throw an opaque 'Unexpected token' SyntaxError instead of a legible error message"
    )


def test_restore_handler_reads_response_as_text_and_parses_manually():
    body = _restore_handler_body()
    assert "await res.text()" in body, (
        "the restore handler must read the response as text first, so a non-JSON body "
        "can be handled explicitly instead of crashing on res.json()"
    )
    assert re.search(r"JSON\.parse\(\s*raw\s*\)", body), (
        "the restore handler must attempt to parse the text response as JSON itself, "
        "with a catch/fallback path for when it isn't JSON"
    )


def test_restore_handler_gives_a_legible_message_for_a_non_json_response():
    body = _restore_handler_body()
    assert "res.status" in body, (
        "a non-JSON response must be reported with its actual HTTP status, not just a "
        "raw parse-error message"
    )
