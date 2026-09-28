"""
Regression coverage for a real, user-reported bug: the Download backup
button used `window.location.href = '/api/backup'` to trigger the
download. window.fetch() calls go through the token-injecting wrapper
(installSettingsAuthFetchWrapper in app.js), but a raw page navigation
via location.href does not and structurally never can — there is no way
to attach a custom header to a browser navigation. Since /api/backup is
a protected endpoint, this meant a properly-logged-in user clicking
"Download backup" got 401'd, and the browser navigated the ENTIRE app
away to display the raw JSON error page in its place — matching exactly
what the user saw and described ("refreshed, locked, unlocked... still"
not working, because there was no app left on screen to interact with).

Fixed with the same fetch-as-blob + synthetic <a download> click pattern
already used by downloadSourcesExport(). Verified for real with a jsdom
test driving the actual login + click flow against a live server (not
included here — see the ad-hoc jsdom scripts this project uses for
this kind of behavioral check, per CONTRIBUTING.md's documented
approach) — confirmed the request comes back 200 (proving the token was
attached) and the app's own DOM stays intact afterward.

This file checks the general SHAPE of the bug, not just this one
button: no `location.href` assignment to any /api/ path should ever
exist, since that pattern can never carry the auth header any protected
endpoint needs.
"""
import re
from pathlib import Path

APP_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "app.js").read_text()


def test_no_raw_navigation_to_any_api_endpoint():
    assert not re.search(r"location\.href\s*=\s*['\"]/api/", APP_JS), (
        "found a raw `location.href = '/api/...'` navigation — this bypasses the settings-auth "
        "fetch wrapper entirely (no way to attach a custom header to a page navigation), so any "
        "protected endpoint reached this way will 401 for a properly-logged-in user and navigate "
        "the whole app away to a raw JSON error page instead of doing the intended action"
    )


def test_backup_button_uses_an_authenticated_fetch():
    match = re.search(r"document\.getElementById\('backupBtn'\)\.onclick\s*=\s*async\s*\(\)\s*=>\s*\{", APP_JS)
    assert match, "expected an async onclick handler on backupBtn (fetch-based, not a bare navigation assignment)"

    start = match.end() - 1
    depth = 0
    end = None
    for i in range(start, len(APP_JS)):
        if APP_JS[i] == "{":
            depth += 1
        elif APP_JS[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = APP_JS[start:end]

    assert "fetch('/api/backup')" in body, "backupBtn must fetch /api/backup (through the token wrapper), not navigate to it"
    assert "res.status === 401" in body, "must handle an expired/missing session by re-showing the lock screen, not leaving the user stuck"
    assert "res.blob()" in body, "must download the actual file content as a blob, since a fetch response (unlike a navigation) needs to be explicitly turned into a downloadable file"
    assert ".download = " in body, "must trigger a real file download (via a synthetic <a download> element), not just fetch the data and discard it"
