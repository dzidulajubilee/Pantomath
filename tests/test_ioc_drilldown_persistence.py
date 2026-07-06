"""
Regression coverage for a real reported bug: opening the "Articles
containing…" drilldown on the IOCs page, then having it silently close
itself the next time the view auto-refreshes — a WebSocket `new_items`
broadcast (a feed poll finding new items) or the 30s fallback poll in
`init()`, both of which call `VIEW_LOADERS[currentView()]?.()`, i.e.
`loadIOCsView()` while the IOCs page is open.

`loadIOCsView()` used to unconditionally hide `#iocArticlesPanel` on
every call. That meant the exact IOC a user had drilled into evaporated
on the very next feed poll, with no user action and no error — the
"page refreshed and the [drilldown] feed goes back" behavior reported.

Fixed by tracking the open drilldown at module level (`iocDrilldown`)
and restoring it in `loadIOCsView()` when the IOC type hasn't changed,
instead of always closing the panel. Explicitly switching IOC type
still closes it, since that's a genuine context change, not an
auto-refresh.

Verified end-to-end against the real served files with a real DOM
(jsdom, outside this suite): clicked an IOC to open the drilldown,
simulated a `new_items` WebSocket broadcast, and confirmed the panel
and its content survive. Also confirmed the identical scenario
reproduces the bug (panel silently closes) when run against the
pre-fix file, so the scenario genuinely catches this class of
regression.

These are plain regex/text checks against the source, not a real JS
runtime — same tradeoff already made in
`test_frontend_view_consistency.py` for this frontend (cheap, fast, no
headless-browser dependency in the suite itself), sufficient to catch
someone reintroducing the unconditional-hide behavior or removing the
drilldown-restore logic.
"""
import re
from pathlib import Path

APP_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "app.js").read_text()


def _function_body(name: str) -> str:
    match = re.search(rf"async function {name}\s*\([^)]*\)\s*\{{", APP_JS)
    assert match, f"could not find `async function {name}(...)` in app.js"
    start = match.end() - 1  # index of the opening brace
    depth = 0
    for i in range(start, len(APP_JS)):
        if APP_JS[i] == "{":
            depth += 1
        elif APP_JS[i] == "}":
            depth -= 1
            if depth == 0:
                return APP_JS[start:i + 1]
    raise AssertionError(f"could not find the end of `{name}`'s function body")


def test_ioc_drilldown_state_is_tracked_at_module_level():
    assert re.search(r"\blet\s+iocDrilldown\s*=\s*null\s*;", APP_JS), (
        "expected a module-level `iocDrilldown` variable (same pattern as "
        "currentIocType/liveCurrentPage) tracking which IOC drilldown, if any, is open"
    )


def test_show_ioc_articles_records_the_open_drilldown():
    body = _function_body("showIocArticles")
    assert re.search(r"iocDrilldown\s*=\s*\{\s*type:\s*iocType,\s*value\s*\}", body), (
        "showIocArticles() must record { type, value } into iocDrilldown so a later "
        "auto-refresh of the IOCs view knows a drilldown was open and what to restore"
    )


def test_load_iocs_view_restores_a_still_relevant_drilldown_instead_of_always_closing_it():
    body = _function_body("loadIOCsView")

    assert re.search(
        r"if\s*\(\s*iocDrilldown\s*&&\s*iocDrilldown\.type\s*===\s*currentIocType\s*\)", body
    ), (
        "loadIOCsView() must check for a still-relevant open drilldown (matching the "
        "currently selected IOC type) before deciding whether to close the panel — "
        "this is what survives a WebSocket new_items broadcast or the 30s poll"
    )
    assert "showIocArticles(iocDrilldown.type, iocDrilldown.value" in body, (
        "loadIOCsView() must re-render the previously open drilldown (refreshing its "
        "content) rather than silently leaving it hidden"
    )

    # The exact shape of the original bug: hiding the panel with no condition guarding
    # it at all. Guard against this regressing back in, in any form, by requiring the
    # only hide-panel line left in the function to be reachable exclusively via the
    # `else` branch of the check above (i.e. never as an unconditional statement) —
    # checked by requiring no `}` (block close) between the `else {` and the hide
    # line, i.e. they're in the same block with nothing else closing in between.
    hide_panel_matches = list(re.finditer(r"document\.getElementById\('iocArticlesPanel'\)\.style\.display = 'none';", body))
    assert len(hide_panel_matches) == 1, (
        "expected exactly one place in loadIOCsView() that hides the drilldown panel"
    )
    else_match = re.search(r"\}\s*else\s*\{", body)
    assert else_match, "expected an `else { ... }` branch pairing with the iocDrilldown check"
    between = body[else_match.end():hide_panel_matches[0].start()]
    assert "}" not in between, (
        "the panel-hiding line must live directly inside the `else` branch of the "
        "iocDrilldown-matches-currentIocType check, not run unconditionally — "
        "this is the exact shape of the original bug"
    )


def test_switching_ioc_type_still_clears_the_drilldown():
    match = re.search(r"btn\.onclick = \(\) => \{ currentIocType = btn\.dataset\.iocType;([^}]*)loadIOCsView\(\); \};", APP_JS)
    assert match, "could not find the .ioc-type-btn onclick handler in app.js"
    assert "iocDrilldown = null" in match.group(1), (
        "switching IOC type is a genuine context change (a different chart entirely) "
        "and should still clear any open drilldown, unlike an auto-refresh"
    )
