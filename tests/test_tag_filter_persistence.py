"""
Regression coverage for a real reported bug: filtering the Vendors or
Threat Actors page down to one chip (e.g. clicking a specific threat
actor), then having the selection silently reset to the first chip again
the next time the view auto-refreshes — a WebSocket `new_items`
broadcast (a feed poll finding new items) or the 30s fallback poll in
`init()`, both of which call `VIEW_LOADERS[currentView()]?.()`, i.e.
`loadVendors()` / `loadThreatActors()` while that page is open.

Both loaders used to unconditionally rebuild the chip list and then
always click the FIRST chip (`chipsEl.querySelector('.tag-chip').click()`)
with no memory of what the user had actually selected — same bug class
already fixed for the IOCs page's drilldown panel (see
`tests/test_ioc_drilldown_persistence.py`), just not caught here at the
time.

Fixed by tracking the selected vendor/actor at module level
(`selectedVendor` / `selectedActor`, same pattern as `iocDrilldown` /
`currentIocType`) and re-selecting it after a refresh if it still exists
in the (possibly changed) tag list, only falling back to the first chip
when there was no prior selection or the previously selected tag has
disappeared entirely.

Plain regex/text checks against the source, not a real JS runtime — same
tradeoff already made for `test_ioc_drilldown_persistence.py` and
`test_ioc_calendar_state.py` for this frontend.
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


def test_selected_vendor_and_actor_are_tracked_at_module_level():
    assert re.search(r"\blet\s+selectedVendor\s*=\s*null\s*;", APP_JS), (
        "expected a module-level `selectedVendor` variable (same pattern as "
        "iocDrilldown/currentIocType) tracking which vendor chip, if any, is selected"
    )
    assert re.search(r"\blet\s+selectedActor\s*=\s*null\s*;", APP_JS), (
        "expected a module-level `selectedActor` variable tracking which "
        "threat-actor chip, if any, is selected"
    )


def test_vendor_chip_click_handler_records_the_selection():
    body = _function_body("loadVendors")
    assert re.search(r"selectedVendor\s*=\s*chip\.dataset\.vendor", body), (
        "the vendor chip's onclick handler must record the selection into "
        "selectedVendor so a later auto-refresh knows what to restore"
    )


def test_actor_chip_click_handler_records_the_selection():
    body = _function_body("loadThreatActors")
    assert re.search(r"selectedActor\s*=\s*chip\.dataset\.actor", body), (
        "the actor chip's onclick handler must record the selection into "
        "selectedActor so a later auto-refresh knows what to restore"
    )


def test_load_vendors_restores_the_previous_selection_instead_of_always_picking_first():
    body = _function_body("loadVendors")
    assert "chipsEl.querySelector('.tag-chip').click()" not in body, (
        "loadVendors() must not unconditionally click the first chip on every call — "
        "that's exactly the bug: it silently discards the user's selection on every "
        "auto-refresh"
    )
    assert re.search(r"selectedVendor\s*&&\s*chipsEl\.querySelector", body), (
        "loadVendors() must check for a still-relevant previous selection before "
        "falling back to the first chip"
    )


def test_load_threat_actors_restores_the_previous_selection_instead_of_always_picking_first():
    body = _function_body("loadThreatActors")
    assert "chipsEl.querySelector('.tag-chip').click()" not in body, (
        "loadThreatActors() must not unconditionally click the first chip on every "
        "call — that's exactly the bug reported: filtering to a threat actor, then "
        "having a new feed item arrive resets the filter"
    )
    assert re.search(r"selectedActor\s*&&\s*chipsEl\.querySelector", body), (
        "loadThreatActors() must check for a still-relevant previous selection before "
        "falling back to the first chip"
    )


def test_empty_tag_lists_clear_the_stale_selection():
    # If a page genuinely has zero vendors/actors left (e.g. after a
    # restore to an empty database), the stale selection must be cleared
    # rather than silently kept around to reference a chip that no longer
    # exists.
    vendors_body = _function_body("loadVendors")
    assert "selectedVendor = null;" in vendors_body
    actors_body = _function_body("loadThreatActors")
    assert "selectedActor = null;" in actors_body
