"""
Regression coverage for the calendar's month/year navigation, added
alongside that feature. Same regex-against-source tradeoff already used
by test_ioc_drilldown_persistence.py / test_ioc_calendar_state.py.

Verified behaviorally (not just via these regexes) using a real jsdom
session against a live server before this was written — confirmed real
prev/next month, prev/next year, the jump popover, boundary disabling,
and that a deliberately-delayed stale response can't visually clobber a
faster newer one. These tests exist to keep that contract from silently
regressing later, cheaply, without needing jsdom in the normal suite.
"""
import re
from pathlib import Path

APP_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "app.js").read_text()
CALENDAR_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "calendar.js").read_text()


def _function_body(name: str, is_async: bool = True) -> str:
    prefix = r"async function" if is_async else r"function"
    match = re.search(rf"{prefix} {name}\s*\([^)]*\)\s*\{{", APP_JS)
    assert match, f"could not find `{prefix} {name}(...)` in app.js"
    start = match.end() - 1
    depth = 0
    for i in range(start, len(APP_JS)):
        if APP_JS[i] == "{":
            depth += 1
        elif APP_JS[i] == "}":
            depth -= 1
            if depth == 0:
                return APP_JS[start:i + 1]
    raise AssertionError(f"could not find the end of `{name}`'s function body")


def test_loadIocCalendar_has_a_request_token_race_guard():
    assert re.search(r"let\s+_iocCalendarRequestToken\s*=\s*0", APP_JS), "expected a module-level request-token counter"
    body = _function_body("loadIocCalendar")
    assert "++_iocCalendarRequestToken" in body, "loadIocCalendar must claim a fresh token at the start of each call"
    assert re.search(r"if\s*\(\s*myToken\s*!==\s*_iocCalendarRequestToken\s*\)\s*return", body), (
        "loadIocCalendar must bail out if a newer request has superseded this one — "
        "without this, a slow stale response can render over a faster newer one"
    )


def test_calendar_navigation_is_bounded_by_real_data_range():
    assert "/api/items/range" in APP_JS, "calendar navigation should be bounded using the real earliest/latest item dates"
    assert "minYear" in APP_JS and "maxYear" in APP_JS, "expected minYear/maxYear bounds to be computed and passed to the calendar"


def test_onNavigate_clamps_and_validates_before_using_year_month():
    match = re.search(r"onNavigate:\s*\(year,\s*month\)\s*=>\s*\{([^}]*)\}", APP_JS)
    assert match, "could not find the onNavigate handler passed into renderCalendarHeatmap"
    body = match.group(1)
    assert "parseInt(year" in body and "parseInt(month" in body, "year/month must be parsed as integers, not trusted as-is"
    assert "Number.isInteger" in body, "non-numeric year/month must be rejected before use"
    assert "Math.min(maxYear" in body and "Math.min(12" in body, "year/month must be clamped into valid bounds before use"


def test_calendar_widget_registers_one_delegated_global_listener_not_one_per_render():
    assert "_calendarGlobalListenerAttached" in CALENDAR_JS, (
        "expected a guard flag preventing the document-level click/keydown listeners from being "
        "re-registered on every render — renderCalendarHeatmap runs on every single navigation, so "
        "an unguarded addEventListener here would leak a new listener on every month/year change"
    )
    assert CALENDAR_JS.count("document.addEventListener('click'") <= 1, (
        "expected at most one document click listener registration in the whole file"
    )


def test_jump_popover_year_options_are_bounded_not_free_text():
    assert "<select class=\"cal-jump-year\">" in CALENDAR_JS, "expected the year picker to be a <select>, not a free-text input"
    assert "yearOptions" in CALENDAR_JS and "for (let y = maxYear; y >= minYear; y--)" in CALENDAR_JS, (
        "year options must be generated from the numeric [minYear, maxYear] bound, not arbitrary user text"
    )
