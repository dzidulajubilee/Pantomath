"""
Regression coverage for the IOCs page calendar's date-selection state,
added alongside the calendar feature itself. Same plain-regex-against-
source tradeoff already established in test_ioc_drilldown_persistence.py
for this frontend — cheap, fast, no headless-browser dependency in the
suite, sufficient to catch the specific bug classes this guards against:

- Selecting a calendar day, then switching IOC type, and the date filter
  silently surviving into a chart it no longer applies to (confusing —
  a "CVEs on July 14th" selection shouldn't still be active after
  switching to viewing IPs).
- Selecting a day and having it NOT survive a WebSocket new_items
  auto-refresh, the same class of bug test_ioc_drilldown_persistence.py
  already guards against for iocDrilldown, now also needed for
  iocSelectedDate since the two are independent pieces of state.
- The "Clear date" button existing but not actually clearing the state.
"""
import re
from pathlib import Path

APP_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "app.js").read_text()
CALENDAR_JS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets" / "calendar.js").read_text()
DASHBOARD_HTML = (Path(__file__).resolve().parents[1] / "frontend" / "pages" / "dashboard.html").read_text()


def _function_body(name: str) -> str:
    match = re.search(rf"async function {name}\s*\([^)]*\)\s*\{{", APP_JS)
    assert match, f"could not find `async function {name}(...)` in app.js"
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


def test_ioc_selected_date_is_tracked_at_module_level():
    assert re.search(r"\blet\s+iocSelectedDate\s*=\s*null\s*;", APP_JS), (
        "expected a module-level `iocSelectedDate` variable (same pattern as "
        "iocDrilldown/currentIocType) tracking which calendar day, if any, is selected"
    )


def test_switching_ioc_type_clears_the_selected_date():
    match = re.search(r"btn\.onclick = \(\) => \{ currentIocType = btn\.dataset\.iocType;([^}]*)loadIOCsView\(\); \};", APP_JS)
    assert match, "could not find the .ioc-type-btn onclick handler in app.js"
    assert "iocSelectedDate = null" in match.group(1), (
        "switching IOC type must also clear any selected calendar date — a date "
        "selected while viewing CVEs shouldn't silently keep filtering after "
        "switching to viewing IPs"
    )


def test_calendar_day_click_sets_selected_date_and_reloads():
    assert "onSelectDay" in CALENDAR_JS, "calendar.js must expose an onSelectDay callback for day clicks"
    assert "iocSelectedDate" in _function_body("loadIocCalendar") or "onSelectDay:" in APP_JS, (
        "app.js must wire calendar.js's onSelectDay callback to set iocSelectedDate"
    )
    match = re.search(r"onSelectDay:\s*\(dateStr\)\s*=>\s*\{([^}]*)\}", APP_JS)
    assert match, "could not find the onSelectDay callback wired up in app.js"
    assert "iocSelectedDate" in match.group(1) and "loadIOCsView()" in match.group(1), (
        "the onSelectDay callback must set iocSelectedDate and reload the view"
    )


def test_load_iocs_view_restores_date_drilldown_when_no_ioc_value_drilldown_is_open():
    body = _function_body("loadIOCsView")
    assert "showIocDateArticles(iocSelectedDate" in body, (
        "loadIOCsView() must restore the date-based article drilldown when a day is "
        "selected and no specific-IOC-value drilldown is open — otherwise a selected "
        "day's article list would vanish on the next auto-refresh, the same class of "
        "bug test_ioc_drilldown_persistence.py guards against for iocDrilldown"
    )


def test_clear_date_button_exists_and_clears_state():
    assert 'id="iocClearDateBtn"' in DASHBOARD_HTML, "dashboard.html must have a #iocClearDateBtn to clear the date filter"
    match = re.search(r"iocClearDateBtn'\)\.onclick = \(\) => \{([^}]*)\}", APP_JS)
    assert match, "could not find the #iocClearDateBtn onclick handler in app.js"
    assert "iocSelectedDate = null" in match.group(1), "the clear-date button must actually clear iocSelectedDate"


def test_top_chart_and_summary_requests_include_date_params_when_a_day_is_selected():
    body = _function_body("loadIOCsView")
    assert "dateParams" in body and "/api/iocs?type=" in body, (
        "the top-IOCs chart request in loadIOCsView() must be scoped by the selected "
        "date, not just IOC type — otherwise selecting a calendar day would visually "
        "highlight it but not actually filter the chart next to it"
    )
