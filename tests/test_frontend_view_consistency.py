"""
Static consistency checks across the frontend's view-routing wiring.

These exist because of a real shipped bug: 'iocs' was registered in
VIEW_LOADERS (so its data loaded correctly) and had a nav button and an
HTML section, but was missing from the VIEWS array — which is what
navigateTo() iterates to decide which section gets the `active` CSS
class. The result: the IOCs view's charts populated correctly, but the
section itself stayed hidden via `display:none` forever, with zero JS
errors thrown — silent and easy to miss without literally clicking
through every nav item after every change to app.js.

These are plain text/regex checks against the source files, not a real
JS runtime (no headless browser dependency in the test suite) — cheap,
fast, and sufficient to catch this specific class of drift.
"""
import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def _extract_js_array(js_source: str, array_name: str) -> set[str]:
    match = re.search(rf"const {array_name}\s*=\s*\[(.*?)\];", js_source, re.DOTALL)
    assert match, f"could not find `const {array_name} = [...]` in app.js"
    return set(re.findall(r"'([\w-]+)'", match.group(1)))


def _extract_view_loader_keys(js_source: str) -> set[str]:
    match = re.search(r"const VIEW_LOADERS\s*=\s*\{(.*?)\n\};", js_source, re.DOTALL)
    assert match, "could not find `const VIEW_LOADERS = {...}` in app.js"
    return set(re.findall(r"'([\w-]+)':", match.group(1)))


def _extract_nav_data_views(html_source: str) -> set[str]:
    return set(re.findall(r'data-view="([\w-]+)"', html_source))


def _extract_view_section_ids(html_source: str) -> set[str]:
    return {m.replace("view-", "", 1) for m in re.findall(r'id="(view-[\w-]+)"', html_source)}


def test_every_view_loader_is_in_the_views_array():
    """
    The exact bug this guards against: a view registered in VIEW_LOADERS
    but missing from VIEWS never becomes visible when navigated to,
    even though its loader runs and populates its content underneath.
    """
    js_source = (FRONTEND / "widgets" / "app.js").read_text()
    views = _extract_js_array(js_source, "VIEWS")
    loader_keys = _extract_view_loader_keys(js_source)
    missing = loader_keys - views
    assert not missing, f"views registered in VIEW_LOADERS but missing from VIEWS (will never become visible): {missing}"


def test_every_nav_button_view_is_in_the_views_array():
    js_source = (FRONTEND / "widgets" / "app.js").read_text()
    html_source = (FRONTEND / "pages" / "dashboard.html").read_text()
    views = _extract_js_array(js_source, "VIEWS")
    nav_views = _extract_nav_data_views(html_source)
    missing = nav_views - views
    assert not missing, f"nav buttons point at views missing from VIEWS: {missing}"


def test_every_view_in_views_array_has_a_matching_html_section():
    js_source = (FRONTEND / "widgets" / "app.js").read_text()
    html_source = (FRONTEND / "pages" / "dashboard.html").read_text()
    views = _extract_js_array(js_source, "VIEWS")
    sections = _extract_view_section_ids(html_source)
    missing = views - sections
    assert not missing, f"views in VIEWS have no matching id=\"view-<name>\" HTML section: {missing}"


def test_every_view_in_views_array_has_a_nav_button():
    js_source = (FRONTEND / "widgets" / "app.js").read_text()
    html_source = (FRONTEND / "pages" / "dashboard.html").read_text()
    views = _extract_js_array(js_source, "VIEWS")
    nav_views = _extract_nav_data_views(html_source)
    missing = views - nav_views
    assert not missing, f"views in VIEWS have no nav button pointing at them: {missing}"
