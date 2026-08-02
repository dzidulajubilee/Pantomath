"""
Regression coverage for a real, confirmed XSS: item.link (sourced from
external RSS/Atom feed content, or a restored database backup — see
pantomath/database/restore.py) was interpolated directly into
href="${i.link}" with no escaping in three places. escapeHtml() alone
would NOT have been sufficient even if used, since it only escapes &, <,
> for text-node content — it deliberately leaves quote characters
untouched, so a value containing a literal " still breaks out of an
href="..." attribute. Confirmed exploitable via a real jsdom
reproduction before this fix: a crafted link value injected a live
onmouseover handler onto the rendered <a> tag; a javascript: URI link
executed on click. Both close over safeHref()/escapeAttr() in app.js.

Same regex-against-source tradeoff as the other frontend contract tests
in this suite (test_ioc_drilldown_persistence.py etc.) — these check the
vulnerable pattern can't silently reappear, and that the sanitizing
helpers still do what they claim to.
"""
import re
from pathlib import Path

FRONTEND_WIDGETS = (Path(__file__).resolve().parents[1] / "frontend" / "widgets")
APP_JS = (FRONTEND_WIDGETS / "app.js").read_text()
FEED_LIST_JS = (FRONTEND_WIDGETS / "feed-list.js").read_text()

ALL_JS_FILES = {p.name: p.read_text() for p in FRONTEND_WIDGETS.glob("*.js")}
ALL_JS_FILES["dashboard.html"] = (Path(__file__).resolve().parents[1] / "frontend" / "pages" / "dashboard.html").read_text()


def test_no_raw_item_link_interpolated_directly_into_an_href_attribute():
    # The specific vulnerable pattern this bug was: href="${i.link}" (or
    # any similarly-named item variable) with no sanitizing function
    # wrapped around it. Every href built from feed/backup-derived content
    # must route through safeHref().
    vulnerable_pattern = re.compile(r'href="\$\{(\w+)\.link\}"')
    for filename, content in ALL_JS_FILES.items():
        matches = vulnerable_pattern.findall(content)
        assert not matches, (
            f"{filename} interpolates an item's .link directly into an href attribute "
            f"without going through safeHref() — this is the exact pattern that caused "
            f"a confirmed attribute-breakout XSS. Found: {matches}"
        )


def test_safe_href_is_actually_used_at_every_known_link_rendering_site():
    assert "href=\"${safeHref(i.link)}\"" in FEED_LIST_JS
    assert FEED_LIST_JS.count("safeHref(i.link)") == 2, "expected both feed-card link sites (title + open-original icon) to use safeHref"
    assert "href=\"${safeHref(i.link)}\"" in APP_JS, "the IOC drilldown article table must also use safeHref"


def _js_function_body(source: str, name: str) -> str:
    match = re.search(rf"function {name}\([^)]*\)\s*\{{", source)
    assert match, f"could not find function {name}(...) in source"
    start = match.end() - 1
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise AssertionError(f"could not find the end of {name}'s function body")


def test_escape_attr_escapes_quote_characters_unlike_escape_html():
    body = _js_function_body(APP_JS, "escapeAttr")
    assert '"' in body or "&quot;" in body, "escapeAttr must escape double-quote characters — this is the whole reason it exists separately from escapeHtml"


def test_safe_href_only_allows_http_and_https_schemes():
    body = _js_function_body(APP_JS, "safeHref")
    assert "'http:'" in body and "'https:'" in body, "safeHref must explicitly allowlist http/https schemes"
    assert "return '#'" in body, "safeHref must have a safe fallback for anything that isn't http(s), e.g. javascript: or data: URIs"
