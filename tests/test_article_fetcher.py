import os
import tempfile

from pantomath.feeds.article_fetcher import fetch_article_text_sync, html_to_text


def test_html_to_text_strips_tags():
    html = "<html><body><p>Hello <b>world</b></p></body></html>"
    assert html_to_text(html) == "Hello world"


def test_html_to_text_skips_script_and_style():
    html = "<html><body><script>alert('x')</script><style>.a{color:red}</style><p>Real content</p></body></html>"
    result = html_to_text(html)
    assert "Real content" in result
    assert "alert" not in result
    assert "color:red" not in result


def test_html_to_text_skips_nav_and_footer():
    html = "<nav>Home | About</nav><p>Article body text</p><footer>Copyright 2026</footer>"
    result = html_to_text(html)
    assert "Article body text" in result
    assert "Home" not in result
    assert "Copyright" not in result


def _write_temp_html(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".html")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return f"file://{path}"


def test_fetch_article_text_via_file_url():
    url = _write_temp_html("<html><body><p>Malware hash d41d8cd98f00b204e9800998ecf8427e found in payload.</p></body></html>")
    text = fetch_article_text_sync(url)
    assert "d41d8cd98f00b204e9800998ecf8427e" in text


def test_fetch_article_text_returns_empty_on_missing_file():
    text = fetch_article_text_sync("file:///tmp/definitely-does-not-exist-pantomath-test.html")
    assert text == ""


def test_fetch_article_text_returns_empty_for_blank_url():
    assert fetch_article_text_sync("") == ""


def test_fetch_article_text_truncates_to_max_length():
    long_html = "<p>" + ("word " * 10000) + "</p>"
    url = _write_temp_html(long_html)
    text = fetch_article_text_sync(url)
    assert len(text) <= 20_000
