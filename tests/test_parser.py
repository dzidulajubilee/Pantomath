from pantomath.feeds.parser import domain_from_url, normalize_entry


class FakeEntry(dict):
    """feedparser entries behave like dicts with attribute access; a plain dict with .get() is enough here."""
    pass


def test_domain_from_url_basic():
    assert domain_from_url("https://example.com/feed.xml") == "example.com"


def test_domain_from_url_strips_path_and_scheme():
    assert domain_from_url("http://sub.example.com/a/b/c") == "sub.example.com"


def test_domain_from_url_strips_userinfo():
    assert domain_from_url("https://user@example.com/feed") == "example.com"


def test_normalize_entry_basic_fields():
    entry = FakeEntry(title="Some Title", link="http://x.com/1", summary="A summary", id="guid-1")
    result = normalize_entry(entry)
    assert result["title"] == "Some Title"
    assert result["link"] == "http://x.com/1"
    assert result["summary"] == "A summary"
    assert result["guid"] == "guid-1"


def test_normalize_entry_falls_back_to_link_as_guid():
    entry = FakeEntry(title="No GUID here", link="http://x.com/2", summary="")
    result = normalize_entry(entry)
    assert result["guid"] == "http://x.com/2"


def test_normalize_entry_generates_guid_when_nothing_available():
    entry = FakeEntry(title="Only a title")
    result = normalize_entry(entry)
    assert result["guid"]  # some non-empty hash was generated
    assert isinstance(result["guid"], str)


def test_normalize_entry_truncates_long_summary():
    entry = FakeEntry(title="T", link="http://x.com", summary="x" * 5000)
    result = normalize_entry(entry)
    assert len(result["summary"]) == 2000
