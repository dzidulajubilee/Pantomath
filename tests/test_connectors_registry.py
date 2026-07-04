import pytest

from pantomath.connectors.registry import CONNECTOR_REGISTRY, available_connector_types, get_connector
from pantomath.connectors.rss import RSSConnector


def test_rss_is_the_only_registered_connector():
    # Per the v1.0 requirement: RSS is the only supported source type.
    assert set(CONNECTOR_REGISTRY.keys()) == {"rss"}


def test_get_connector_returns_rss_connector():
    source = {"id": "abc", "connector_type": "rss", "url": "http://example.com/feed.xml"}
    connector = get_connector(source)
    assert isinstance(connector, RSSConnector)


def test_get_connector_defaults_to_rss_when_type_missing():
    source = {"id": "abc", "url": "http://example.com/feed.xml"}
    connector = get_connector(source)
    assert isinstance(connector, RSSConnector)


def test_get_connector_raises_for_unknown_type():
    source = {"id": "abc", "connector_type": "taxii", "url": "http://example.com"}
    with pytest.raises(ValueError):
        get_connector(source)


def test_available_connector_types_reports_rss():
    types = available_connector_types()
    assert any(t["type"] == "rss" for t in types)
