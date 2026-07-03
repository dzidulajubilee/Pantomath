"""
Maps a source's `connector_type` to its connector class.

v1.0 registers exactly one entry ("rss"), per the requirement that RSS is
the only supported intelligence source in this version. Adding a future
source type is a two-step, additive change:

    1. implement BaseConnector in backend/connectors/<name>.py
    2. add one line to CONNECTOR_REGISTRY below

No other file in the app needs to change — the scheduler, database, and
API layers all work against BaseConnector, not against RSS specifically.
"""
from backend.connectors.rss import RSSConnector

CONNECTOR_REGISTRY = {
    "rss": RSSConnector,
}


def get_connector(source: dict):
    connector_type = source.get("connector_type") or "rss"
    cls = CONNECTOR_REGISTRY.get(connector_type)
    if cls is None:
        raise ValueError(f"No connector registered for type '{connector_type}'")
    return cls(source)


def available_connector_types() -> list[dict]:
    """Used by the API/UI to know what source types can be added."""
    labels = {"rss": "RSS / Atom Feed"}
    return [{"type": t, "label": labels.get(t, t)} for t in CONNECTOR_REGISTRY]
