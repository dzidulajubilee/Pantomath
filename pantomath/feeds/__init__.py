from pantomath.feeds.parser import domain_from_url, normalize_entry
from pantomath.feeds.rss import fetch_raw

# NOTE: Scheduler is deliberately NOT re-exported here. It depends on
# pantomath.connectors.registry, which depends on pantomath.connectors.rss,
# which depends on pantomath.feeds.parser — importing Scheduler at this
# package's top level would re-trigger this very __init__.py mid-import
# and cause a circular import. Import it directly where needed:
#     from pantomath.feeds.scheduler import Scheduler
# (this is exactly what pantomath/app.py does).

__all__ = ["fetch_raw", "normalize_entry", "domain_from_url"]