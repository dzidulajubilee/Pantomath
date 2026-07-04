"""
Pantomath — threat intelligence RSS feed aggregator.

Deliberately does NOT import `pantomath.app` here. Doing so would make
every `import pantomath.<anything>` eagerly construct the FastAPI app
(mounting static files, registering routes) as a side effect, which is
unwanted for lightweight uses like `from pantomath.intelligence.scoring
import score_severity` in a script or test. Import `pantomath.app` (or
just run `uvicorn pantomath.app:app`) explicitly when you actually want
the app.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pantomath")
except PackageNotFoundError:
    # Not pip-installed (e.g. running via PYTHONPATH=. in dev without
    # `pip install -e .`) — see pyproject.toml for the real version.
    __version__ = "0.0.0-dev"