# Contributing to Pantomath

## Project structure

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the codebase is
organized and why. The short version: `pantomath/` is the installable
Python package (FastAPI backend, connectors, database, intelligence
processing); `frontend/` is a plain HTML/CSS/JS single-page app served by
it, no build step; `installer/` and `build.sh` produce `.deb`/`.rpm`
packages; `tests/` is the pytest suite.

## Setup

```bash
git clone <this repo> && cd Pantomath
make dev              # creates venv/, installs pantomath in editable mode + dev deps
source venv/bin/activate
```

Or by hand:
```bash
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

## Running it locally

```bash
make run
# or: PANTOMATH_DB=./data/pantomath.db PYTHONPATH=. uvicorn pantomath.app:app --reload --port 7373
```

Dashboard at http://localhost:7373. `--reload` picks up backend changes
automatically; frontend files are static and just need a browser refresh.

## Tests

```bash
make test
# or: PYTHONPATH=. python3 -m pytest tests/ -v
```

`tests/conftest.py` points the app at a temp SQLite file for the whole
test session — it never touches a real `/var/lib/pantomath` database.
Please add tests for new behavior, especially anything touching:
- the dedup guarantee (`RSSConnector.store()` must never re-emit an
  already-seen item — see `tests/test_rss_connector.py`)
- the connector registry contract (`tests/test_connectors_registry.py`)
- API endpoints that have broken before (`tests/test_api_integration.py`)
  — fresh installs starting with zero sources is a real regression this
  project shipped once; there's a test guarding it specifically.

## Linting

```bash
make lint     # check only
make fmt      # auto-fix + format
```

Ruff config lives in `pyproject.toml`. CI (if/when you wire one up) should
run `make lint` and `make test` on every PR.

## Adding a new intelligence source connector

RSS is the only connector in v1.0 by design — but the architecture is
built for more. To add one:

1. Implement `BaseConnector` (`pantomath/connectors/base.py`) in a new
   `pantomath/connectors/<name>.py`: `fetch()`, `normalize()`, `store()`
   at minimum (`validate()` has a sane default, `update()` is provided).
2. Register it in `pantomath/connectors/registry.py`'s
   `CONNECTOR_REGISTRY` dict.
3. That's it — the scheduler, database, and API layer all work against
   `BaseConnector`, not against RSS specifically. `POST /api/sources`
   will accept the new `connector_type` automatically once it's
   registered (remove the "only rss" validation in
   `pantomath/api/routes.py:add_source` if you're intentionally opening
   this up beyond v1.0's scope).

See `pantomath/connectors/rss.py` for a complete reference implementation,
and `docs/ARCHITECTURE.md` for the reasoning behind the split between
retrieval, parsing, and storage.

## Building packages

```bash
make package        # both .deb and .rpm
./build.sh deb       # .deb only — dpkg-deb, no extra tools needed
./build.sh rpm       # .rpm only — requires nfpm (https://nfpm.goreleaser.com)
```

Version comes from `pyproject.toml`'s `[project] version` — bump it there,
nowhere else.

## Code style

- Prefer readability over cleverness; this is a small-team/solo-collab
  project, not a codebase optimized for maximum abstraction.
- Docstrings that explain *why*, not just *what* — especially for any
  non-obvious tradeoff (there are several called out directly in
  docstrings throughout, e.g. why tagging is keyword-based, why there's
  no chart library dependency).
- Keep the frontend dependency-free (no build step, no framework) unless
  there's a strong reason to introduce one — that's a deliberate
  architectural choice, not an oversight.
