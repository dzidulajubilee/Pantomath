# Architecture

## Layout

```
Pantomath/
├── pantomath/                 # the installable Python package
│   ├── connectors/
│   │   ├── base.py        # BaseConnector — the extensibility contract
│   │   ├── rss.py          # RSSConnector — the only implementation in v1.0
│   │   └── registry.py    # connector_type -> class lookup
│   ├── feeds/
│   │   ├── rss.py         # blocking feedparser fetch, run in a thread executor
│   │   ├── parser.py      # normalizes feedparser entries into a flat dict
│   │   └── scheduler.py   # background asyncio loop, connector-agnostic
│   ├── intelligence/
│   │   ├── scoring.py     # keyword-based high/medium/low severity tagging
│   │   └── enrichment.py  # derives a source's favicon URL from its domain
│   ├── database/
│   │   ├── models.py      # SQL schema (sources, items, settings)
│   │   └── sqlite.py      # connection helper + startup init/seed logic
│   ├── api/
│   │   └── routes.py      # REST endpoints + the /ws WebSocket
│   └── app.py              # FastAPI app, mounts frontend/, wires it together
│
├── frontend/
│   ├── pages/dashboard.html   # page shell: sidebar nav + all views + modal
│   ├── themes/pantomath.css   # design tokens + all styling
│   ├── widgets/
│   │   ├── app.js             # router, view loaders, sources/settings, WebSocket
│   │   ├── feed-list.js       # reusable item-card renderer (save/open/tags)
│   │   └── charts.js          # dependency-free bar chart + sparkline
│   ├── components/icon.js     # favicon-with-fallback helper
│   └── assets/icons/          # app logo (also used as favicon)
│
├── config/feeds.json      # optional starter sources — EMPTY by default
├── icons/                 # app icon for OS-level packaging (pixmaps)
├── installer/
│   ├── deb/                # control file, postinst/prerm/postrm, systemd unit
│   └── rpm/                # nfpm.yaml spec (builds rpm without rpmbuild) + same scripts
├── tests/                 # pytest suite — see conftest.py for the env-var-before-import setup
├── pyproject.toml         # package metadata, version, deps, ruff/pytest config — single source of truth
├── Makefile               # make dev / test / lint / fmt / package
├── CONTRIBUTING.md
└── docs/
```

## Data flow

1. `pantomath/feeds/scheduler.py` wakes every 20s, checks each enabled source's
   `interval_seconds` against its `last_fetched` timestamp.
2. Due sources get handed to `pantomath/connectors/registry.get_connector()`,
   which looks up the class for that source's `connector_type` and calls
   its `update()` — the fetch → normalize → validate → store cycle defined
   by `BaseConnector`. The scheduler itself has no RSS-specific code.
3. `RSSConnector.fetch()` calls `pantomath/feeds/rss.py` (`feedparser`, run in
   a thread pool since it's blocking); `.normalize()` calls
   `pantomath/feeds/parser.py` to shape entries into the common item dict;
   `.store()` scores severity (`pantomath/intelligence/scoring.py`) and
   writes to SQLite.
4. Newly-inserted items are broadcast to all connected browsers over
   `/ws`. The frontend prepends them with a slide-in animation.
5. On page load, `GET /api/items` returns whatever's cached — no live
   fetching happens on the request path, so page load stays fast regardless
   of source count or feed size.

## Extensibility: the connector contract

`pantomath/connectors/base.py` defines `BaseConnector`, an abstract class
with five methods: `fetch()`, `normalize()`, `validate()`, `store()`, and
`update()` (which chains the first four). `RSSConnector` is the only
implementation shipped in v1.0.

Retrieval, parsing/normalization, and storage are deliberately separate
steps — not just separate function calls, but separate *files*
(`pantomath/feeds/rss.py` vs `pantomath/feeds/parser.py` vs the `store()`
method) — so each can change independently. A future connector for a
different kind of source (a TAXII feed, a vendor API, anything) is added
by:

1. Implementing `BaseConnector` in a new `pantomath/connectors/<name>.py`.
2. Adding one line to `CONNECTOR_REGISTRY` in `pantomath/connectors/registry.py`.

No changes to the scheduler, the database schema (the `sources` table
already has a `connector_type` column, defaulting to `'rss'`), or the API
layer are required. `GET /api/connectors` reports which types are
currently supported, so the UI never has to hardcode "RSS" — it's just
the only entry in the registry today.

**This version only registers RSS.** `POST /api/sources` rejects any
`connector_type` other than `"rss"` with a 400, by design — the schema
and interfaces are ready for more source types, but v1.0 doesn't add any.

## Guarantee: only new items are ever stored

`RSSConnector.store()` writes with `INSERT OR IGNORE` against the
`UNIQUE(source_id, guid)` constraint on the `items` table, and checks
`cursor.rowcount` after each write: `0` means that exact item was already
on disk and nothing happened; `1` means it was genuinely new. Only items
with `rowcount == 1` are returned from `store()` — which means only
genuinely new items are ever broadcast to the dashboard or counted in
"items / 24h". Polling the same feed repeatedly is safe and cheap: no
duplicate rows, no duplicate WebSocket pushes, no re-processing of
already-seen articles.

## Why sources start empty

Earlier builds auto-seeded five default sources on first run. That's
surprising behavior — a fresh install should show exactly what you
configured, nothing more. `config/feeds.json` ships with an empty
`sources` array; it's only consulted on a genuinely empty database, so it's
safe for scripted/fleet deployments (fill it in before building the
package) without affecting normal installs.

## History: retention, pagination, and the calendar

Nothing is ever deleted automatically by default. `settings.retention_days`
(default `0` = forever) is the only thing that prunes old items, and it's
opt-in from Settings — the scheduler checks it at most once an hour
(`pantomath/feeds/scheduler.py: _maybe_run_retention`) and just does
nothing if it's `0`.

Being direct about a real constraint here: RSS is not an archive format.
Most feeds only ever expose their most recent 10–50 items — Pantomath
can't retroactively pull a year of posts a source never published via
RSS. What "keep forever" actually buys you is that everything Pantomath
*has* seen stays on disk indefinitely, so a year of continuous running
gives you a genuinely browsable year of history.

Browsing that history is `GET /api/items` with `date_from`/`date_to`
(day-granularity, inclusive) and `limit`/`offset` for pagination — Live
Feed's "Load more" button just increments `offset`. `GET /api/items/range`
reports the earliest/latest/total stored, used to bound the date pickers
to actual data. `GET /api/items/calendar?year=&month=` backs the calendar
widget (`frontend/widgets/calendar.js`) — a dependency-free month grid
that dots any day with stored items; clicking a day sets `date_from` and
`date_to` to that single day.

## Packaging & collaboration

`pantomath/` is a real installable Python package now (PEP 621, via
`pyproject.toml`) — `pip install -e .` gets you an editable install,
`from pantomath.intelligence.scoring import score_severity` works from
anywhere, and `pantomath.__version__` reflects whatever's actually
installed. Version lives in exactly one place: `pyproject.toml`'s
`[project] version`. `build.sh` reads it from there automatically, so
there's nothing else to bump on a release.

Each subpackage's `__init__.py` re-exports its public API (e.g.
`from pantomath.connectors import BaseConnector, RSSConnector` instead of
reaching into `pantomath.connectors.rss` directly) — except
`pantomath/feeds/__init__.py`, which deliberately does NOT re-export
`Scheduler`: doing so would create a real circular import
(`feeds → connectors → feeds.parser → feeds/__init__ again`), caught by
the test suite the first time it was tried. Import `Scheduler` directly
from `pantomath.feeds.scheduler` instead — that one line of nuance is
called out in the module's own docstring so it isn't rediscovered the
hard way twice.

The top-level `pantomath/__init__.py` deliberately does NOT import
`pantomath.app` — doing so would make every `import pantomath.<anything>`
eagerly construct the FastAPI app (mounting static files, registering
routes) as a side effect, which is unwanted for lightweight uses like
importing a scoring function in a script or test.

`tests/conftest.py` is the one file that has to run before anything else:
several modules read `PANTOMATH_DB`/`PANTOMATH_ICON_CACHE` as module-level
constants at import time, so the test env vars are set at conftest
*module-load* time, not inside a fixture — pytest guarantees conftest.py
loads before any test module it applies to.

## IOC extraction

`pantomath/intelligence/ioc_extraction.py` does the same kind of
rule-based extraction as tagging.py, for a different purpose: CVEs, IPv4
addresses, MD5/SHA1/SHA256 hashes, and email addresses, via regex against
each item's title+summary at store time. A few deliberate details worth
knowing:
- IPv4 matching validates each octet is actually 0–255 (so it doesn't
  treat arbitrary `x.y.z.w`-shaped version numbers as IPs), and filters
  a short list of constantly-recurring noise addresses
  (`127.0.0.1`, `8.8.8.8`, etc.) that show up in prose as examples, not
  as real indicators.
- Hashes are matched longest-pattern-first (SHA256 → SHA1 → MD5) since a
  regex word boundary can't match partway through a continuous hex run,
  so there's no risk of a 64-char hash also registering as containing an
  MD5.

Stored as comma-separated strings on the `items` row (`cves`, `ips`,
`hashes`, `emails`) — same pattern as `vendors`/`actors`, same tradeoff
(simple now, easy to normalize into real join tables later if needed).

`GET /api/iocs?type=&limit=` returns the top IOCs of one type with
occurrence counts (powers the IOCs page's bar chart); `GET
/api/iocs/summary` returns a distinct-count-per-type breakdown (powers
the distribution donut — built with CSS `conic-gradient`, no chart
library). `GET /api/items?ioc_type=&ioc_value=` filters articles
containing a specific indicator — clicking any bar or chip in the IOCs
view calls exactly this endpoint to populate the "Articles containing…"
table below it.

## Schema migrations

`CREATE TABLE IF NOT EXISTS` is a no-op against an already-existing
table — so every column added after the very first release (`icon_url`,
`connector_type`, `severity`, `vendors`, `actors`, `bookmarked`, and now
the four IOC columns) needed an explicit migration path, which didn't
exist until this pass. `pantomath/database/models.py: MIGRATIONS` is the
list of `(table, column, definition)` tuples; `pantomath/database/sqlite.py:
_run_migrations` checks `PRAGMA table_info` and only `ALTER TABLE ADD
COLUMN`s what's actually missing. Runs on every startup, safe to run
against an up-to-date database (no-op) or a genuinely old one (brings it
current, verified against a simulated pre-v1.4 database with none of
these columns — the old row survived untouched and every expected column
was added). Any future column addition should get an entry here, not just
a change to `SCHEMA`.

## UI

Twelve views, matching the target navigation: Dashboard, Live Feed,
Critical, Vulnerabilities, Malware, Ransomware, Threat Actors, Vendors,
Saved, Sources, Analytics, Settings. It's a single-page app with a small
hash-based router (`frontend/widgets/app.js`) — no framework, no build
step, no bundler. Charts are plain CSS/SVG bars and a sparkline
(`frontend/widgets/charts.js`); there's no charting library dependency,
which keeps the whole frontend at a handful of KB.

Each of Critical / Vulnerabilities / Malware / Ransomware / Vendors /
Threat Actors / Saved / the Dashboard's "Latest intelligence" panel is
just the same `renderFeedCards()` (`frontend/widgets/feed-list.js`) fed a
different pre-filtered `/api/items` query — one card renderer, many views.

## Tagging (vendors & threat actors)

`pantomath/intelligence/tagging.py` does rule-based keyword/pattern
matching against curated vendor and threat-actor name lists (plus a regex
for APT/UNC/FIN/TA-style actor codenames). This is deliberately simple —
no NLP, no LLM call, no external dependency — and is applied once, at
store time, so it costs nothing on every page load. It's the file to
replace if you want smarter extraction later; nothing else references it
except the RSS connector's `store()` step and the `/api/tags` endpoint.
Tags are stored as comma-separated strings on the `items` row (not a
normalized join table) — a deliberate v1.0 simplification given the
dataset size; easy to normalize into real `Tags`/`ArticleTags` tables
later without changing the tagging logic itself.

## Icons — fetched once, served from disk

Each source has an `icon_url` (auto-derived from its domain, or a custom
URL you supply). The browser never hits that URL directly — it requests
`GET /api/sources/{id}/icon`, and `pantomath/intelligence/enrichment.py`
fetches it **exactly once**, caches the bytes + content-type under
`PANTOMATH_ICON_CACHE` (defaults to an `icons/` folder next to the
database), and every request after that is a disk read. A failed fetch is
negative-cached for an hour too, so a dead icon host doesn't get hit on
every page load — it just 404s quickly, and the frontend's `onerror`
handler swaps in the category's colored dot. Deleting a source also
deletes its cached icon file.

## Theme (light/dark)

One `data-theme` attribute on `<html>`, one CSS block
(`[data-theme="light"] { ... }` in `themes/pantomath.css`) overriding the
same custom properties the dark theme sets on `:root` — every component
that already uses `var(--x)` adapts automatically, no per-component theme
logic needed. `frontend/widgets/theme.js` handles the two toggle controls
(header button, Settings row) and persists the choice to `localStorage`;
an inline snippet in `<head>` applies it before first paint to avoid a
flash of the wrong theme. Severity/category accent colors intentionally
stay the same across both themes — they're recognition colors, not
surface colors.

## Desktop notifications

Implemented with the standard browser `Notification` API
(`frontend/widgets/notifications.js`) — Pantomath is a locally-hosted web
app, not a native Tauri/Electron build, so this is the correct mechanism
for this architecture, and it does produce real OS-level notification
popups. The honest limitation, stated directly in the Settings page: it
only fires while the dashboard tab is open in the browser — there's no
service-worker/background push for when the tab is closed. The WebSocket
handler in `app.js` calls `notifyForNewItems()` on every `new_items`
broadcast; a severity threshold (Settings) controls what qualifies.
