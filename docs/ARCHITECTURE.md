> **This is the design log.** It records why things are the way they are,
> release by release, including bugs that shaped the design, and some early
> sections describe the code as it was then. For the current overview start
> with [how-it-works.md](how-it-works.md); the full documentation index is
> [docs/README.md](README.md).

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
3. `RSSConnector.fetch()` calls `pantomath/feeds/rss.py` (urllib fetch with
   timeouts, then `feedparser` as the parser, run in a thread pool since it's
   blocking — see "Feed fetching" below); `.normalize()` calls
   `pantomath/feeds/parser.py` to shape entries into the common item dict;
   `.store()` scores severity (`pantomath/intelligence/scoring.py`) and
   writes to SQLite.
4. Newly-inserted items are broadcast to all connected browsers over
   `/ws`. The frontend prepends them with a slide-in animation.
5. On page load, `GET /api/items` returns whatever's cached — no live
   fetching happens on the request path, so page load stays fast regardless
   of source count or feed size.

## Feed fetching: timeouts and honest status

`pantomath/feeds/rss.py` downloads the feed itself with urllib and only
then hands the bytes to feedparser as a parser. Handing the URL straight
to `feedparser.parse()` (the original approach) caused two real problems:

- **Broken feeds showed as healthy.** feedparser never raises — a 404, a
  DNS failure, a refused connection or an HTML page all come back as zero
  entries with a `bozo` flag, and the scheduler recorded `last_status =
  'ok'`. A dead feed was indistinguishable from a quiet one.
- **No timeout.** feedparser opens URLs with no socket timeout, and the
  scheduler polls sources one after another, so a single server that
  accepted the connection and never answered stalled polling of *every*
  source indefinitely.

Now: a 15s per-read timeout, a 45s whole-download deadline (read via
`read1()`, so a server dripping one byte at a time can't dodge it), a
10 MB size cap that also applies after gzip/deflate decompression, and an
`asyncio.wait_for` backstop in `RSSConnector.fetch()` for the one thing
urllib can't bound (DNS resolution). Any failure raises `FeedFetchError`
with a short reason ("HTTP 404 Not Found", "could not resolve the host
name", "URL returned a web page, not an RSS/Atom feed") which the
scheduler stores as `error: <reason>` and the Sources table shows as-is.
A feed that is valid but currently empty is still `ok`. Only `http://`
and `https://` URLs are fetched — `feedparser.parse()` would also read a
local file path. feedparser's own User-Agent and Accept header are still
sent, so publishers see exactly what they saw before.

Verified against a real local HTTP server in `tests/test_feed_fetch.py`
(404, HTML page, refused connection, hang, slow drip, oversize, gzip,
redirect, relative links), including a scheduler-level test that a hanging
source no longer stops a healthy one from being polled — and confirmed
those tests fail against the pre-fix code.

## Dashboard, header status and "published" time (0.5.0)

The dashboard and the header's status indicators read one public endpoint,
`GET /api/overview?hours=&since=`, added alongside `/api/stats` (which is
unchanged, so nothing depending on it breaks). Three rules matter:

- **Counts follow the published date**, not the fetch time. Counting by
  fetch time made a newly added source's two-week backlog show up as
  "new today" and "critical in the last 24 hours". The effective time is
  the feed's own date unless it is more than an hour later than the fetch
  (a publisher's wrong clock), in which case the fetch time is used —
  `_EFFECTIVE_TS` in `api/routes.py`, mirrored by `effectiveTs()` in
  `frontend/widgets/feed-list.js`. Published dates are parsed with
  `calendar.timegm` (feedparser's parsed dates are UTC; `time.mktime`
  shifted them by the server's UTC offset).
- **"New since you last looked" follows the fetch time**, because it is
  about what the viewer hasn't seen. The browser records when it last
  left Pantomath (`localStorage`) and passes it as `since`.
- **No feed URLs in the response.** The endpoint is public like the rest
  of the dashboard, and a feed URL can carry an API key, so source health
  exposes only name, category, state and the last error message.

The header's old "Sources" and "Items / 24h" counters are gone: one needed
a Settings login to show anything and the other was never updated. In
their place, a "N sources failing" indicator and a connection state that
switches to **Not updating** when no data has arrived for two minutes, so
an unattended wall display that has frozen doesn't look like a quiet day.

Global search in the header recognises an exact CVE, IP address, hash or
email and opens its indicator drill-down; anything else becomes a Live
feed keyword filter. On screens narrower than 900px the sidebar becomes a
drawer. UI text is IBM Plex Sans (bundled, like the other fonts); IBM Plex
Mono stays for indicators. Severity is always shown as colour + label +
shape (triangle high, diamond medium, ring low), never colour alone.

## Sources, Indicators and Analytics (0.6.0)

- **Source health history.** `sources` gained `last_success`,
  `failing_since` and `last_duration_ms` (added through `MIGRATIONS`, so
  existing databases upgrade in place). `last_fetched` alone could not say
  when a failing feed last worked, because it updates on failures too.
  `failing_since` is set on the first failure and kept until a success.
- **Feed test.** `POST /api/sources/test` (Settings password required, since
  it makes the server fetch a URL) runs the scheduler's own `fetch_raw`
  with the same limits and error messages, and saves nothing. The Add/Edit
  form runs it before saving; if it fails, the button becomes "Save anyway".
- **Indicator detail.** `GET /api/iocs?detail=1&q=` adds sources, highest
  severity and first/last seen to each value. It is opt-in, so the plain
  `{name, count}` response stays exactly as it was.
- **Analytics.** `GET /api/analytics?days=` (public) counts by published date
  like the dashboard, and returns the previous period of the same length and
  a weekday-by-hour publishing matrix.
- **List order.** `/api/items` orders by arrival minute, then by published
  date, so a feed's batch reads newest-first instead of in the order the
  publisher happened to list it.
- **Read state** is per browser (`localStorage`): an item is new if it
  arrived after the later of "last left Pantomath" and "Mark all as read".

## Shared feed pages and the Indicators calendar (0.6.1)

- **One list component.** The Live feed's list and detail panel is a small
  component (`createFeedPanel` in `app.js`) with per-page state. High
  severity, Vulnerabilities, Malware, Ransomware, Saved, Vendors and Threat
  actors each get an instance; keyboard shortcuts act on the visible page.
  Pages that are an OR of two filters (Vulnerabilities: Vulnerability source
  OR mentions a CVE) make two requests and merge them, because the items API
  ANDs filters within one request.
- **Calendar unit.** `/api/iocs/calendar` returns `count` = distinct
  indicators of the type seen that day (the unit of the table and of
  `/api/iocs/summary` for that day) and `articles` = items they appeared in.
  It used to return the number of items as `count`, which never matched the
  table next to it.
- **First/last seen.** In `/api/iocs?detail=1`, mentions, sources and
  severity follow the selected day, but first and last seen are computed
  over all items, so "first seen" really is the first time.

## Our stack and CISA KEV (0.7.0)

- **Stored per item.** `items.watch_hits` (names of Our stack entries the
  item mentions) and `items.kev_cves` (its CVEs that are on the KEV
  catalog), both comma-separated like the other tag columns, so pages,
  counts and webhooks filter with plain SQL (`affects_us=1`, `exploited=1`).
- **When they change.** New items are marked at ingest
  (`connectors/rss.py`), and Reprocess all recomputes both. Adding, editing
  or removing an Our stack entry re-matches every stored item
  (`watchlist.rematch_all`, rowid batches); a catalog download re-marks every
  item with a CVE (`kev.recompute_item_kev`).
- **Matching** (`intelligence/watchlist.py`) uses the title and RSS summary
  only, never the deep-extraction page: that page isn't stored, so stored
  items couldn't be re-matched the same way, and sidebars would cause false
  matches. Whole words; short all-capital terms are case-sensitive.
- **KEV download** (`intelligence/kev.py`) runs as a background task from the
  scheduler: daily after a success, hourly after a failure, never when
  disabled. A failed download keeps the previous copy and records the reason
  for Settings. `kev_url` can point at an internal copy for offline servers.
- **Exposure.** `/api/watchlist` and the KEV settings are protected. Public
  endpoints return counts (`/api/overview`) and each item's own matches, never
  the list itself; `/api/kev?cves=` is public because CISA's data is.

## Sign-in, priority and read state (0.8.0)

- **Sign-in** (`auth/sign_in.py`). `router` carries a `require_viewer`
  dependency, so every data route needs a session by construction; only
  `auth_router` (sign-in endpoints and the WebSocket, which checks the
  cookie itself and closes with 4401) is reachable without one. Sessions
  live in the `sessions` table as SHA-256 hashes of 256-bit tokens, cached
  for 30 s per token, touched at most every 5 minutes. Roles: `team`,
  `admin` (signed in with the Settings password, which also returns a
  Settings token), `api` (keys). The Settings password check used here
  doesn't count toward the Settings lockout; sign-in has its own per-address
  limit. `PANTOMATH_OPEN_DASHBOARD=1` disables sign-in (reverse-proxy SSO,
  and the test suite, where `tests/test_sign_in.py` turns it back on).
- **Priority** (`intelligence/priority.py`). `items.severity` now holds the
  priority (critical/high/medium/low) so every existing filter, count,
  webhook and notification threshold uses it; the keyword rating and the
  phrase that decided it are in `content_severity` / `content_keyword`.
  Ingest, Reprocess, Our stack re-matching and KEV re-marking all recompute
  it; `init_db` backfills items stored before 0.8.0 once. Reasons are
  derived per request in `_row_to_item`.
- **Read state** stays in the browser: a time mark ("since you last left",
  or Mark all as read) plus small maps of items opened after it and items
  marked unread from before it. The server's `new_since` count is adjusted
  with them, so counts drop the moment an item is opened; `storage` events
  keep other tabs in step. The sign-in page never records a visit.

## First run and recovery (0.8.1)

- **Setup code.** Before 0.8.1 the first person to reach a fresh install
  created the Settings password ("trust on first use"). Now
  `auth/setup_code.py` creates a one-time 12-character code (about 59 bits)
  when the install has no Settings password: at install time
  (`postinstall.sh` runs `pantomath-admin setup-code --bare` as the service
  user before starting the service, and prints it) or on startup. Only its
  PBKDF2 hash is in the database; the plain code is in `setup-code` next to
  the database (mode 0600), never in the logs. `/api/auth/setup` and the
  in-app `/api/settings/auth/setup` both require it (the latter only with
  sign-in on); it's deleted once used.
- **Recovery on the sign-in page.** In 0.8.0 the recovery-code form only
  existed inside the Settings unlock prompt, behind sign-in, so a lost
  Settings password without a team password could only be fixed on the
  server. `/api/auth/recover` (no sign-in needed, attempt-limited) resets it
  and signs out other Settings-password sessions.
- **The CLI never reopens first-run setup by accident.**
  `reset-settings-password` sets the new password directly; `--clear`
  returns to first-run setup but signs every browser out, so the only way
  back in is the setup code. Commands that touch the database continue as the
  owner of the database folder when run as root: the database is in WAL
  mode, and a root-owned `-wal`/`-shm` file would stop the service writing.

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

## Deep extraction: fetching full articles for richer IOC/tag signal

RSS summaries are short teasers — real IOCs (C2 IPs, hashes, full CVE
lists) usually live in the article body on the publisher's site, not in
the feed's excerpt. `pantomath/feeds/article_fetcher.py` fetches the full
page for each genuinely-new item and strips it to plain text (a small
`HTMLParser` subclass, skipping `<script>`/`<style>`/`<nav>`/`<footer>`
content — no HTML-parsing library dependency). That richer text feeds
severity scoring, tagging, and IOC extraction; the stored/displayed
summary stays the original RSS teaser.

A few things worth knowing:
- **Toggleable in Settings** (`deep_extraction`, on by default) — since
  it means Pantomath fetches every new article's page, which is slower
  and means more outbound requests than summary-only extraction.
- **Filters to genuinely-new items before fetching anything.**
  feedparser re-returns the same ~50 recent entries on every poll
  regardless of dedup state — without checking the database for
  already-stored guids first, every poll cycle would re-fetch and
  re-parse the full page for every already-stored article, forever.
  `RSSConnector.store()` does this filter before any network call.
- **Bounded concurrency** (5 at a time) so fetching many new items at
  once (e.g. adding a source for the first time) doesn't serialize into
  a very slow first poll, without hammering a single host either.
- **Silent, total failure tolerance.** Paywalls, bot-blocking, timeouts,
  non-HTML responses — anything — just falls back to summary-only
  extraction for that item. Never blocks storing it, never raises.

Verified end-to-end (not just unit-tested): a test article with a CVE,
hash, and email present ONLY in the full body (not the summary) is
correctly detected when deep extraction is on, and correctly NOT detected
when it's off — see `tests/test_rss_connector.py`.

## Webhook alerting

`pantomath/alerts/` — `matcher.py` decides whether a new item matches a
webhook's conditions (keyword, specific source, minimum severity; any
unset condition means "any", and a rule with everything unset matches
every new item), `dispatcher.py` sends the actual HTTP POST (`urllib` in
a thread executor, same pattern as icon fetching — no async HTTP client
dependency for this volume). Called from the scheduler right after
`broadcast()` for the same new items, so WebSocket push and webhook
delivery see identical data.

Payload has a top-level `"text"` summary (so Slack/Discord/Mattermost-style
"post a message" webhooks show something reasonable with zero
configuration) plus a structured `"pantomath"` object for custom
consumers. Full native formatting for a specific service (Slack blocks,
Discord embeds) would need a small transform in front of this — out of
scope here, noted as an honest limitation rather than half-implemented.

`POST /api/webhooks/{id}/test` sends a synthetic payload immediately, so
you can verify a webhook works without waiting for a real matching item —
verified in tests against a real local HTTP server (not mocked), and
separately verified against the actual `scheduler.poll_source()` code
path end-to-end: a real feed poll, keyword-matched, delivered over real
HTTP, payload content confirmed on the receiving end.

## Fonts and icons: fully local, no CDN dependency

Both UI fonts (IBM Plex Mono, Space Grotesk) and all sidebar icons are
bundled under `frontend/assets/fonts/` and `frontend/assets/icons/nav/` —
fetched once from their open-source GitHub repos, not loaded from Google
Fonts or any icon CDN. This matters for a self-hosted security tool:
works fully offline/air-gapped, and doesn't leak "someone opened
Pantomath" to a third party on every page load. Both fonts are SIL OFL
1.1 licensed (license files included alongside them); icons are Lucide
(ISC licensed, license included). Space Grotesk ships as a single
variable-weight WOFF2 (one file covers the whole 300–700 weight range
instead of one file per weight); IBM Plex Mono ships as three static
WOFF2 weights (400/500/600) since that's what's actually used.

Sidebar icons are applied via CSS `mask-image` + `background-color:
currentColor` rather than `<img src="...">` — an `<img>`-loaded SVG
can't be recolored by the page's CSS (it's rendered as an opaque
resource, not part of the current-color inheritance chain), which would
have made hover/active color states impossible. The mask approach treats
each SVG as a stencil and lets `background-color` supply the actual
color, so icons correctly follow `.nav-item`'s existing hover/active
theme-aware colors for free.

## Content-aware filtering vs. source-category filtering

A real reported bug: the Vulnerabilities page originally only showed
items from sources manually categorized as `"vulnerability"` when added.
If you added a general news source (CyberScoop, Krebs, etc.) under
`"news"`, its CVE-laden articles were invisible there even though CVEs
were clearly being extracted and shown elsewhere (Dashboard, IOCs page).
Source category is a one-time manual choice at add-source time and
easy to get "wrong" for this purpose; an article actually containing a
detected CVE is a more reliable, content-based signal.

Fixed with a `has_cve=true` filter (`items.cves != ''`) on `GET
/api/items`, and the frontend's Vulnerabilities loader now merges two
queries — `category=vulnerability` OR `has_cve=true` — deduping by id
and re-sorting (`loadMergedFeed()` in `frontend/widgets/app.js`), since
the backend's query builder only ANDs conditions within one request.
Regression-tested directly against the reported scenario: a `"news"`-
categorized source with a CVE-bearing item is invisible to the old
`category=vulnerability` query and correctly found by `has_cve=true`
(`tests/test_api_integration.py`).

## Reprocessing: backfilling data for items stored before a feature existed

A schema migration adding a column (`MIGRATIONS` in
`pantomath/database/models.py`) only gives it an empty default — it never
retroactively computes real values for rows that predate the feature. An
install running since before IOC extraction or tagging shipped will have
items with genuinely empty `vendors`/`actors`/`cves`/etc., not because
nothing was there to find, but because detection didn't exist yet when
they were stored.

`pantomath/intelligence/reprocessor.py: reprocess_items()` re-runs
severity scoring, tagging, and IOC extraction against items already on
disk — no RSS re-fetch, using the exact same extraction logic (and
optionally the same deep-extraction full-article fetch) that new items
get. `POST /api/reprocess` exposes it (global or scoped to one source via
`source_id`); Settings has a "Reprocess all" button. This is the actual
fix for "Vulnerabilities/Malware/IOCs show nothing despite obviously
having CVE-tagged content elsewhere" — that's old data that predates the
feature, not a bug in the feature itself, and reprocessing is how you
backfill it without waiting for those old articles' feeds to naturally
cycle through fresh polls (which likely won't happen — RSS feeds don't
re-serve old entries).

`POST /api/sources/poll-all` complements this: an on-demand "refresh
every source right now" rather than waiting for each source's scheduled
interval, using the same fetch → normalize → validate → store pipeline
(and therefore the same dedup guarantee) as a normal poll.

## Cache-busting for the frontend shell

`GET /` no longer serves `dashboard.html` as a static file — it reads the
file, substitutes a `{{CACHEBUST}}` token in every CSS/JS reference with
the installed package version (`pantomath.__version__`), and returns it
as a rendered response (`pantomath/app.py: dashboard()`). Without this, a
browser that cached `pantomath.css` or `app.js` from a previous release
can keep serving that stale copy indefinitely after an upgrade, since the
URL never changes — there's nothing to tell the browser a newer version
exists. This was very likely the actual explanation for a real report of
"icons not displaying" shortly after an upgrade: correct new HTML paired
with a stale cached CSS file that predated the icon rules.

## Server-side pagination

Live Feed's severity/keyword filters moved from client-side (filtering an
already-fetched batch) to fully server-side, because that's a
prerequisite for accurate page counts — a "page 3 of 708" number is
meaningless if the actual displayed content is then further filtered
client-side afterward. `GET /api/items/count` mirrors every filter `GET
/api/items` accepts (both go through the same
`_build_item_conditions()` in `pantomath/api/routes.py`, so they can
never silently drift out of sync with each other) and returns a total,
which the frontend uses to compute page count. `severity` now accepts a
comma-separated list (`"high,medium"`) for the multi-select toggle,
translating to a SQL `IN (...)` clause instead of a single equality
match. `frontend/widgets/pagination.js` renders the numbered
first/prev/…/next/last control — dependency-free, consistent with the
rest of the app's charts/calendar-style widgets.

## A real shipped bug: views registered but never visible

`navigateTo(view)` toggles the `active` CSS class on `#view-<name>`
sections by iterating the `VIEWS` array — but `VIEWS` and
`VIEW_LOADERS` are two separate lists maintained by hand, and 'iocs' was
added to `VIEW_LOADERS` (and got a nav button, and got an HTML section)
without also being added to `VIEWS`. The result: clicking "IOCs"
correctly ran `loadIOCsView()`, which correctly populated its charts —
but the section itself never received the `active` class, so it stayed
hidden via `display:none` forever. No JS error, no console warning,
nothing — just a permanently blank content area. Confirmed with a real
headless-DOM test (jsdom) that loaded the actual served page, clicked
the actual nav button, and checked the actual resulting classList state,
rather than reasoning about the code in the abstract.

`tests/test_frontend_view_consistency.py` guards against this
permanently: plain regex checks (no JS runtime dependency in the test
suite) that every entry in `VIEW_LOADERS` is in `VIEWS`, every nav
button's `data-view` is in `VIEWS`, and every entry in `VIEWS` has both
a matching HTML section and a nav button. Verified the test actually
catches the bug by reintroducing it and watching the test fail, then
restoring the fix and watching it pass — not just written to look
plausible.

## A real shipped bug: the IOC drilldown closing itself on every auto-refresh

Reported behavior: click an IOC on the IOCs page to open the "Articles
containing…" drilldown, then the next time a feed poll finds new items
(or the 30s fallback poll in `init()`), the drilldown silently closes
and the view resets to just the top chart — with no user action.

Root cause: both the WebSocket `new_items` handler and the 30s
`setInterval` in `init()` re-run `VIEW_LOADERS[currentView()]?.()` on
every auto-refresh — the simplest-correct pattern described above under
"websocket". For the IOCs page that's `loadIOCsView()`, which
unconditionally hid `#iocArticlesPanel` on every call, since it had no
memory of whether a drilldown was open. So a feed poll finding a single
new item anywhere would close a drilldown that had nothing to do with
that item, without any error being thrown.

Fixed by tracking the open drilldown at module level (`iocDrilldown =
{ type, value }`, same pattern as `currentIocType`/`liveCurrentPage`),
set in `showIocArticles()`. `loadIOCsView()` now checks it: if a
drilldown for the *currently selected IOC type* is open, it re-renders
that same drilldown (picking up any new matching articles) instead of
closing it; only a genuine context change — explicitly clicking a
different IOC type button — clears it.

Verified end-to-end with jsdom against the real served files: opened a
drilldown by clicking a bar, simulated a `new_items` WebSocket
broadcast, confirmed the panel and its content survive. Confirmed the
identical scenario reproduces the bug (panel silently closes) when run
against the pre-fix file, so the test genuinely catches this class of
regression, not just the specific line changed.
`tests/test_ioc_drilldown_persistence.py` keeps the same regex-based,
no-JS-runtime tradeoff as `test_frontend_view_consistency.py` to guard
against it permanently.

## Editing sources and webhooks in place

`PATCH /api/sources/{id}` and `PATCH /api/webhooks/{id}` used to only
accept a single `enabled` query parameter (pause/resume). Both now
accept a full partial-update JSON body — only fields actually present in
the request change, everything else is left alone. This is what backs
the Edit button on both the Sources and Webhooks tables: the same
Add-modal is reopened pre-filled with the row's current values, and
submitting sends a PATCH instead of a POST. Previously the only way to
change a source's URL or a webhook's keyword filter was to delete it and
recreate it (losing the source's polling history/status in the process).
Editing a source's `icon_url` or `url` invalidates its cached favicon so
a stale icon doesn't linger. Verified end-to-end with jsdom: opened the
real edit modal by clicking the real Edit button, confirmed the fields
were genuinely pre-filled (not just visually similar), submitted, and
confirmed the source/webhook count stayed the same (a PATCH, not an
accidental duplicate POST) with unedited fields left untouched.

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
for APT/UNC/FIN/TA-style actor codenames). Names match as whole words,
not substrings — substring matching (the original approach) tagged
"threat intelligence" as Intel, "PHP" as HP, "ASAP" as SAP, "continue" as
Conti, "display" as Play, and any hash containing "f5" as F5. Names that
are also everyday words (Play, Oracle, Intel, Meta, Zoom, Apple, Chrome,
Juniper) additionally require their real capitalization, and "Threat
Intel" is explicitly excluded from Intel. Items stored before this fix
keep their old tags until you run **Reprocess all** in Settings. This is deliberately simple —
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
