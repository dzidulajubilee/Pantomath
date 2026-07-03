# Architecture

## Layout

```
Pantomath/
├── backend/
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
└── docs/
```

## Data flow

1. `backend/feeds/scheduler.py` wakes every 20s, checks each enabled source's
   `interval_seconds` against its `last_fetched` timestamp.
2. Due sources get handed to `backend/connectors/registry.get_connector()`,
   which looks up the class for that source's `connector_type` and calls
   its `update()` — the fetch → normalize → validate → store cycle defined
   by `BaseConnector`. The scheduler itself has no RSS-specific code.
3. `RSSConnector.fetch()` calls `backend/feeds/rss.py` (`feedparser`, run in
   a thread pool since it's blocking); `.normalize()` calls
   `backend/feeds/parser.py` to shape entries into the common item dict;
   `.store()` scores severity (`backend/intelligence/scoring.py`) and
   writes to SQLite.
4. Newly-inserted items are broadcast to all connected browsers over
   `/ws`. The frontend prepends them with a slide-in animation.
5. On page load, `GET /api/items` returns whatever's cached — no live
   fetching happens on the request path, so page load stays fast regardless
   of source count or feed size.

## Extensibility: the connector contract

`backend/connectors/base.py` defines `BaseConnector`, an abstract class
with five methods: `fetch()`, `normalize()`, `validate()`, `store()`, and
`update()` (which chains the first four). `RSSConnector` is the only
implementation shipped in v1.0.

Retrieval, parsing/normalization, and storage are deliberately separate
steps — not just separate function calls, but separate *files*
(`backend/feeds/rss.py` vs `backend/feeds/parser.py` vs the `store()`
method) — so each can change independently. A future connector for a
different kind of source (a TAXII feed, a vendor API, anything) is added
by:

1. Implementing `BaseConnector` in a new `backend/connectors/<name>.py`.
2. Adding one line to `CONNECTOR_REGISTRY` in `backend/connectors/registry.py`.

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

`backend/intelligence/tagging.py` does rule-based keyword/pattern
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
`GET /api/sources/{id}/icon`, and `backend/intelligence/enrichment.py`
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
