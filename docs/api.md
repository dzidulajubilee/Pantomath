# Pantomath API reference

Everything the web interface does goes through this HTTP API, so scripts can
do the same. All paths are relative to the server, for example
`https://pantomath.example`. Requests and responses are JSON unless noted.
How the pieces fit together is in [how-it-works.md](how-it-works.md#9-the-api-layer).

**Contents**

1. [Authentication](#1-authentication)
2. [Conventions and errors](#2-conventions-and-errors)
3. [Sign-in endpoints](#3-sign-in-endpoints)
4. [Items](#4-items)
5. [Indicators and tags](#5-indicators-and-tags)
6. [Dashboard and analytics](#6-dashboard-and-analytics)
7. [Exploited vulnerabilities (read)](#7-exploited-vulnerabilities-read)
8. [Settings-level endpoints](#8-settings-level-endpoints)
9. [WebSocket](#9-websocket)
10. [Examples](#10-examples)

---

## 1. Authentication

Three access levels:

| Level | How to get it | Header or cookie |
|---|---|---|
| **None** | — | Only section 3 and the WebSocket handshake |
| **Signed in** (read everything) | sign in with a password (browser), or create an **API key** in Settings, Security | cookie `pantomath_session`, or `Authorization: Bearer pmk_…` |
| **Settings** (change things) | `POST /api/settings/auth/login` with the Settings password, while signed in | `X-Settings-Token: <token>` (valid one hour) |

For scripts: create an API key, send it as a Bearer token, and for
Settings-level calls also obtain a Settings token:

```bash
KEY="pmk_…"
TOKEN=$(curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"password":"<Settings password>"}' https://pantomath.example/api/settings/auth/login | jq -r .token)
curl -H "Authorization: Bearer $KEY" -H "X-Settings-Token: $TOKEN" https://pantomath.example/api/sources
```

A valid Settings token alone also counts as signed in. When sign-in is turned
off (`PANTOMATH_OPEN_DASHBOARD=1`), "signed in" endpoints need no
credentials.

## 2. Conventions and errors

- Times are Unix timestamps in seconds (UTC), except dates given as
  `YYYY-MM-DD`, which are days in the server's time zone.
- List fields on items (`cves`, `vendors`, `watch_hits`…) are JSON arrays.
- `severity` on items is the **priority**: `critical`, `high`, `medium` or `low`.
- Errors return `{"detail": "readable message"}`:

| Status | Meaning |
|---|---|
| 400 | Invalid input (the message says what) |
| 401 | Not signed in (with header `X-Pantomath-Sign-In: required`), Settings token missing or expired, or a wrong password or code |
| 404 | Not found |
| 409 | Conflict: already set up, not set up yet, a duplicate name |
| 429 | Too many attempts; the message says how long to wait |

## 3. Sign-in endpoints

No credentials needed. These are what the sign-in page uses; scripts should
use API keys instead.

| Method and path | Body | Result |
|---|---|---|
| `GET /api/auth/status` | — | `{signed_in, open, setup_needed, team_password, role, remembered, version}`. Also a good health check |
| `POST /api/auth/login` | `{password, remember}` | Sets the sign-in cookie. `{ok, role}`; with the Settings password also `settings_token` |
| `POST /api/auth/setup` | `{password, setup_code, remember}` | First run only: creates the Settings password. `{ok, role, recovery_code, settings_token}` |
| `POST /api/auth/recover` | `{recovery_code, new_password, remember}` | Resets the Settings password with the recovery code; signs out other Settings-password sign-ins. `{ok, role, recovery_code (new), settings_token}` |
| `POST /api/auth/logout` | — | Ends this sign-in and clears the cookie |

Login, setup and recover share a limit of five failures per address, then
429 for a minute.

## 4. Items

**`GET /api/items`**: items, newest arrivals first (by minute, then newest
published).

| Parameter | Meaning |
|---|---|
| `limit` (100), `offset` (0) | Paging |
| `severity` | One priority or a comma-separated list: `critical,high` |
| `keyword` | Text in the title or summary |
| `source_id`, `category` | One source; one source category (`general`, `government`, `vulnerability`, `news`, `malware`, `research`) |
| `vendor`, `actor` | Items tagged with this vendor or threat actor |
| `ioc_type` + `ioc_value` | Items mentioning an indicator; type `cve`, `ip`, `hash` or `email` |
| `has_cve`, `has_actor` | Only items with at least one CVE / threat actor |
| `affects_us`, `exploited` | Only items marked Affects us / Exploited |
| `bookmarked_only` | Only saved items |
| `date_from`, `date_to` | `YYYY-MM-DD`, by the date Pantomath stored the item |

Each item:

```json
{
  "id": "…", "source_id": "…", "source_name": "Example advisories", "source_color": "#34d399",
  "category": "vulnerability", "title": "…", "link": "https://…", "summary": "…",
  "published": 1790600000.0, "fetched_at": 1790603600.0,
  "severity": "critical", "content_severity": "high", "content_keyword": "remote code execution",
  "priority_reasons": ["Exploited: CVE-2026-1234 on CISA's list", "Affects us: VPN gateway", "Wording: mentions “remote code execution”"],
  "vendors": [], "actors": [], "cves": ["CVE-2026-1234"], "ips": [], "hashes": [], "emails": [],
  "watch_hits": ["VPN gateway"], "kev_cves": ["CVE-2026-1234"], "bookmarked": false
}
```

| Endpoint | Purpose |
|---|---|
| `GET /api/items/count` | `{total}` for the same filters |
| `GET /api/items/range` | Earliest and latest stored times |
| `PATCH /api/items/{id}/bookmark?bookmarked=true` | Save or unsave an item (shared by everyone) |

## 5. Indicators and tags

| Endpoint | Parameters | Returns |
|---|---|---|
| `GET /api/iocs` | `type` (`cve`), `limit` (20), `offset`, `date_from`, `date_to`, `detail`, `q` | Distinct values, most mentioned first: `[{name, count}]`. With `detail=1` also `sources`, `severity` (highest priority), `first_seen`, `last_seen` (all time); `q` filters by text |
| `GET /api/iocs/summary` | `date_from`, `date_to` | Distinct values per type: `{cve, ip, hash, email}` |
| `GET /api/iocs/calendar` | `type`, `date_from`, `date_to` | Per day: `[{date, count, articles}]`, where `count` = distinct values seen that day |
| `GET /api/tags` | `type` (`vendor` or `actor`), `limit` (20) | `[{name, count}]`, most mentioned first |

To list every item mentioning an indicator, use
`/api/items?ioc_type=ip&ioc_value=203.0.113.7`.

## 6. Dashboard and analytics

**`GET /api/overview?hours=24&since=<timestamp>`**: everything the dashboard
and header need. `hours` is the time range; `since` is the "new since you
last looked" mark. Includes counts in the range (`high_in_window`, meaning
Critical or High, and `critical_in_window`), `new_since`, indicator and
published counts for the week, per-day counts for the last 7 days,
`attention` (up to 8 Critical and High items), source health (states and
reasons, never addresses), `affects_us` `{items, exploited, watchlist}` and
`exploited` `{items, catalog, enabled}`.

**`GET /api/analytics?days=30`** (`days` from 1 to 365): `totals` and
`previous` (per priority, and `items`), `by_day`, `by_category`,
`top_sources`, `top_vendors`, `top_actors`, `indicators` (distinct per type),
`active_sources`, and `heatmap` (7 × 24 counts, weekday 0 = Sunday, server
time).

`GET /api/stats` returns older overall counts kept for compatibility.

## 7. Exploited vulnerabilities (read)

`GET /api/kev?cves=CVE-2026-1234,CVE-2026-5678` returns up to 50 catalog
entries: `cve, vendor, product, name, date_added, due_date, ransomware,
description`.

## 8. Settings-level endpoints

All need `X-Settings-Token`.

**Settings password and unlock** (these need to be signed in, not a token):

| Endpoint | Body | Purpose |
|---|---|---|
| `GET /api/settings/auth/status` | — | Whether a Settings password exists |
| `POST /api/settings/auth/login` | `{password}` | `{token}`: a Settings token for one hour |
| `POST /api/settings/auth/recover` | `{recovery_code, new_password}` | Reset with the recovery code |
| `POST /api/settings/auth/logout` | header `X-Settings-Token` | End that Settings token |
| `POST /api/settings/auth/setup` | `{password, setup_code}` | First-run setup from inside the app; needs the setup code unless sign-in is turned off (the sign-in page uses `/api/auth/setup`) |

**Sources**

| Endpoint | Purpose |
|---|---|
| `GET /api/sources` | All sources with health fields, `items_today`, `items_total` |
| `POST /api/sources` | Add: `{name, url, category, color, icon_url, connector_type ("rss"), interval_seconds}` |
| `PATCH /api/sources/{id}` | Change any of those fields, or `enabled` |
| `DELETE /api/sources/{id}` | Remove it and its items |
| `POST /api/sources/test` | `{url}`: test without saving: `{ok, format, title, items, newest_published, items_with_cve}` or `{ok: false, error}` |
| `POST /api/sources/{id}/poll` | Check one source now |
| `POST /api/sources/poll-all` | Check every enabled source now |
| `GET /api/sources/export`, `POST /api/sources/import` | `{"sources": [...]}`; import skips duplicates |
| `GET /api/connectors` | Available source types |
| `GET /api/sources/{id}/icon` | The cached icon (signed-in level) |

**Our stack and exploited vulnerabilities**

| Endpoint | Purpose |
|---|---|
| `GET /api/watchlist` | Entries with how many items each marks |
| `POST /api/watchlist` | `{name, aliases}` (aliases comma-separated); re-checks all items; `{id, items_marked}` |
| `PATCH /api/watchlist/{id}`, `DELETE /api/watchlist/{id}` | Change or remove; re-checks all items |
| `GET /api/kev/status` | `{enabled, url, default_url, count, updated_at, checked_at, error}` |
| `PATCH /api/kev/settings` | `{enabled, url}`; an empty url means CISA's official feed |
| `POST /api/kev/refresh` | Download now; returns the status |

**Sign-ins, API keys, team password**

| Endpoint | Purpose |
|---|---|
| `GET /api/auth/sessions` | `{devices, api_keys}`, each with `id, label, role, remember, created_at, last_seen, expires_at, ip, current` |
| `DELETE /api/auth/sessions/{id}` | Sign a device out or revoke a key |
| `POST /api/auth/sessions/sign-out-others` | Every browser except this one |
| `POST /api/auth/api-keys` | `{label}` → `{id, key}` (the key is shown only here) |
| `PUT /api/auth/team-password` | `{password}`; signs out the team |
| `DELETE /api/auth/team-password` | Remove it; signs out the team |

**Webhooks**

| Endpoint | Purpose |
|---|---|
| `GET /api/webhooks` | All webhooks (protected ones with the URL masked) |
| `POST /api/webhooks` | `{name, url, keyword, source_id, min_severity ("", "low", "medium", "high", "critical"), enabled, allow_insecure_tls, only_affects_us, only_exploited, key}` |
| `PATCH /api/webhooks/{id}` | Change fields (protected webhooks need their `key`) |
| `POST /api/webhooks/{id}/reveal` | The real URL (with the key if protected) |
| `POST /api/webhooks/{id}/test` | Send a sample payload now |
| `DELETE /api/webhooks/{id}` | Remove |

The payload sent to a webhook is shown in the
[user guide](user-guide.md#14-alerts-desktop-notifications-and-webhooks).

**Settings, storage, backup**

| Endpoint | Purpose |
|---|---|
| `GET /api/settings`, `POST /api/settings` | Key/value settings, e.g. `{"deep_extraction": "1", "retention_days": "90"}` |
| `POST /api/reprocess` | `{source_id?, deep_extraction?}`: re-run the analysis on stored items |
| `GET /api/backup` | The database file |
| `POST /api/restore` | Multipart upload of a backup file (replaces everything) |

## 9. WebSocket

`/ws` (same host, `wss://` behind HTTPS). The browser's sign-in cookie is
checked when it connects; without a valid one the connection is closed with
code **4401**. Messages are JSON:

- `{"type": "new_items", "items": [ …items as in section 4… ]}`: just stored;
- `{"type": "sources_changed"}`: a source was added, changed or removed.

## 10. Examples

Critical and high items from the last 24 hours:

```bash
curl -s -H "Authorization: Bearer $KEY" \
  "https://pantomath.example/api/items?severity=critical,high&limit=100" \
  | jq --argjson since "$(date -d '24 hours ago' +%s)" '.[] | select(.fetched_at > $since) | {severity, title, link, reasons: .priority_reasons}'
```

A firewall blocklist of every IP address mentioned this week:

```bash
curl -s -H "Authorization: Bearer $KEY" \
  "https://pantomath.example/api/iocs?type=ip&limit=10000&date_from=$(date -d '7 days ago' +%F)" \
  | jq -r '.[].name' > pantomath-ips.txt
```

Everything that affects your stack and is being exploited:

```bash
curl -s -H "Authorization: Bearer $KEY" "https://pantomath.example/api/items?affects_us=true&exploited=true"
```
