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
9. [IOC database](#9-ioc-database)
10. [Lookup API for SIEMs (/api/v1)](#10-lookup-api-for-siems-apiv1)
11. [WebSocket](#11-websocket)
12. [Examples](#12-examples)

---

## 1. Authentication

Three access levels:

| Level | How to get it | Header or cookie |
|---|---|---|
| **None** | — | Only section 3 and the WebSocket handshake |
| **Signed in** (read everything) | sign in with a password (browser), or create an **API key** in Settings, Security | cookie `pantomath_session`, or `Authorization: Bearer pmk_…` |
| **Settings** (change things) | `POST /api/settings/auth/login` with the Settings password, while signed in | `X-Settings-Token: <token>` (valid one hour) |
| **SIEM** (the lookup API only) | create a **SIEM key** in Settings, Security | `Authorization: Bearer pms_…`, accepted by `/api/v1` and nothing else (section 10) |

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
  `YYYY-MM-DD`, which are days in the server's time zone, and the lookup
  API (`/api/v1`), which uses ISO 8601 times.
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
| 503 | The IOC database (`ioc.db`) can't be opened; the message says why. Only sections 9 and 10 |

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
| `keyword` | Words to find; each must appear in the title, summary, source name, vendors, actors, indicators, Our stack matches or KEV CVEs, in any order |
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
| `POST /api/auth/siem-keys` | `{label}` → `{id, key}`: a key for `/api/v1` only (shown only here). `GET /api/auth/sessions` lists them as `siem_keys`; revoke with `DELETE /api/auth/sessions/{id}` |
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
[user guide](user-guide.md#15-alerts-desktop-notifications-and-webhooks).

**Settings, storage, backup**

| Endpoint | Purpose |
|---|---|
| `GET /api/settings`, `POST /api/settings` | Key/value settings, e.g. `{"deep_extraction": "1", "retention_days": "90"}` |
| `POST /api/reprocess` | `{source_id?, deep_extraction?}`: re-run the analysis on stored items |
| `GET /api/backup` | The database file |
| `POST /api/restore` | Multipart upload of a backup file (replaces everything) |

## 9. IOC database

The IOC database (1.0.0) keeps indicators published by IOC feeds or added by
your team, in its own file (`ioc.db`). Browsing and looking up need sign-in;
everything that changes it needs a Settings token, like Sources. If `ioc.db`
can't be opened these endpoints return **503** with the reason, and the rest
of the API is unaffected.

An indicator has a `type` (`ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`,
`sha1`, `sha256`, `ja3`, `ja4`, `x509`), a normalized `value`, a
`confidence` from 0 to 100, a `status` (`active`, `expired`,
`false_positive`, `allowlisted`), `threat_type`, `malware`, `campaign`,
`tags`, `note`, and `first_seen`, `last_seen` and `expires_at` (0 = never).
Each source that reports it is a **sighting**. Filters that take a `type`
also accept the groups `ip`, `hash` and `network` (JA3, JA4 and
certificates), or several types separated by commas.

**Signed in**

| Endpoint | Parameters | Returns |
|---|---|---|
| `GET /api/ioc/summary` | — | `{active, by_type, by_status, added_today, expiring_week, malware: [{name, count}], feeds: {total, enabled, ok, failing, list}, last_feed_update, siem: {lookups_today, matches_today, indicators_seen_week}}` |
| `GET /api/ioc/indicators` | `type`, `q` (words in the value, malware, campaign, threat type, tags or note), `status` (`active`; several with commas, or `all`), `min_confidence`, `malware`, `source` (a feed id, `manual` or `promoted`), `seen_days` (only ones your SIEMs looked up in that many days, today included), `limit` (50, at most 200), `offset` | `{total, items}`; each item also has `sources` (how many report it now) and `hits_week` (SIEM lookups in 7 days) |
| `GET /api/ioc/indicators/{id}` | — | The indicator with `sightings` (`source_name`, `confidence`, `reference`, `first_seen`, `last_seen`, `active`, `context`), `confidence_explained` and `siem_hits: {today, week, days_90, last_hit}` |
| `GET /api/ioc/indicators/{id}/mentions` | `limit` (5) | Stored news items that mention it: `{count, items: [{id, title, link, severity, fetched_at, source_name}], field}`. IPs, hashes and emails match the extracted values (`field` is `ips`, `hashes` or `emails`); other types are found in titles and summaries (`field` null) |
| `POST /api/ioc/lookup` | `{values: [...], include_expired}` | As `/api/v1/lookup` (section 10), plus each stored value's `id`, and for a miss the `status` or the `reason` it can't match |

**Settings-level**

| Endpoint | Purpose |
|---|---|
| `POST /api/ioc/indicators` | Add by hand: `{text, format ("text" or "csv"), value_column, type ("" detects), confidence, threat_type, malware, campaign, lifetime_days (0 each type's default, -1 never), reference, note, promoted}` → `{added, updated, rejected, rejected_samples, allowlisted, false_positive}`. `promoted: true` files them under the source *Promoted from the news* |
| `PATCH /api/ioc/indicators/{id}` | `{status ("active" or "false_positive"), confidence (null goes back to the sources' number), threat_type, malware, campaign, tags, note}` |
| `DELETE /api/ioc/indicators/{id}` | Remove it and its sightings. A feed that still lists it adds it again; mark it a false positive to keep it out |
| `GET /api/ioc/feeds` | `{feeds, manual, promoted, readers}`: every feed with its health (`last_status`, `last_success`, `last_count`, `last_new`, `last_dropped`, `last_rejected`), `indicators` (active ones it reports) and `has_key`. The key itself is never returned |
| `POST /api/ioc/feeds/test` | The fields below, without saving: `{ok, lines, valid, skipped, rejected, rejected_samples, by_type, sample, columns, preview_rows, value_column, duration_ms}` or `{ok: false, error}` |
| `POST /api/ioc/feeds` | `{name, url, format, value_column, date_column, malware_column, default_type, confidence, threat_type, lifetime_days, interval_seconds (at least 900), enabled, snapshot, max_mb (1-500), key_header, key_value}`. `format` is `text`, `csv` or a built-in reader: `threatfox`, `urlhaus`, `malwarebazaar`, `feodo`, `sslbl`, `abuseipdb` (each one's defaults are in `readers` above; `abuseipdb` at least every 18,000 s) |
| `PATCH /api/ioc/feeds/{id}` | Change fields; an empty `key_value` keeps the stored key, `clear_key: true` removes it |
| `POST /api/ioc/feeds/{id}/run` | Download it now: `{ok, values, new, refreshed, unchanged, dropped, rejected}`, `{ok: true, unchanged: true}` if the list hasn't changed, or `{ok: false, error}` |
| `DELETE /api/ioc/feeds/{id}` | Remove it; indicators only it reported expire now |
| `GET /api/ioc/backup` | A consistent copy of `ioc.db` (it holds the feeds' keys) |
| `GET /api/ioc/settings`, `PATCH /api/ioc/settings` | `{keep_expired_days}`: how long expired indicators are kept before deletion: 30, 90 (default), 180, 365 or 730, or 0 for ever |
| `GET /api/ioc/allowlist`, `POST /api/ioc/allowlist`, `DELETE /api/ioc/allowlist/{id}` | `{value, reason}`: an IP, a range (`198.51.100.0/24`), a domain (covers subdomains, and URLs and emails on them) or any exact value |

## 10. Lookup API for SIEMs (/api/v1)

A small, versioned contract for SIEMs, firewalls and scripts. It stays put
while the dashboard's own `/api` routes change with the interface. It is
read-only and only accepts **SIEM keys** (`Authorization: Bearer pms_…`);
browser sessions and ordinary API keys get 401. Times here are ISO 8601 in
UTC (`2026-10-18T22:40:00Z`).

Lookups return only active indicators unless `include_expired` is true, and
never false positives or allowlisted values. Pantomath works out each
value's type and restores defanged text. A miss is a normal `200` with
`"match": false`.

| Endpoint | Parameters | Returns |
|---|---|---|
| `GET /api/v1/lookup` | `value`, `include_expired` | One result, as below |
| `POST /api/v1/lookup` | `{values: [...] (up to 1,000), include_expired}` | `{checked, matched, results}` |
| `GET /api/v1/export` | `type`, `min_confidence`, `malware`, `feed` (a feed id or `manual`), `format` (`txt`, `csv`, `json` or `cdb`), `since`, `include_expired` | Whole lists, streamed. See below |
| `GET /api/v1/health` | — | `{status ("ok" or "degraded" when a feed is failing), version, indicators: {active, by_type}, feeds: {total, enabled, failing}, last_feed_update, generated_at}` |

```
POST /api/v1/lookup
Authorization: Bearer pms_…
{"values": ["203.0.113.45", "login-secure-update.example", "198.51.100.200"]}

{"checked": 3, "matched": 2, "results": [
  {"value": "203.0.113.45", "type": "ipv4", "match": true, "status": "active",
   "confidence": 85, "threat_type": "c2", "malware": "QakBot", "campaign": null,
   "first_seen": "2026-10-02T09:14:00Z", "last_seen": "2026-10-18T22:40:00Z",
   "expires_at": "2026-11-17T22:40:00Z",
   "sources": [{"name": "ThreatFox", "confidence": 75, "reference": "https://…"},
               {"name": "Feodo Tracker", "confidence": 75}]},
  {"value": "login-secure-update.example", "type": "domain", "match": true, …},
  {"value": "198.51.100.200", "type": "ipv4", "match": false}]}
```

When a value is stored in a different spelling (`HXXP://Evil[.]Example/`),
the result also has `normalized`.

**Export.** Without `since`, the values that match now: `txt` is one value
per line, ready for a firewall's external block list;
`csv` and `json` add `type, value, status, confidence, threat_type, malware,
campaign, first_seen, last_seen, expires_at`. With `since` (a Unix time or
ISO time), every indicator that changed after it, **whatever its status**,
so an incremental sync can also remove what expired or was marked a false
positive (`txt` lists only the active ones, since it can't say more). Send
the response's `X-Pantomath-Exported-At` header as the next `since`. It is
rounded down to the second, so a change made during an export is sent again
next time rather than missed. Deleted indicators don't appear; a full export
now and then catches those.

`cdb` is a Wazuh CDB list: one `key:confidence` line per indicator, keys
containing a colon (URLs, IPv6) in double quotes. It is always the whole
list (`since` is refused), since Wazuh reloads lists only on restart.

High-volume SIEMs should pull `export?since=` every few minutes and match
locally, rather than call `lookup` per event.

Every `lookup` that matches counts a hit for that indicator, shown on the
IOC database tab ("which indicators your network actually touched"). Hits
are added up in memory and written every 30 seconds, so lookups never write
to the database; exports don't count.

## 11. WebSocket

`/ws` (same host, `wss://` behind HTTPS). The browser's sign-in cookie is
checked when it connects; without a valid one the connection is closed with
code **4401**. Messages are JSON:

- `{"type": "new_items", "items": [ …items as in section 4… ]}`: just stored;
- `{"type": "sources_changed"}`: a source was added, changed or removed.

## 12. Examples

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

Keep a firewall's block list of confident C2 addresses up to date (a SIEM key):

```bash
curl -s -H "Authorization: Bearer $SIEM_KEY" \
  "https://pantomath.example/api/v1/export?type=ip&min_confidence=70&format=txt" > c2-ips.txt
```

Check a handful of values from an alert:

```bash
curl -s -H "Authorization: Bearer $SIEM_KEY" -H "Content-Type: application/json" \
  -d '{"values": ["203.0.113.45", "hxxp://login-secure-update[.]example/"]}' \
  https://pantomath.example/api/v1/lookup | jq '.results[] | select(.match)'
```
