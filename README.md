# Pantomath

A local, self-hosted threat intelligence dashboard. It polls RSS/Atom feeds
from your threat intel sources and streams new items into a live dashboard
in real time — Dashboard overview, Live Feed, Critical, Vulnerabilities,
Malware, Ransomware, Threat Actors, Vendors, Saved, Sources, Analytics, and
Settings. **Ships with zero pre-loaded sources**, so a fresh install shows
exactly what you configure.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how it's structured internally.

## Install

```bash
# Debian/Ubuntu
sudo dpkg -i pantomath_1.4.0_amd64.deb
sudo apt-get install -f   # pulls in python3/python3-venv if missing

# RHEL/Fedora/CentOS
sudo rpm -i pantomath-1.4.0.x86_64.rpm
```

The installer:
- creates a dedicated unprivileged `pantomath` system user
- sets up an isolated Python venv under `/opt/pantomath/venv` and installs deps
- installs and starts a `systemd` service (`pantomath.service`)
- enables it to start on boot

Open **http://localhost:7373**. The source list is empty — click **+ Add
Source**, paste an RSS/Atom URL, and it starts polling immediately. Leave
the icon field blank and Pantomath fetches the site's favicon for you.

## Fully local, no CDN dependencies

Fonts and sidebar icons are bundled in the repo (`frontend/assets/`), not
loaded from Google Fonts or an icon CDN — works fully offline, and
doesn't leak page-load telemetry to a third party. See
`docs/ARCHITECTURE.md` for licensing details (both OFL/ISC, license
files included alongside the assets).

## Configuration

Everything is managed from the UI:
- **Add a source**: name, RSS/Atom URL, category, optional custom icon, poll interval
- **Pause/resume** a source without deleting its history
- **Remove** a source (its cached items go with it)
- **Filter** the Live Feed by category, severity, or free-text search
- **Save/bookmark** any item (star icon) — shows up under **Saved**
- **Vendors / Threat Actors**: automatically tagged via rule-based keyword
  matching (see `docs/ARCHITECTURE.md`) — click a name to filter
- **Export/Import sources** as JSON (Sources page or Settings)
- **Backup**: download the raw SQLite database (Settings)
- **Light/dark theme**: toggle in the header or Settings; persists locally
- **Desktop notifications**: real browser notifications for new items above
  a severity threshold you set — requires the dashboard tab to stay open
  (see Honest scope notes)
- **History**: nothing is deleted automatically (configurable in Settings
  if you ever want a retention cap). Live Feed has date-range filtering
  and "Load more" pagination to browse whatever's accumulated over time.
- **IOCs**: CVEs, IP addresses, hashes, and emails are automatically
  extracted from every article (rule-based, see
  `docs/ARCHITECTURE.md`). The IOCs page shows top indicators per type
  and a distribution breakdown — click any one to see exactly which
  articles mention it. **Deep extraction** (on by default, toggle in
  Settings) fetches each new article's full page rather than just the
  RSS teaser, since real indicators usually aren't in the short summary.
- **Webhook alerts**: send a POST to any URL when a new item matches a
  keyword, a specific source, and/or a minimum severity — configurable
  in Settings, with a one-click test button. Works over plain HTTP,
  unlike browser notifications.
- **Reprocess stored items** (Settings): re-runs severity/tagging/IOC
  detection against everything already on disk, without re-fetching any
  RSS feed. Use this after an upgrade to backfill data for items stored
  before a detection feature existed.
- **Refresh all now** (Sources page): fetches every enabled source
  immediately rather than waiting for its scheduled interval.
- **Edit sources and webhooks in place** — change a source's URL,
  category, or poll interval, or a webhook's keyword/source/severity
  filter, without deleting and recreating it.
- **Numbered pagination** on Live Feed, with severity/keyword/date
  filters fully server-side for accurate page counts.

Data lives in a single SQLite file: `/var/lib/pantomath/pantomath.db`.
Source icons are fetched once and cached to disk next to it (in an
`icons/` folder) — the browser never repeatedly hits an external favicon
service.

Want a curated starter pack pre-loaded on install (e.g. for fleet
deployment)? Add entries to `config/feeds.json` before building the
package — it's only read on a genuinely empty database, so it never
affects an install that already has sources.

To change the listening port:
```bash
sudo systemctl edit pantomath.service
# [Service]
# Environment=PANTOMATH_PORT=8080
sudo systemctl restart pantomath
```

**Honest scope notes** (things intentionally simplified in this version):
- Vendor/threat-actor tagging is keyword-based, not NLP/ML — see
  `pantomath/intelligence/tagging.py` to tune or extend the lists.
- Desktop notifications only fire while the dashboard tab is open in your
  browser (standard browser Notification API, no background push) — see
  `docs/ARCHITECTURE.md`.
- Light/dark only — no custom theme colors yet.
- RSS itself only exposes a source's most recent items — Pantomath can't
  retroactively pull a year of history a source never published via RSS.
  "Keep forever" (the default) means everything Pantomath *has* seen
  stays browsable; it accumulates real history over time rather than
  fabricating it.
- Deep extraction (fetching full article pages) means more outbound
  requests and a slower first poll for a newly-added source — turn it
  off in Settings if that's not a tradeoff you want. It fails silently
  back to summary-only text on paywalls/timeouts/blocks, never blocks
  storing an item.
- Webhook payloads are a generic JSON shape with a Slack/Discord-compatible
  "text" field, not a native integration for any specific service — full
  native formatting (Slack blocks, Discord embeds) would need a small
  transform in front of the webhook URL.

## Upgrading

After upgrading to a new version, two things are worth doing from
Settings:
1. **Reprocess all stored items** — if the new version added or improved
   any detection (IOCs, tagging, severity scoring), your existing items
   won't have that data until you do this. It's a one-time backfill, not
   something that happens automatically on upgrade.
2. **Hard-refresh your browser tab** (Ctrl+Shift+R / Cmd+Shift+R) once,
   just in case — the dashboard cache-busts its own CSS/JS against the
   installed version automatically, but it's a cheap sanity check after
   a version jump.

## Operating

```bash
sudo systemctl status pantomath
sudo systemctl restart pantomath
journalctl -u pantomath -f
```

Uninstall (keeps data): `sudo apt remove pantomath` / `sudo rpm -e pantomath`
Full purge (wipes data): `sudo apt purge pantomath`

## Building the packages from source

```bash
./build.sh deb     # -> dist/pantomath_<ver>_amd64.deb   (dpkg-deb, no extra tools)
./build.sh rpm     # -> dist/pantomath-<ver>.x86_64.rpm  (requires nfpm)
./build.sh all
```

`nfpm` (https://nfpm.goreleaser.com/) builds the `.rpm` from
`installer/rpm/nfpm.yaml` — no `rpmbuild`/RPM toolchain required.

## Running without installing a package (dev mode)

```bash
make dev              # creates venv/, pip install -e ".[dev]"
source venv/bin/activate
make run              # -> http://localhost:7373
```

Or by hand:
```bash
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
export PANTOMATH_DB=./data/pantomath.db
export PYTHONPATH=.
uvicorn pantomath.app:app --reload --port 7373
```

## Development

Pantomath is a normal installable Python package (`pyproject.toml`), with
a pytest suite and ruff for linting — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full contributor guide.

```bash
make test    # pytest — 34 tests covering dedup, tagging, connector registry, API behavior
make lint    # ruff check
make fmt     # ruff check --fix + format
```

## Previews

### Dashboard

<img width="1920" height="754" alt="Screenshot from 2026-07-06 17-08-37" src="https://github.com/user-attachments/assets/2db27d7e-5792-405a-88eb-38facafffe47" />


<img width="1920" height="907" alt="Screenshot from 2026-07-06 17-08-58" src="https://github.com/user-attachments/assets/50a86854-114c-44fa-880b-6a1da19d4870" />

### Feed Source Management

<img width="1920" height="907" alt="Screenshot from 2026-07-06 17-09-20" src="https://github.com/user-attachments/assets/a4f3b76d-27f5-4d60-ac4c-fb27bc386084" />


### IOCs

<img width="1920" height="907" alt="Screenshot from 2026-07-07 17-33-47" src="https://github.com/user-attachments/assets/1c26694a-1740-4194-9c82-26392eb5ff2c" />

### Settings

<img width="1920" height="907" alt="Screenshot from 2026-07-07 17-33-10" src="https://github.com/user-attachments/assets/29f1eb38-1769-4367-a3c7-7bca1ffcf2b4" />


