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
  `backend/intelligence/tagging.py` to tune or extend the lists.
- Desktop notifications only fire while the dashboard tab is open in your
  browser (standard browser Notification API, no background push) — see
  `docs/ARCHITECTURE.md`.
- Light/dark only — no custom theme colors yet.

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
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export PANTOMATH_DB=./data/pantomath.db
export PYTHONPATH=.
uvicorn backend.app:app --reload --port 7373
```
