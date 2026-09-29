# Pantomath administration guide

Installing, securing, running and upgrading Pantomath. For using it, see the
[user guide](user-guide.md); for how it works inside, see
[how-it-works.md](how-it-works.md).

**Contents**

1. [Requirements](#1-requirements)
2. [Installing](#2-installing)
3. [First-time setup](#3-first-time-setup)
4. [Passwords and sign-in](#4-passwords-and-sign-in)
5. [Admin commands](#5-admin-commands)
6. [HTTPS](#6-https)
7. [Network: ports and outbound connections](#7-network-ports-and-outbound-connections)
8. [Running the service](#8-running-the-service)
9. [Data, backups and retention](#9-data-backups-and-retention)
10. [Upgrading](#10-upgrading)
11. [Monitoring](#11-monitoring)
12. [Security checklist](#12-security-checklist)
13. [Troubleshooting](#13-troubleshooting)
14. [Uninstalling](#14-uninstalling)

---

## 1. Requirements

- Linux on x86_64 with systemd. The Debian/Ubuntu package is built and tested
  on Ubuntu 24.04. An RPM spec exists but is untested (see the README's known
  limitations).
- Python 3.10 to 3.13 with `venv` (Debian/Ubuntu: the `python3-venv`
  package). The package bundles Python wheels for exactly these versions, so
  it installs without internet access.
- Disk: the database grows with history; a few hundred MB covers a long
  time for a typical set of feeds. Restoring a backup needs free space for
  the upload plus a copy of the current database.
- For HTTPS through `pantomath-admin setup-https`: Debian or Ubuntu (it
  installs nginx with `apt-get`).

## 2. Installing

**From the repository** (recommended; the package is built on the machine):

```bash
sudo apt install python3-venv git
git clone https://github.com/dzidulajubilee/Pantomath.git
cd Pantomath
./build.sh deb                      # -> dist/pantomath_<version>_amd64.deb
sudo dpkg -i dist/pantomath_*_amd64.deb
```

`build.sh` reads the version with Python 3.11's `tomllib`. On Python 3.10
(Ubuntu 22.04), pass it yourself: `VERSION=0.8.1 ./build.sh deb`.

**A ready-made package:** copy it to the server, compare `sha256sum` with the
published checksum (a truncated copy fails halfway through unpacking), then
`sudo dpkg -i pantomath_<version>_amd64.deb`.

**What the installer does:**

1. creates the `pantomath` system user (no login shell, no home directory);
2. creates `/var/lib/pantomath` for the data, owned by that user;
3. builds a private Python environment in `/opt/pantomath/venv` from the
   bundled wheels (falling back to the internet only if the package was built
   without them);
4. links `pantomath-admin` into `/usr/local/bin`;
5. installs, enables and starts the `pantomath` systemd service;
6. on a new install, creates the **setup code** and prints it (next section).

Pantomath starts with **no sources**. To pre-load a starter list on new
installs (for a fleet of servers, say), put them in `config/feeds.json`
before building the package. It's only read when the database has no
sources at all.

## 3. First-time setup

A new install has no passwords. The first-run page creates the **Settings
password**, and it only does so for someone who also has the **setup code**
printed by the installer:

```
==================== First-time setup ====================
  Open http://panther:7373 and enter this setup code on the
  Welcome screen to create the Settings password:

      K7QM-4XPA-9HTE

  Nobody can set Pantomath up without it. Show it again with:
      sudo pantomath-admin setup-code
==========================================================
```

The code means someone else on the network can't claim a fresh install
before you do. It's stored as a hash in the database, and in plain form only
in `/var/lib/pantomath/setup-code` (readable only by the service user and
root, never written to the logs). It's deleted as soon as the Settings
password exists.

**Recommended order:**

1. `sudo pantomath-admin setup-https` (section 6), so the first password
   never crosses the network in plain HTTP.
2. Open Pantomath in a browser. The **Welcome to Pantomath** page asks for:
   - the setup code (spaces, dashes and upper/lower case don't matter);
   - a new Settings password (at least 8 characters, typed twice).
3. Save the **recovery code** it shows. It's shown once, and it resets the
   Settings password from the sign-in page if the password is ever lost.
4. In Settings, Security, set a **team password** for everyone who only needs
   to view Pantomath.
5. In Settings, add **Our stack** (what you run) and check that **Exploited
   vulnerabilities** could download CISA's catalog.
6. Add sources (the **+ Add source** button), testing each one.
7. Sign the wall screen in with the team password, ticking **Remember this
   device**.

## 4. Passwords and sign-in

**Roles**

| Signed in with | Role | Can |
|---|---|---|
| Team password | team | View everything |
| Settings password | admin | View everything; Settings and Sources are unlocked straight away |
| API key | api | Read everything through the API; change nothing |

Settings and Sources always need the Settings password: team members who
open them are asked for it. An unlocked Settings page stays unlocked for an
hour.

**Rules:** passwords need at least 8 characters, and the team password can't
be the same as the Settings password, so viewers can never change settings.

**Sign-in lifetime:** with *Remember this device*, 90 days since last use;
otherwise until the browser closes, or 12 idle hours. Sign-ins are stored in
the database, so they survive restarts and upgrades.

**Attempt limits:** five wrong passwords, setup codes or recovery codes from
one address lock that address out for a minute. The Settings unlock prompt
inside the app has its own limit (five wrong attempts lock it for a
minute).

**What signs people out:**

| Event | Who is signed out |
|---|---|
| Team password changed or removed | Everyone signed in with the team password |
| Settings password reset (recovery code or `reset-settings-password`) | Everyone signed in with the Settings password |
| Settings, Security: *Sign out* on a device | That device |
| Settings, Security: *Sign out all other devices* | Every browser except yours (API keys stay) |
| `sudo pantomath-admin sign-out-everyone` | Every browser (add `--api-keys` to revoke keys too) |
| `sudo pantomath-admin reset-settings-password --clear` | Every browser (back to first-run setup) |

A running Pantomath notices sign-outs made from the command line within
30 seconds. Settings pages already unlocked in a browser stay unlocked for
up to an hour after a Settings password reset.

**Lost passwords:**

- *Team password:* set a new one in Settings, Security.
- *Settings password, recovery code at hand:* **Forgot the Settings
  password?** on the sign-in page (or *Reset with recovery code* in the
  Settings unlock prompt). You get a new recovery code.
- *Settings password and recovery code both lost:* on the server,
  `sudo pantomath-admin reset-settings-password` (next section).

**Sign-in off:** installations already behind an authenticating reverse
proxy (single sign-on) can set `PANTOMATH_OPEN_DASHBOARD=1` in the service
environment (section 8). Pantomath's own sign-in is then skipped entirely,
and anyone who reaches Pantomath through the proxy can view it. Settings
still need the Settings password, which is then created in Settings itself
on first use; with sign-in off, the proxy is the gate, so no setup code is
asked for. Only do this if the proxy really
authenticates everyone.

## 5. Admin commands

Run on the server. Commands that touch the database, when run with `sudo`,
continue as the owner of the database folder (the `pantomath` user), so they
never leave root-owned database files that would stop the service.

```
sudo pantomath-admin setup-code [--bare]
```

Shows the one-time setup code while Pantomath hasn't been set up, or says it
already has been. `--bare` prints just the code (or nothing), for scripts.

```
sudo pantomath-admin reset-settings-password [--clear]
```

Asks for a new Settings password in the terminal (twice), sets it, signs out
everyone signed in with the old one, and prints a new recovery code. When
input isn't a terminal, it reads the password from the first line of
standard input. With `--clear` it removes the Settings password instead and
goes back to first-run setup: everyone is signed out (API keys keep working)
and a new setup code is printed. Items, sources,
webhooks, the team password and settings are never touched.

```
sudo pantomath-admin sign-out-everyone [--api-keys]
```

Ends every browser sign-in (and, with `--api-keys`, revokes every API key).
For when a device is lost or you suspect a password leaked. Change the
passwords afterwards.

```
sudo pantomath-admin setup-https [--port 7373] [--yes]
```

Puts nginx with HTTPS in front of Pantomath (next section).

## 6. HTTPS

Over plain HTTP, passwords and session cookies cross the network readable,
and browsers refuse desktop notifications. On anything but a trusted
network, use HTTPS:

```bash
sudo pantomath-admin setup-https
```

It:

- installs nginx (Debian/Ubuntu, with `apt-get`);
- creates a self-signed certificate (an existing one is kept, so anything that
  already trusts it keeps working);
- adds an nginx site that forwards to Pantomath;
- renames nginx's stock default site rather than deleting it;
- checks the configuration with `nginx -t` before reloading;
- offers to restrict Pantomath to `127.0.0.1`, so nginx becomes the only way
  in (recommended).

It asks before every change unless you pass `--yes`, and it's safe to run
again. Browsers warn about a self-signed certificate until it's trusted;
for a company-wide setup, replace it with a certificate from your internal
CA in the nginx site configuration.

Behind HTTPS, Pantomath marks its sign-in cookie *Secure* automatically
(nginx tells it the original request was HTTPS).

## 7. Network: ports and outbound connections

**Listening:** port **7373** on every interface (`0.0.0.0`), or only on
`127.0.0.1` after `setup-https` restricts it. Limit who can reach it with a
firewall either way.

**Outbound connections Pantomath makes:**

| To | When | Needed for |
|---|---|---|
| Each source's feed address | Every poll | Collecting items |
| Article pages linked from feeds | Once per new item, with deep extraction on | Better ratings and indicators (8 s timeout, first 400 KB) |
| `www.google.com/s2/favicons` | Once per source (cached; a failure is retried after an hour) | Source icons |
| `www.cisa.gov` | Once a day (hourly retries after a failure) | The Exploited marks |
| Each webhook's address | When a new item matches | Alerts |
| `pypi.org` | At install, only if the package has no bundled wheels | Installing |

**Without internet access:** feeds on your network still work; turn deep
extraction off if article pages aren't reachable; source icons fall back to
colour dots (or set an *Icon URL* per source); point Settings, Exploited
vulnerabilities, *Catalog address* at an internal copy of CISA's JSON file,
refreshed however you like (for example a daily `curl` on a machine that can
reach `cisa.gov`).

Feed fetching limits: 15 s without data ends a read, 45 s is the most one
feed may take in total, and a feed larger than 10 MB is rejected. Sources are
checked one after another, so a slow or broken feed can delay the others by
at most about a minute, but it can never stall collection.

## 8. Running the service

```bash
sudo systemctl status pantomath
sudo systemctl restart pantomath
sudo journalctl -u pantomath -f          # live log
```

**Environment variables** (set with `sudo systemctl edit pantomath`, then a
restart):

| Variable | Default | Meaning |
|---|---|---|
| `PANTOMATH_PORT` | `7373` | Port to listen on |
| `PANTOMATH_DB` | `/var/lib/pantomath/pantomath.db` | Database file (the setup code and icons live next to it) |
| `PANTOMATH_ICON_CACHE` | `icons/` next to the database | Where source icons are cached |
| `PANTOMATH_OPEN_DASHBOARD` | unset | `1` turns Pantomath's own sign-in off (section 4) |

Example, changing the port:

```bash
sudo systemctl edit pantomath.service
# [Service]
# Environment=PANTOMATH_PORT=8080
sudo systemctl restart pantomath
```

The service runs as `pantomath` with systemd hardening: no new privileges,
a read-only system except `/var/lib/pantomath`, no access to home directories,
and a private `/tmp`.

## 9. Data, backups and retention

**Files:**

| Path | Contents |
|---|---|
| `/var/lib/pantomath/pantomath.db` | Everything: items, sources, settings, webhooks, Our stack, CISA's catalog, sign-ins. SQLite in WAL mode, so `-wal` and `-shm` files sit next to it |
| `/var/lib/pantomath/icons/` | Cached source icons |
| `/var/lib/pantomath/setup-code` | The one-time setup code, only until first-run setup is done |
| `/opt/pantomath/` | The application and its Python environment |

**Backups:**

- From the browser: Settings, Backup and restore, **Download backup**.
- From the command line, safely while Pantomath runs (needs the `sqlite3`
  package; run as the service user so no root-owned files appear next to
  the database):

  ```bash
  sudo -u pantomath sqlite3 /var/lib/pantomath/pantomath.db ".backup /tmp/pantomath-backup.db"
  sudo mv /tmp/pantomath-backup.db /var/backups/pantomath-$(date +%F).db
  ```

A backup contains the password hashes, sign-in records and webhook
addresses, so store it as carefully as the server itself.

**Restoring:** Settings, Backup and restore, **Restore from file**. The file
must be a Pantomath SQLite database (checked before anything changes) of at
most 2 GB. The current database is copied to a timestamped safety copy next
to it first, then replaced in one step. Older backups are brought up to date
automatically (new tables and columns are added, and items get their
priority worked out).

**Retention:** nothing is deleted unless you choose a limit in Settings,
Storage, *Keep items for*. The check runs about once an hour.

**Reprocessing:** Settings, Storage, *Reprocess all* re-rates and re-extracts
every stored item with the current rules, without re-reading feeds.

## 10. Upgrading

Install the new package over the old one:

```bash
sudo dpkg -i pantomath_<new version>_amd64.deb
```

Data and settings are kept, database changes are applied automatically when
the service starts, and sign-ins survive. Then hard-refresh open browsers
once (Ctrl+Shift+R).

**Version notes:**

| Upgrading past | Do this |
|---|---|
| 0.4.5 | Settings, Storage, *Reprocess all* (tagging and rating fixes) |
| 0.6.0 | Nothing; source health history starts recording |
| 0.7.0 | Add Our stack; check the CISA catalog downloads |
| 0.8.0 | Sign-in is now required. Sign in with the Settings password, set a team password, sign the wall screen in again. Optionally *Reprocess all* (tighter wording rules) |
| 0.8.1 | Nothing, unless the install never had a Settings password: then use `sudo pantomath-admin setup-code` |

## 11. Monitoring

- **The header** of any open Pantomath: failing sources, and **Not updating**
  when no data has arrived for two minutes.
- **Sources page**: each feed's state, reason, last success and response time.
- **Settings, Exploited vulnerabilities**: when the catalog last downloaded,
  or why it couldn't.
- **The journal** (`journalctl -u pantomath`): startup (including "not set
  up yet"), unexpected scheduler errors, catalog download failures and
  retention clean-ups. Individual feed failures are shown on the Sources page
  rather than logged; webhook delivery results appear in Settings, Alerts.
- **A health check for monitoring tools:** `GET /api/auth/status` answers
  without signing in and returns JSON with the version; anything else needs
  an API key.

## 12. Security checklist

- [ ] HTTPS in front (`setup-https`), with Pantomath restricted to `127.0.0.1`.
- [ ] A firewall limiting port 443 (or 7373) to the networks that need it.
- [ ] Distinct Settings and team passwords; the Settings password known to
      few people; the recovery code stored in a password manager.
- [ ] Remember this device only on the wall screen and personal computers.
- [ ] Review Settings, Security, *Signed-in devices* now and then; revoke
      API keys no longer used.
- [ ] Backups stored as carefully as the server.
- [ ] Feed addresses that contain API keys are only visible in Settings and
      Sources, and in source exports, so treat exports as confidential.

What Pantomath protects by design: all data needs a sign-in; passwords,
recovery codes, setup codes and webhook keys are stored as salted PBKDF2
hashes (200,000 iterations); sign-in tokens only as SHA-256 fingerprints;
the sign-in cookie is HttpOnly and SameSite=Strict; the Our stack list is
only readable in Settings; making the server fetch an arbitrary address
(testing feeds, the catalog address) needs the Settings password.

## 13. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| The Welcome page rejects the setup code | Show the current code with `sudo pantomath-admin setup-code`. Five wrong tries lock that computer for a minute |
| Nobody can sign in | Check the passwords; if the Settings password is lost, use the recovery code on the sign-in page, or `sudo pantomath-admin reset-settings-password` |
| "Too many attempts. Try again in N seconds" | Five wrong tries from that address; wait a minute |
| The wall screen shows the sign-in page | The team password changed, or the device was signed out; sign in again with Remember this device |
| **Not updating** in the header | The browser lost the server: check the service (`systemctl status pantomath`) and the network |
| A source is **Failing** | The reason is on the Sources page; *Test* rechecks it |
| Exploited items never appear | Settings, Exploited vulnerabilities shows the download status; without internet, set an internal catalog address |
| Desktop notifications blocked | They need HTTPS (section 6) |
| The service won't start after a manual database operation | Files in `/var/lib/pantomath` owned by root: `sudo chown -R pantomath:pantomath /var/lib/pantomath` |
| Restore refused | Not a Pantomath database, over 2 GB, or not enough free disk space for the upload plus a safety copy |

## 14. Uninstalling

```bash
sudo apt remove pantomath      # keeps /var/lib/pantomath (your data)
sudo apt purge pantomath       # removes the data too
```
