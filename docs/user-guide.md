# Pantomath user guide

How to use Pantomath day to day: reading the feed, finding what affects
you, working with indicators, and (for administrators) managing sources,
settings and alerts.

Installing and running the server is covered in
[administration.md](administration.md). How Pantomath works inside, and
every rule it applies, is in [how-it-works.md](how-it-works.md).

**Contents**

1. [Signing in](#1-signing-in)
2. [Finding your way around](#2-finding-your-way-around)
3. [Priority, markers and reasons](#3-priority-markers-and-reasons)
4. [Dashboard](#4-dashboard)
5. [Affects us and Exploited](#5-affects-us-and-exploited)
6. [Live feed](#6-live-feed)
7. [Critical & high, Vulnerabilities, Malware, Ransomware, Saved](#7-critical--high-vulnerabilities-malware-ransomware-saved)
8. [Vendors and Threat actors](#8-vendors-and-threat-actors)
9. [Indicators](#9-indicators)
10. [Analytics](#10-analytics)
11. [Search](#11-search)
12. [Sources (administrators)](#12-sources-administrators)
13. [Settings (administrators)](#13-settings-administrators)
14. [Alerts: desktop notifications and webhooks](#14-alerts-desktop-notifications-and-webhooks)
15. [Setting up a wall screen](#15-setting-up-a-wall-screen)
16. [Using the API](#16-using-the-api)
17. [Keyboard shortcuts](#17-keyboard-shortcuts)
18. [Questions and problems](#18-questions-and-problems)

---

## 1. Signing in

Everyone signs in. There are two passwords:

| Password | Who has it | What it allows |
|---|---|---|
| **Team password** | Everyone who uses Pantomath | Viewing everything: feeds, indicators, analytics, Affects us, Exploited |
| **Settings password** | Whoever manages Pantomath | Everything the team password allows, plus Settings and Sources |

Type either one on the sign-in page. Signing in with the Settings password
also unlocks Settings straight away; otherwise Settings asks for it when you
open it (and stays unlocked for an hour).

**Remember this device** keeps you signed in for 90 days since you last
used Pantomath. Use it on the wall screen and your own computer, never on a
shared machine. Without it you stay signed in until you close the browser
(or after 12 hours without using it).

**Signing out:** the door icon at the right of the header. An administrator
can also sign any device out from Settings, Security.

**If your session ends** (it expired, or someone signed the device out), the
sign-in page appears with "Your session has ended". Sign in again and carry
on.

**Forgot a password?**

- *Team password:* ask whoever manages Pantomath.
- *Settings password:* on the sign-in page, choose **Forgot the Settings
  password?** and enter the recovery code you saved when Pantomath was set up.
  You choose a new password and get a new recovery code (each code works
  once). If the recovery code is lost too, an administrator can set a new
  password on the server; see [administration.md](administration.md#5-admin-commands).

Five wrong attempts from the same computer lock that computer out for a
minute.

## 2. Finding your way around

**Header** (top of every page):

- **Search box**: see [Search](#11-search). Press `/` to jump to it.
- **"N sources failing"**: shown only when some feeds can't be read. Click
  it to see why.
- **Live status**: *Live · updated 5 s ago* while data is flowing,
  *Reconnecting* if the live connection drops, and **Not updating** in red
  if nothing has arrived for two minutes. On a wall screen, "Not updating"
  means don't trust the screen until it recovers.
- **Moon button**: light or dark theme (remembered in this browser).
- **Door button**: sign out.
- **+ Add source**: add a feed (administrators).

**Sidebar**, grouped:

- *Overview*: Dashboard, Affects us, Exploited, Live feed, Critical & high
- *Investigate*: Indicators, Vulnerabilities, Malware, Ransomware
- *Intelligence*: Threat actors, Vendors, Sources
- *Workspace*: Saved
- *System*: Analytics, Settings

Numbers next to sidebar entries: **Live feed** shows how many items are new
since you last looked; **Affects us** and **Exploited** show how many items
were published in the dashboard's current time range; **Sources** shows how
many feeds are failing.

**On a phone** the sidebar opens from the menu button at the top left.

Pages refresh themselves every 30 seconds, and new items also arrive
instantly over the live connection. You never need to reload the page.

## 3. Priority, markers and reasons

Every item has a **priority**:

| Pill | Meaning |
|---|---|
| **Critical** (solid red) | Something on *Our stack* is mentioned **and** the item describes an exploited vulnerability or a serious flaw. Act on these. |
| **High** | An exploited vulnerability anywhere, a serious flaw (zero-day, RCE, ransomware…), or a vulnerability in something you run |
| **Medium** | Vulnerability, CVE, breach, malware or phishing language; or something you run is mentioned without warning words |
| **Low** | Everything else |

Two markers can appear before an item's title:

- **Exploited** (red): one of its CVEs is on CISA's Known Exploited
  Vulnerabilities catalog, meaning attacks using it have been confirmed.
- **Affects us** (teal outline): it names something on Our stack, the list of
  what your organisation runs.

Open an item and its panel says **why** it got its priority, for example:
*Why Critical: Exploited: CVE-2026-1234 on CISA's list · Affects us:
FortiGate · Wording: mentions "remote code execution"*. Hovering the
priority pill in a list shows the same reasons.

The full rules are in [how-it-works.md](how-it-works.md#5-analysis-rules).

## 4. Dashboard

The first page after signing in. The **24 h / 7 d / 30 d / 90 d** buttons set
the time range for the banner, the first figure and "Needs attention". All
counts use each item's **published** date (see
[how-it-works.md](how-it-works.md#6-dates-and-counting)).

**The banner** at the top answers "does anything affect us?":

- *Tell Pantomath what you run* (dashed): Our stack is empty. The button
  opens Settings, Our stack.
- *N items affect our stack* (teal): items in the range mention your kit.
- *N items affect our stack, M exploited* (red): some of them are being
  exploited. The **View** button opens the Affects us page.
- *Nothing in the range mentions our stack*: all clear, with a link to
  exploited items elsewhere if there are any.

**The figures:**

| Figure | What it counts |
|---|---|
| Critical and high | Items with Critical or High priority published in the range (how many are Critical underneath) |
| New since you last looked | Items Pantomath stored since you last left, minus the ones you've opened |
| Indicators this week | Distinct CVEs, IP addresses, hashes and emails seen in the last 7 days |
| Published this week | Items published in the last 7 days (how many today) |
| Sources | Working feeds out of all feeds; click to see failing ones |

Click a figure to open the matching page.

**Needs attention** lists up to eight Critical and High items from the range,
Critical first. **Source health** lists every feed with its state and, for a
failing feed, the exact reason. **Published per day** is a chart of the last
seven days, stacked by priority.

## 5. Affects us and Exploited

**Affects us** lists every item that mentions something on Our stack,
newest first. **Exploited** lists every item with a CVE on CISA's catalog.
Both use the same list and panel as the Live feed (next section), with a
summary strip on top:

- *Items*: how many are listed (the newest 200 are shown);
- *New since you last looked*;
- *Published in the last 24 hours*;
- *Exploited* (on Affects us) or *Affect our stack* (on Exploited).

**Most mentioned here** shows the Our stack names, CVEs, vendors and actors
that come up most on the page; click one to jump to it. On Affects us,
clicking a stack name filters the page to items that mention it.

If Affects us is empty, check that Our stack has entries (Settings, Our
stack). If Exploited is empty, check Settings, Exploited vulnerabilities:
the catalog may be switched off or unable to download.

## 6. Live feed

Everything Pantomath has collected, 50 items per page.

**Order:** newest arrivals first. Items that arrived in the same poll of a
feed are listed newest-published first.

**Filters** (combine freely):

- **Search box** on the page: keyword, CVE, vendor or actor.
- **Priority toggles**: Critical, High, Medium, Low. Click to hide or show a level.
- **Affects us** and **Exploited**: show only those items.
- **All sources / All categories**: one feed, or one kind of feed.
- **From / To**: by the date Pantomath stored the item. The hint next to
  the dates shows the stored range.

**Comfortable / Compact** switches between rows with a one-line summary and
denser rows with titles only. Your choice is remembered and applies to every
list.

**New since you last looked.** Items that arrived after you last left
Pantomath are grouped under this divider, with a teal dot and a bold title.
**Opening an item marks it read**: the dot goes, the title un-bolds and every
"new" count drops by one straight away, in this tab and any other open tab.
The item stays where it is so the list doesn't jump. **Mark all as read**
clears everything at once.

**The item panel** opens on the right when you click an item:

- priority and category, and **Why** it got that priority;
- for exploited CVEs, a red box with CISA's details: when it was added,
  CISA's deadline for fixing it, and whether ransomware groups use it;
- source, published time and when Pantomath saw it, vendors and threat actors;
- the summary;
- **Indicators**: every CVE, IP address, hash and email found, each with a
  copy button (**Copy all** copies the lot). Click one to see every item that
  mentions it on the Indicators page;
- **Related**: up to three other items that share its first indicator;
- **Open original** (the publisher's page), **Save** (adds it to Saved), and
  **Mark as unread**.

Close the panel with the ✕ or `Esc`.

## 7. Critical & high, Vulnerabilities, Malware, Ransomware, Saved

These pages work like the Live feed (same list, panel, shortcuts and read
marks), each showing the newest 200 matching items:

| Page | What's on it |
|---|---|
| Critical & high | Items with Critical or High priority |
| Vulnerabilities | Items that mention a CVE, or come from a source in the Vulnerability category |
| Malware | Items that name a threat actor, or come from a source in the Malware category |
| Ransomware | Items that mention ransomware, from any source |
| Saved | Items saved with the star or **Save**. Saves are shared by everyone using this Pantomath |

Each has a summary strip, **Most mentioned here** chips, and a filter box that
narrows the page by title, source, CVE, vendor, actor or stack name. If a page
says "Showing the newest 200", the Live feed's filters reach everything else.

## 8. Vendors and Threat actors

Chips list the most mentioned vendors (or threat actors) with their counts;
**Find a vendor** narrows the chips. Click a chip to see its items in the
usual list and panel, with a summary: how many items name it, how many are
new, published in the last day, and how many are Critical or High.

Vendors come from a curated list of names; threat actors from a curated list
plus naming patterns such as APT28, UNC3886, FIN7 and TA505. See
[how-it-works.md](how-it-works.md#53-vendors-and-threat-actors-taggingpy).

## 9. Indicators

Every CVE, IP address, hash and email address found in stored items.

**Tabs** (CVEs, IP addresses, Hashes, Emails) show how many distinct values
of each type there are. **Filter** narrows the current tab by text (up to 200
matches are shown).

**The table**, most mentioned first, 25 per page:

| Column | Meaning |
|---|---|
| Mentions | How many items mention it (in the selected day, if one is picked) |
| Sources | How many different feeds mentioned it |
| Highest priority | The highest priority of any item that mentions it |
| First seen / Last seen | When Pantomath first and last saw it, over all time |

Click a value to open its **drill-down** under the table: every article that
mentions it (with when Pantomath saw each one) and **Seen alongside**, the
other indicators, vendors and actors that appear in the same articles.

**Exporting.** Tick rows (the box in the header ticks the whole page), then:

- **Copy selected**: one value per line, to the clipboard.
- **Export selected (CSV)**: indicator, type, mentions, sources, highest
  priority, first and last seen (UTC). Values starting with `=`, `+`, `-` or
  `@` are prefixed with `'` so spreadsheets don't run them as formulas.
- **Download blocklist (.txt)** (or *list* for CVEs): one value per line
  under a comment header, ready for a firewall or EDR import.

With nothing ticked, the buttons act on **every** indicator in the current
tab (respecting the selected day and filter).

**The activity calendar** shows, for each day, how many distinct indicators
of the current type Pantomath saw that day. It's the same count the table
shows when you click that day. Hover a day for "N CVEs in M articles". Click
a day to narrow the table and list that day's articles; **Clear date** goes
back to all time. The arrows move between months.

## 10. Analytics

Trends over **7 d, 30 d, 90 d or 12 months**, all by published date:

- **Summary**: items published (with the change from the previous period of the
  same length), Critical and high, distinct indicators found, and how many
  sources published anything.
- **Published per day**, stacked by priority. Hover a bar for that day's numbers.
- **Priority mix**, with the change from the previous period.
- **Top sources**: items, how many were Critical or High, and share of all
  items.
- **When items are published**: weekday by hour, in the server's time zone.
  Darker cells mean more items.
- **Most mentioned vendors** and **threat actors**.
- **Categories**, by the category of each item's source.
- **Indicators found**: distinct values of each type.

## 11. Search

The search box in the header:

- a **CVE**, **IP address**, **hash** or **email address** opens that
  indicator's drill-down on the Indicators page;
- anything else searches the Live feed.

Press `/` from anywhere to jump to it.

## 12. Sources (administrators)

Sources are the RSS and Atom feeds Pantomath reads. Pantomath starts with
none.

**The health strip** at the top: *Healthy* (of all sources), *Failing* (and
the oldest failure), *Waiting or paused*, and *Items today*.

**The table** lists failing feeds first. For each source:

| Column | Meaning |
|---|---|
| Status | **Healthy** (last check worked), **Failing** (last check failed), **Waiting** (not checked yet), **Paused** |
| Source | Name, category, how often it's checked, items stored; for a failing feed, the reason ("HTTP 404 Not Found", "URL returned a web page, not an RSS/Atom feed", "no response from the server within 15 s"…) and when it started failing |
| Last success | When the feed last worked |
| Today | Items stored from it today |
| Response | How long the last check took |

**Actions** on each row: **Test** (checks the feed now without changing
anything), **Edit**, **Pause/Resume**, **Remove** (also removes its stored
items).

**Adding or editing a source** (the **+ Add source** button):

- **Name**, **RSS/Atom URL**, **Category** (General, Government,
  Vulnerability, News, Malware, Research), **Icon URL** (leave empty to
  use the site's own icon) and **Poll interval** in seconds.
- **Test feed** checks the address without saving: "Valid RSS 2.0 feed:
  Example, 16 items, newest published 2 hours ago. 4 of them mention a
  CVE", or exactly why it doesn't work.
- Saving runs the same test. If it fails, the button changes to **Save
  anyway**, so a broken feed is only saved on purpose (for example, one
  that's temporarily down).

**Also on this page:** **Refresh all now** (checks every enabled source
immediately), **Export** / **Import** (the source list as JSON, for another
Pantomath; the file contains feed addresses, which can include API keys, so
treat it as confidential), and **Lock** (locks Settings and Sources again
until the Settings password is entered).

The category matters: it decides what shows on the Vulnerabilities and
Malware pages, and the Categories chart in Analytics.

## 13. Settings (administrators)

Settings shows one section at a time; the menu on the left switches between
them and your last choice is remembered.

**Collection**

- *Default check interval for new sources*: pre-filled in the Add source
  form.
- *Deep extraction* (on by default): fetch each new article's full page, not
  just the feed's summary, before rating it and extracting indicators. Real
  indicators are rarely in the summary. It costs one extra request per new
  article.

**Our stack**: the vendors, products and systems you run. Add a **name** and,
optionally, other spellings under **Also match** (separated by commas). Items
whose title or summary mention one are marked **Affects us** and rise one
priority level. Matching is by whole words, ignoring case, except short
all-capital names such as *APC* or *NAS*, which must match exactly. The table
shows how many stored items each entry marks; every stored item is checked
again when the list changes. **Vendors named in your items** suggests names
from your feeds. Good entries: firewalls, switches and routers, hypervisors,
storage, VPN and remote access, identity, UPS and cooling management, and
the software on top.

**Exploited vulnerabilities**: CISA's Known Exploited Vulnerabilities
catalog. The switch turns it on or off; the status line shows how many
vulnerabilities are in it and when it was last updated (or why the last
update failed); **Update now** downloads it immediately. **Catalog address**
can point at an internal copy of the same JSON file on a server without
internet access; leave it empty for CISA's official feed.

**Alerts**

- *Desktop notifications* and *Notify me for*: see [Alerts](#14-alerts-desktop-notifications-and-webhooks).
- *Webhooks*: see the same section.

**Storage**

- *Currently stored*: the date range and number of items on disk.
- *Keep items for*: forever (the default), 2 years, 1 year, 6 months, 90 days
  or 30 days. Older items are removed about once an hour.
- *Reprocess all*: re-rates every stored item, re-extracts tags and
  indicators, and re-checks Our stack and the catalog with the current rules,
  without re-reading the feeds. With deep extraction on, it fetches article
  pages again. Worth doing after an upgrade that improves detection.

**Backup and restore**

- *Download backup*: the whole database (items, sources, settings, webhooks,
  sign-ins) as one SQLite file.
- *Restore from file*: replaces **everything** with a backup. A safety copy
  of the current database is kept on the server first.
- *Export sources*: the source list as JSON.

**Appearance**: light theme on or off (also the moon button in the header).

**Security**

- *Team password*: set, change or remove it. Changing or removing it signs
  out everyone who signed in with it, including wall screens.
- *Signed-in devices*: every browser that's signed in, with how it signed in,
  whether it's remembered, when it was last active and from which address.
  **Sign out** ends one; **Sign out all other devices** ends all but yours.
- *API keys*: see [Using the API](#16-using-the-api).
- Reminders for resetting the Settings password and enabling HTTPS.

## 14. Alerts: desktop notifications and webhooks

**Desktop notifications** are your browser's own pop-ups. Turn them on in
Settings, Alerts, allow them when the browser asks, and choose the lowest
priority that should trigger one (Critical only; Critical and high; Critical,
high and medium; Everything). They only appear while a Pantomath tab is open.
Browsers only allow notifications on **HTTPS** (or on the server itself), so
on plain HTTP Settings shows the permission as *blocked (insecure
connection)*; run `sudo pantomath-admin setup-https` on the server.

**Webhooks** send a message to another system (a team chat channel, a
ticketing system, your own script) whenever a new item matches, with no
browser needed. In Settings, Alerts, **+ Add webhook**:

- **Name** and **Webhook URL** (receives an HTTP POST with a JSON body).
- **Keyword filter**: comma-separated; any one appearing in the title or
  summary matches. Empty means any item.
- **Source filter**: one source, or any.
- **Minimum priority**: any, Medium and above, High and critical, or
  Critical only.
- **Only items that affect our stack** and **Only exploited vulnerabilities
  (CISA KEV)**.
- **Allow self-signed certificates**: for an internal HTTPS endpoint with its
  own certificate. It turns off certificate checking for this webhook only.
- **Protect this webhook with a key**: the key is then needed to see the real
  URL or change the webhook. There is no way to recover a lost key: delete
  the webhook and create it again.

All filters that are set must match. The **test** button sends a sample
message immediately. The message looks like this (a `text` line that most
chat tools display as-is, plus the structured data):

```json
{
  "text": "[CRITICAL] Example advisories: Remote code execution in a VPN gateway (Affects us: VPN gateway; Exploited: CVE-2026-1234)",
  "pantomath": {
    "id": "…", "title": "…", "link": "https://…", "summary": "…",
    "severity": "critical", "source_id": "…", "source_name": "Example advisories",
    "category": "vulnerability", "vendors": [], "actors": [],
    "cves": ["CVE-2026-1234"], "watch_hits": ["VPN gateway"], "kev_cves": ["CVE-2026-1234"],
    "matched_webhook": {"name": "SOC channel", "keyword": null, "min_severity": "high",
                        "only_affects_us": false, "only_exploited": false}
  }
}
```

`severity` carries the priority (critical, high, medium or low).

## 15. Setting up a wall screen

1. On the screen's browser, open Pantomath and sign in with the **team
   password**, ticking **Remember this device**. It stays signed in for 90
   days since it was last used, through restarts and upgrades.
2. Leave it on the **Dashboard** (or Affects us). Everything refreshes by
   itself.
3. Use the dark theme (the default) for a room display.
4. Watch the header: **Not updating** in red means no data has arrived for
   two minutes. Check the network and the service before trusting the
   screen again.

If the team password changes, or someone signs the screen out in Settings,
Security, it shows the sign-in page again.

## 16. Using the API

Scripts and other dashboards read Pantomath's data with an **API key**:

1. Settings, Security, **API keys**: type what will use it (for example
   *SIEM export*) and **Create key**.
2. Copy the key immediately. Pantomath keeps only a fingerprint and can't show it
   again.
3. Send it with every request:

```bash
curl -H "Authorization: Bearer pmk_…" "https://pantomath.example/api/items?severity=critical,high&limit=20"
```

A key can read everything but change nothing. Revoke it from the same
list. The endpoints are described in [api.md](api.md).

## 17. Keyboard shortcuts

| Key | Where | What it does |
|---|---|---|
| `/` | anywhere | Jump to the search box |
| `J` / `K` | any item list | Next / previous item (opens it in the panel) |
| `O` | any item list | Open the selected item's original page |
| `S` | any item list | Save or unsave the selected item |
| `Esc` | any item list | Close the item panel |

Shortcuts are ignored while you're typing in a field.

## 18. Questions and problems

**Why is an item High when nothing we run is involved?** It describes a
serious flaw (zero-day, RCE, ransomware…) or has a CVE on CISA's list. Open
it and read **Why**.

**Why is an item Critical?** It mentions something on Our stack *and* has an
exploited CVE or serious-flaw wording. If the stack match is wrong (a
product name that's also an ordinary word, say), refine the entry in
Settings, Our stack.

**An item says "Wording rated high" instead of the words it matched.** It was
stored before Pantomath recorded that detail. An administrator can run
Settings, Storage, Reprocess all.

**The "new" counts look wrong.** They're kept per browser: another computer
has its own. Mark all as read resets them.

**A feed says Failing.** The reason is on the Sources page. Common ones:
*HTTP 404* (the address changed), *URL returned a web page* (not a feed
address), *could not resolve the host name* or *no response* (network or DNS
from the server).

**Desktop notifications never appear.** They need HTTPS and an open
Pantomath tab. See [Alerts](#14-alerts-desktop-notifications-and-webhooks).

**The page asks me to sign in again.** Your session ended or was signed
out. Sign in again; tick Remember this device on your own computer.
