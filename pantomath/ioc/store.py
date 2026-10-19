"""
Adding values to the IOC database, and keeping them honest over time.

A value is stored once, however often feeds send it. Each arrival is
evidence, so it still counts:

  - a value nobody has reported before becomes a new indicator with its
    first sighting;
  - a value already stored, from a source that hadn't reported it, gets a
    new sighting, which raises its confidence;
  - a value this source already reported refreshes last_seen and the
    expiry, at most once a day: feeds resend everything they hold on every
    download, so a repeat download costs one indexed read and no write;
  - an allowlisted value, or one an analyst marked as a false positive,
    is dropped and counted.

What an arrival never changes: an analyst's edits, a false-positive mark
or an allowlist entry. A feed can fill an empty malware, threat type or
campaign field; it never overwrites one that has a value.

Confidence is kept explainable (see `confidence_for`): the highest any
source gives, plus 10 for each further independent source, capped at 100;
a number an analyst sets wins. Expiry is counted from the last time any
source reported the indicator, per type (normalize.DEFAULT_LIFETIME_DAYS)
unless the source sets its own lifetime.
"""
import ipaddress
import json
import time
import urllib.parse
from dataclasses import dataclass, field

from pantomath.ioc.normalize import DEFAULT_LIFETIME_DAYS

BATCH = 2000
DAY = 86400
REFRESH_EVERY = DAY            # at most one write per indicator and source a day
KEEP_EXPIRED_DAYS = 90         # default: expired indicators are deleted this long after they expire
KEEP_EXPIRED_CHOICES = (30, 90, 180, 365, 730, 0)   # 0 = keep them for ever
MANUAL = "manual"


@dataclass
class Source:
    """Who is reporting a batch of values, and what it says about all of them."""
    id: str                     # an ioc_feeds id, or MANUAL
    name: str
    confidence: int = 50
    lifetime_days: int = 0      # 0 = each type's default, -1 = never, otherwise days
    threat_type: str = ""
    malware: str = ""
    campaign: str = ""
    reference: str = ""
    note: str = ""


@dataclass
class Arrival:
    type: str
    value: str
    context: dict = field(default_factory=dict)
    malware: str = ""           # per value, e.g. from a CSV column


@dataclass
class IngestResult:
    new: int = 0
    refreshed: int = 0          # new sighting, or a sighting refreshed
    unchanged: int = 0          # reported within the last day: nothing written
    allowlisted: int = 0
    false_positive: int = 0
    seen_ids: set = field(default_factory=set)   # every indicator this source now reports

    def as_dict(self) -> dict:
        return {"new": self.new, "refreshed": self.refreshed, "unchanged": self.unchanged,
                "allowlisted": self.allowlisted, "false_positive": self.false_positive}


def confidence_for(sighting_confidences: list[int], analyst: int | None) -> int:
    if analyst is not None:
        return max(0, min(100, int(analyst)))
    if not sighting_confidences:
        return 0
    return min(100, max(sighting_confidences) + 10 * (len(sighting_confidences) - 1))


def explain_confidence(sightings: list[dict], analyst: int | None) -> str:
    """The sum behind an indicator's confidence, for the detail panel: nobody should have to guess where 85 came from."""
    if analyst is not None:
        return f"{analyst}, set by an analyst"
    active = [s for s in sightings if s["active"]]
    if not active:
        return "No source reports it any more"
    best = max(active, key=lambda s: s["confidence"])
    others = len(active) - 1
    if not others:
        return f"{best['confidence']}, from {best['source_name'] or 'one source'}"
    total = confidence_for([s["confidence"] for s in active], None)
    capped = " (capped at 100)" if best["confidence"] + 10 * others > 100 else ""
    return (f"{total}: highest source {best['confidence']} ({best['source_name']}) "
            f"+ 10 × {others} more source{'s' if others > 1 else ''}{capped}")


def expiry_for(type_: str, lifetime_days: int, now: float) -> float:
    """When an indicator reported now expires; 0 = never."""
    days = DEFAULT_LIFETIME_DAYS.get(type_) if lifetime_days == 0 else (None if lifetime_days < 0 else lifetime_days)
    return 0 if days is None else now + days * DAY


def _later_expiry(old: float, new: float) -> float:
    return 0 if (not old or not new) else max(old, new)


class Allowlist:
    """Settings, Allowlist, loaded once per import so each value is checked in memory."""

    def __init__(self, rows):
        self.exact = {r["value"] for r in rows if r["type"] == "exact"}
        self.domains = {r["value"] for r in rows if r["type"] == "domain"}
        self.networks = []
        for r in rows:
            if r["type"] == "cidr":
                try:
                    self.networks.append(ipaddress.ip_network(r["value"], strict=False))
                except ValueError:
                    continue

    def __bool__(self):
        return bool(self.exact or self.domains or self.networks)

    def covers(self, type_: str, value: str) -> bool:
        if value in self.exact:
            return True
        if type_ in ("ipv4", "ipv6") and self.networks:
            ip = ipaddress.ip_address(value)
            return any(ip in net for net in self.networks if net.version == ip.version)
        if self.domains:
            host = value
            if type_ == "url":
                host = urllib.parse.urlsplit(value).hostname or ""
            elif type_ == "email":
                host = value.rsplit("@", 1)[-1]
            elif type_ != "domain":
                return False
            labels = host.split(".")
            return any(".".join(labels[i:]) in self.domains for i in range(len(labels)))
        return False


async def load_allowlist(db) -> Allowlist:
    cur = await db.execute("SELECT type, value FROM allowlist")
    return Allowlist([dict(r) for r in await cur.fetchall()])


async def ingest(db, source: Source, arrivals, now: float | None = None,
                 analyst_confidence: int | None = None) -> IngestResult:
    """
    Adds a batch of normalized values from one source. Writes in batches
    of 2,000 and commits after each, so a large import never holds ioc.db's
    lock for long. `analyst_confidence` is for values entered by hand.
    """
    now = now or time.time()
    result = IngestResult()
    allow = await load_allowlist(db)
    unique: dict[tuple[str, str], Arrival] = {}
    for a in arrivals:
        unique.setdefault((a.type, a.value), a)
    pending = list(unique.values())
    for start in range(0, len(pending), BATCH):
        await _ingest_batch(db, source, pending[start:start + BATCH], now, analyst_confidence, allow, result)
        await db.commit()
    return result


async def _ingest_batch(db, source, batch, now, analyst_confidence, allow, result):
    manual = source.id == MANUAL
    kept = []
    for a in batch:
        if allow and allow.covers(a.type, a.value):
            result.allowlisted += 1
        else:
            kept.append(a)
    if not kept:
        return

    placeholders = ",".join("?" * len(kept))
    cur = await db.execute(
        f"SELECT id, type, value, status, expires_at, malware, threat_type, campaign FROM indicators WHERE value IN ({placeholders})",
        [a.value for a in kept],
    )
    existing = {(r["type"], r["value"]): dict(r) for r in await cur.fetchall()}
    sightings = {}
    if existing:
        ids = [r["id"] for r in existing.values()]
        cur = await db.execute(
            f"SELECT indicator_id, last_seen, active FROM sightings WHERE source = ? AND indicator_id IN ({','.join('?' * len(ids))})",
            [source.id, *ids],
        )
        sightings = {r["indicator_id"]: dict(r) for r in await cur.fetchall()}

    new_rows, touched, sighting_writes = [], {}, []
    for a in kept:
        row = existing.get((a.type, a.value))
        malware = a.malware or source.malware
        if row is None:
            new_rows.append((a, malware))
            continue
        if row["status"] in ("false_positive", "allowlisted"):
            if row["status"] == "false_positive":
                result.false_positive += 1
            else:
                result.allowlisted += 1
            continue
        result.seen_ids.add(row["id"])
        seen = sightings.get(row["id"])
        fresh = seen and seen["active"] and seen["last_seen"] > now - REFRESH_EVERY
        if fresh and row["status"] == "active" and not manual:
            result.unchanged += 1
            continue
        result.refreshed += 1
        touched[row["id"]] = (row, a, malware)
        sighting_writes.append((row["id"], a))

    if new_rows:
        await db.executemany(
            """INSERT OR IGNORE INTO indicators
               (type, value, first_seen, last_seen, expires_at, confidence, analyst_confidence,
                threat_type, malware, campaign, status, note, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?, 'active', ?, ?)""",
            [(a.type, a.value, now, now, expiry_for(a.type, source.lifetime_days, now),
              confidence_for([source.confidence], analyst_confidence), analyst_confidence,
              source.threat_type, malware, source.campaign, source.note, now) for a, malware in new_rows],
        )
        values = [a.value for a, _ in new_rows]
        cur = await db.execute(f"SELECT id, type, value FROM indicators WHERE value IN ({','.join('?' * len(values))})", values)
        ids = {(r["type"], r["value"]): r["id"] for r in await cur.fetchall()}
        for a, _ in new_rows:
            indicator_id = ids.get((a.type, a.value))
            if indicator_id is None:
                continue
            result.new += 1
            result.seen_ids.add(indicator_id)
            sighting_writes.append((indicator_id, a))

    if sighting_writes:
        await db.executemany(
            """INSERT INTO sightings (indicator_id, source, source_name, reference, confidence, first_seen, last_seen, active, context)
               VALUES (?,?,?,?,?,?,?,1,?)
               ON CONFLICT(indicator_id, source) DO UPDATE SET
                   last_seen = excluded.last_seen, active = 1, confidence = excluded.confidence,
                   source_name = excluded.source_name,
                   reference = CASE WHEN excluded.reference != '' THEN excluded.reference ELSE sightings.reference END,
                   context = CASE WHEN excluded.context != '' THEN excluded.context ELSE sightings.context END""",
            [(indicator_id, source.id, source.name, source.reference, source.confidence, now, now,
              json.dumps(a.context, separators=(",", ":")) if a.context else "") for indicator_id, a in sighting_writes],
        )

    if touched:
        updates = []
        for indicator_id, (row, a, malware) in touched.items():
            expires = _later_expiry(row["expires_at"], expiry_for(a.type, source.lifetime_days, now))

            def pick(current, offered):
                # Analysts overwrite what they type; feeds only fill blanks.
                return (offered or current) if manual else (current or offered)
            updates.append((now, expires, pick(row["malware"], malware), pick(row["threat_type"], source.threat_type),
                            pick(row["campaign"], source.campaign), now, indicator_id))
        await db.executemany(
            """UPDATE indicators SET last_seen = ?, expires_at = ?, status = 'active', malware = ?, threat_type = ?,
                                      campaign = ?, updated_at = ? WHERE id = ?""",
            updates,
        )
        if manual:
            ids = list(touched)
            marks = ",".join("?" * len(ids))
            if analyst_confidence is not None:
                await db.execute(f"UPDATE indicators SET analyst_confidence = ? WHERE id IN ({marks})", [analyst_confidence, *ids])
            if source.note:
                await db.execute(f"UPDATE indicators SET note = ? WHERE id IN ({marks})", [source.note, *ids])
        await recompute_confidence(db, list(touched), now)


async def recompute_confidence(db, indicator_ids, now: float | None = None) -> None:
    """Works confidence out again from the active sightings, for indicators whose sightings changed."""
    now = now or time.time()
    ids = list(indicator_ids)
    for start in range(0, len(ids), BATCH):
        chunk = ids[start:start + BATCH]
        marks = ",".join("?" * len(chunk))
        cur = await db.execute(
            f"""SELECT i.id, i.confidence, i.analyst_confidence, s.confidence AS sc
                FROM indicators i LEFT JOIN sightings s ON s.indicator_id = i.id AND s.active = 1
                WHERE i.id IN ({marks})""",
            chunk,
        )
        per: dict[int, tuple[int, int | None, list[int]]] = {}
        for r in await cur.fetchall():
            entry = per.setdefault(r["id"], (r["confidence"], r["analyst_confidence"], []))
            if r["sc"] is not None:
                entry[2].append(r["sc"])
        changes = []
        for indicator_id, (current, analyst, scores) in per.items():
            if not scores and analyst is None:
                continue  # nothing reports it: keep the last number, expiry decides what happens
            level = confidence_for(scores, analyst)
            if level != current:
                changes.append((level, now, indicator_id))
        if changes:
            await db.executemany("UPDATE indicators SET confidence = ?, updated_at = ? WHERE id = ?", changes)


async def end_snapshot(db, source_id: str, seen_ids: set, now: float | None = None) -> int:
    """
    For a snapshot feed, after a complete download: values it no longer
    lists stop counting for it. An indicator another source still reports
    stays active on that evidence; one nobody reports any more expires now.
    Returns how many values dropped off the list.
    """
    now = now or time.time()
    await db.execute("CREATE TEMP TABLE IF NOT EXISTS snapshot_seen (id INTEGER PRIMARY KEY)")
    await db.execute("DELETE FROM snapshot_seen")
    await db.executemany("INSERT OR IGNORE INTO snapshot_seen (id) VALUES (?)", [(i,) for i in seen_ids])
    cur = await db.execute(
        """SELECT indicator_id FROM sightings WHERE source = ? AND active = 1
           AND indicator_id NOT IN (SELECT id FROM snapshot_seen)""",
        (source_id,),
    )
    dropped = [r["indicator_id"] for r in await cur.fetchall()]
    await db.execute("DELETE FROM snapshot_seen")
    for start in range(0, len(dropped), BATCH):
        chunk = dropped[start:start + BATCH]
        marks = ",".join("?" * len(chunk))
        await db.execute(f"UPDATE sightings SET active = 0 WHERE source = ? AND indicator_id IN ({marks})", [source_id, *chunk])
        await db.execute(
            f"""UPDATE indicators SET status = 'expired', expires_at = ?, updated_at = ?
                WHERE id IN ({marks}) AND status = 'active' AND analyst_confidence IS NULL
                  AND NOT EXISTS (SELECT 1 FROM sightings s WHERE s.indicator_id = indicators.id AND s.active = 1)""",
            [now, now, *chunk],
        )
        await recompute_confidence(db, chunk, now)
        await db.commit()
    return len(dropped)


async def remove_source(db, source_id: str, now: float | None = None) -> None:
    """A feed was deleted: its sightings go, and indicators nothing else reports expire now."""
    now = now or time.time()
    cur = await db.execute("SELECT indicator_id FROM sightings WHERE source = ?", (source_id,))
    ids = [r["indicator_id"] for r in await cur.fetchall()]
    await db.execute("DELETE FROM sightings WHERE source = ?", (source_id,))
    for start in range(0, len(ids), BATCH):
        chunk = ids[start:start + BATCH]
        marks = ",".join("?" * len(chunk))
        await db.execute(
            f"""UPDATE indicators SET status = 'expired', expires_at = ?, updated_at = ?
                WHERE id IN ({marks}) AND status = 'active' AND analyst_confidence IS NULL
                  AND NOT EXISTS (SELECT 1 FROM sightings s WHERE s.indicator_id = indicators.id AND s.active = 1)""",
            [now, now, *chunk],
        )
        await recompute_confidence(db, chunk, now)
    await db.commit()


async def set_source_confidence(db, source_id: str, confidence: int) -> None:
    """A feed's confidence was edited: its sightings take the new number straight away."""
    cur = await db.execute("SELECT indicator_id FROM sightings WHERE source = ?", (source_id,))
    ids = [r["indicator_id"] for r in await cur.fetchall()]
    await db.execute("UPDATE sightings SET confidence = ? WHERE source = ?", (confidence, source_id))
    await recompute_confidence(db, ids)
    await db.commit()


async def keep_expired_days(db) -> int:
    """Settings, IOC feeds, "Keep expired indicators for": days, or 0 for ever."""
    cur = await db.execute("SELECT value FROM ioc_settings WHERE key = 'keep_expired_days'")
    row = await cur.fetchone()
    try:
        days = int(row["value"]) if row else KEEP_EXPIRED_DAYS
    except ValueError:
        days = KEEP_EXPIRED_DAYS
    return days if days in KEEP_EXPIRED_CHOICES else KEEP_EXPIRED_DAYS


async def set_keep_expired_days(db, days: int) -> None:
    if days not in KEEP_EXPIRED_CHOICES:
        raise ValueError(f"Keep expired indicators for one of: {', '.join(str(d) for d in KEEP_EXPIRED_CHOICES)} days (0 = for ever).")
    await db.execute(
        "INSERT INTO ioc_settings (key, value) VALUES ('keep_expired_days', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(days),),
    )
    await db.commit()


async def expire_due(db, now: float | None = None) -> tuple[int, int]:
    """
    Hourly: active indicators past their expiry become expired, and
    expired ones are deleted after the time chosen in Settings (90 days by
    default: long enough for any SIEM syncing with export?since= to see
    them go; 0 keeps them for ever). Expired indicators are never returned
    to SIEMs either way. False-positive marks are kept. Returns (expired, deleted).
    """
    now = now or time.time()
    cur = await db.execute(
        "UPDATE indicators SET status = 'expired', updated_at = ? WHERE status = 'active' AND expires_at != 0 AND expires_at < ?",
        (now, now),
    )
    expired = cur.rowcount
    deleted = 0
    keep = await keep_expired_days(db)
    if keep:
        cur = await db.execute(
            "DELETE FROM indicators WHERE status = 'expired' AND expires_at != 0 AND expires_at < ?",
            (now - keep * DAY,),
        )
        deleted = cur.rowcount
    await db.commit()
    return expired, deleted


async def apply_allowlist(db, now: float | None = None) -> int:
    """
    After the allowlist changes: stored indicators it now covers are set
    aside as 'allowlisted' (lookups and exports stop returning them), and
    ones it no longer covers come back. Returns how many are allowlisted.
    """
    now = now or time.time()
    allow = await load_allowlist(db)
    covered, last_id = 0, 0
    while True:
        cur = await db.execute(
            """SELECT id, type, value, status, expires_at FROM indicators
               WHERE id > ? AND status IN ('active', 'expired', 'allowlisted') ORDER BY id LIMIT ?""",
            (last_id, BATCH * 5),
        )
        rows = await cur.fetchall()
        if not rows:
            break
        changes = []
        for r in rows:
            listed = bool(allow) and allow.covers(r["type"], r["value"])
            covered += listed
            if listed and r["status"] != "allowlisted":
                changes.append(("allowlisted", now, r["id"]))
            elif not listed and r["status"] == "allowlisted":
                back = "active" if (not r["expires_at"] or r["expires_at"] > now) else "expired"
                changes.append((back, now, r["id"]))
        if changes:
            await db.executemany("UPDATE indicators SET status = ?, updated_at = ? WHERE id = ?", changes)
        last_id = rows[-1]["id"]
    await db.commit()
    return covered
