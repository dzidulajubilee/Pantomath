"""
HTTP routes for the IOC database (1.0.0), in three groups with three gates:

  ioc_router            /api/ioc/...  the IOC database tab: anyone signed in can
                        browse and look values up (same gate as the dashboard).
  ioc_protected_router  /api/ioc/...  adding, editing and marking indicators,
                        IOC feeds, the allowlist and SIEM keys: the Settings
                        password, like Sources. What's in here ends up in SIEMs
                        and firewalls, so viewers can't change it.
  siem_router           /api/v1/...   the lookup API for SIEMs, firewalls and
                        scripts. Read-only, SIEM keys only, and a contract that
                        stays put while the dashboard's own /api routes change
                        with the interface.

Every route opens ioc.db through `ioc_db()`, which turns a database that
can't be opened into a 503 with the reason, so the rest of Pantomath is
unaffected.
"""
import asyncio
import csv
import datetime
import io
import json
import os
import sqlite3
import tempfile
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

from pantomath import __version__
from pantomath.api.routes import _client_ip, require_settings_auth, require_viewer
from pantomath.auth import sign_in
from pantomath.database.sqlite import get_db
from pantomath.ioc.db import IOC_DB_PATH, IocUnavailable, get_ioc_db
from pantomath.ioc.feeds import (
    DEFAULT_MAX_MB,
    FORMATS,
    MAX_MB_LIMIT,
    MIN_INTERVAL,
    IocFeedError,
    check_key_header,
    download_and_parse,
    nothing_readable,
    parse_list,
    reader_for_url,
)
from pantomath.ioc.hits import day_of, hit_counter
from pantomath.ioc.normalize import (
    TYPE_LABELS,
    TYPES,
    IocValueError,
    candidates,
    detect,
    normalize,
    normalize_allow_entry,
    refang,
)
from pantomath.ioc.readers import READERS
from pantomath.ioc.scheduler import IocScheduler
from pantomath.ioc.store import (
    KEEP_EXPIRED_CHOICES,
    MANUAL,
    PROMOTED,
    Source,
    apply_allowlist,
    explain_confidence,
    ingest,
    keep_expired_days,
    load_allowlist,
    recompute_confidence,
    remove_source,
    set_keep_expired_days,
    set_source_confidence,
)

ioc_scheduler = IocScheduler()

ioc_router = APIRouter(dependencies=[Depends(require_viewer)])
ioc_protected_router = APIRouter(dependencies=[Depends(require_settings_auth)])

MAX_LOOKUP_VALUES = 1000
MAX_MANUAL_BYTES = 20 * 1024 * 1024
TYPE_GROUPS = {"ip": ("ipv4", "ipv6"), "hash": ("md5", "sha1", "sha256"), "network": ("ja3", "ja4", "x509")}
STATUSES = ("active", "expired", "false_positive", "allowlisted")
LIST_FORMATS = ("text", "csv")      # what can be pasted or imported by hand
# Where the news side keeps each kind of value it extracts (items.ips...).
NEWS_COLUMNS = {"ipv4": "ips", "ipv6": "ips", "md5": "hashes", "sha1": "hashes", "sha256": "hashes", "email": "emails"}


@asynccontextmanager
async def ioc_db():
    try:
        db = await get_ioc_db()
    except IocUnavailable as e:
        raise HTTPException(503, str(e)) from None
    try:
        yield db
    except sqlite3.DatabaseError as e:
        raise HTTPException(503, f"The IOC database isn't usable right now: {e}") from None
    finally:
        await db.close()


def iso(ts) -> str | None:
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_since(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        parsed = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "since must be a Unix time or an ISO 8601 time such as 2026-10-19T08:00:00Z") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def type_filter(type_: str | None) -> list[str]:
    """'ipv4', 'ip' (IPv4 and IPv6), 'hash', 'network', or several separated by commas."""
    if not type_:
        return []
    out = []
    for part in (p.strip().lower() for p in type_.split(",") if p.strip()):
        if part in TYPE_GROUPS:
            out += TYPE_GROUPS[part]
        elif part in TYPES:
            out.append(part)
        else:
            raise HTTPException(400, f"Unknown type '{part}'. Use one of: {', '.join((*TYPES, *TYPE_GROUPS))}.")
    return out


def _local_midnight() -> float:
    local = time.localtime()
    return time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))


# ------------------------------------------------------------------ lookups

async def lookup_values(db, values: list[str], include_expired: bool = False, for_people: bool = False,
                        hits: list | None = None) -> dict:
    """
    The one lookup both the tab and /api/v1 use. Every value is matched on
    the UNIQUE (type, value) index, in one query for the whole request. A
    miss is a normal result. `for_people` adds what an analyst wants and a
    SIEM doesn't: the row id, and why a stored value doesn't match. The id
    of every match is appended to `hits`, for the SIEM hit counts.
    """
    wanted = []
    for raw in values:
        raw = str(raw)
        options = candidates(raw)
        wanted.append((raw, options))
    lookups = sorted({v for _, options in wanted for _, v in options})
    found = {}
    for start in range(0, len(lookups), 900):
        chunk = lookups[start:start + 900]
        cur = await db.execute(f"SELECT * FROM indicators WHERE value IN ({','.join('?' * len(chunk))})", chunk)
        for r in await cur.fetchall():
            found[(r["type"], r["value"])] = dict(r)
    matched_ids = [r["id"] for r in found.values() if r["status"] == "active" or (include_expired and r["status"] == "expired")]
    sources: dict[int, list] = {}
    for start in range(0, len(matched_ids), 900):
        chunk = matched_ids[start:start + 900]
        cur = await db.execute(
            f"""SELECT indicator_id, source_name, confidence, reference FROM sightings
                WHERE active = 1 AND indicator_id IN ({','.join('?' * len(chunk))}) ORDER BY confidence DESC""",
            chunk,
        )
        for r in await cur.fetchall():
            entry = {"name": r["source_name"], "confidence": r["confidence"]}
            if r["reference"]:
                entry["reference"] = r["reference"]
            sources.setdefault(r["indicator_id"], []).append(entry)
    allow = await load_allowlist(db) if for_people else None

    results, matched = [], 0
    for raw, options in wanted:
        if not options:
            result = {"value": raw, "type": detect(raw), "match": False}
            if for_people:
                result["reason"] = _why_not(raw)
            results.append(result)
            continue
        rows = [found[o] for o in options if o in found]
        hit = next((r for r in rows if r["status"] == "active"), None) or next(
            (r for r in rows if include_expired and r["status"] == "expired"), None)
        if not hit:
            result = {"value": raw, "type": options[0][0], "match": False}
            if for_people:
                stored = rows[0] if rows else None
                if stored:
                    result.update(id=stored["id"], status=stored["status"], type=stored["type"])
                elif allow and allow.covers(*options[0]):
                    result["status"] = "allowlisted"
            results.append(result)
            continue
        matched += 1
        if hits is not None:
            hits.append(hit["id"])
        result = {
            "value": raw, "type": hit["type"], "match": True, "status": hit["status"], "confidence": hit["confidence"],
            "threat_type": hit["threat_type"] or None, "malware": hit["malware"] or None, "campaign": hit["campaign"] or None,
            "first_seen": iso(hit["first_seen"]), "last_seen": iso(hit["last_seen"]), "expires_at": iso(hit["expires_at"]),
            "sources": sources.get(hit["id"], []),
        }
        if hit["value"] != raw:
            result["normalized"] = hit["value"]
        if for_people:
            result["id"] = hit["id"]
        results.append(result)
    return {"checked": len(values), "matched": matched, "results": results}


def _why_not(raw: str) -> str:
    detected = detect(raw)
    if not detected:
        return "not a recognised indicator"
    try:
        normalize(detected, raw)
    except IocValueError as e:
        return str(e)
    return "not stored"


class LookupIn(BaseModel):
    values: list[str] = []
    include_expired: bool = False


def _lookup_list(body: LookupIn) -> list[str]:
    values = [v for v in (str(x).strip() for x in body.values) if v]
    if len(values) > MAX_LOOKUP_VALUES:
        raise HTTPException(400, f"Up to {MAX_LOOKUP_VALUES} values per request; this one has {len(values)}.")
    return values


@ioc_router.post("/api/ioc/lookup")
async def tab_lookup(body: LookupIn):
    async with ioc_db() as db:
        return await lookup_values(db, _lookup_list(body), body.include_expired, for_people=True)


# --------------------------------------------------------------- the tab

@ioc_router.get("/api/ioc/summary")
async def ioc_summary():
    now = time.time()
    async with ioc_db() as db:
        async def scalar(sql, params=()):
            cur = await db.execute(sql, params)
            return (await cur.fetchone())[0] or 0
        cur = await db.execute("SELECT type, COUNT(*) AS n FROM indicators WHERE status = 'active' GROUP BY type")
        by_type = {r["type"]: r["n"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT status, COUNT(*) AS n FROM indicators GROUP BY status")
        by_status = {r["status"]: r["n"] for r in await cur.fetchall()}
        cur = await db.execute(
            """SELECT malware, COUNT(*) AS n FROM indicators WHERE status = 'active' AND malware != ''
               GROUP BY malware ORDER BY n DESC, malware LIMIT 40"""
        )
        malware = [{"name": r["malware"], "count": r["n"]} for r in await cur.fetchall()]
        cur = await db.execute("SELECT id, name, enabled, last_status, last_success FROM ioc_feeds ORDER BY name")
        feeds = [dict(r) for r in await cur.fetchall()]
        today = day_of(now)
        cur = await db.execute("SELECT lookups, matches FROM lookup_stats WHERE day = ?", (today,))
        stored = await cur.fetchone()
        cur = await db.execute("SELECT DISTINCT indicator_id FROM indicator_hits WHERE day >= ?", (day_of(now - 6 * 86400),))
        seen = {r["indicator_id"] for r in await cur.fetchall()}
        pending_lookups, pending_matches, pending_hits = hit_counter.pending(today)
        seen |= set(pending_hits)
        return {
            "active": sum(by_type.values()),
            "by_type": by_type,
            "by_status": by_status,
            "added_today": await scalar("SELECT COUNT(*) FROM indicators WHERE first_seen >= ?", (_local_midnight(),)),
            "expiring_week": await scalar(
                "SELECT COUNT(*) FROM indicators WHERE status = 'active' AND expires_at != 0 AND expires_at BETWEEN ? AND ?",
                (now, now + 7 * 86400)),
            "malware": malware,
            "feeds": {
                "total": len(feeds),
                "enabled": sum(1 for f in feeds if f["enabled"]),
                "ok": sum(1 for f in feeds if f["enabled"] and f["last_status"] == "ok"),
                "failing": [{"id": f["id"], "name": f["name"]} for f in feeds if f["enabled"] and f["last_status"].startswith("error")],
                "list": [{"id": f["id"], "name": f["name"]} for f in feeds],
            },
            "last_feed_update": max((f["last_success"] or 0 for f in feeds), default=0) or None,
            "siem": {
                "lookups_today": (stored["lookups"] if stored else 0) + pending_lookups,
                "matches_today": (stored["matches"] if stored else 0) + pending_matches,
                "indicators_seen_week": len(seen),
            },
            "types": [{"type": t, "label": TYPE_LABELS[t]} for t in TYPES],
        }


def _indicator_conditions(type_, q, status, min_confidence, malware, source, seen_days=0):
    conditions, params = [], []
    if seen_days:
        since = day_of(time.time() - (seen_days - 1) * 86400)
        pending = sorted(hit_counter.pending_since(since))   # counted, not written yet
        conditions.append("(EXISTS (SELECT 1 FROM indicator_hits h WHERE h.indicator_id = indicators.id AND h.day >= ?)"
                          + (f" OR indicators.id IN ({','.join('?' * len(pending))})" if pending else "") + ")")
        params += [since, *pending]
    types = type_filter(type_)
    if types:
        conditions.append(f"type IN ({','.join('?' * len(types))})")
        params += types
    if status and status != "all":
        wanted = [s for s in status.split(",") if s]
        bad = [s for s in wanted if s not in STATUSES]
        if bad:
            raise HTTPException(400, f"Unknown status '{bad[0]}'. Use one of: {', '.join(STATUSES)}, all.")
        conditions.append(f"status IN ({','.join('?' * len(wanted))})")
        params += wanted
    if min_confidence:
        conditions.append("confidence >= ?")
        params.append(min_confidence)
    if malware:
        conditions.append("malware = ? COLLATE NOCASE")
        params.append(malware)
    if source:
        conditions.append("EXISTS (SELECT 1 FROM sightings s WHERE s.indicator_id = indicators.id AND s.source = ? AND s.active = 1)")
        params.append(source)
    for word in (q or "").split():
        word = refang(word)
        pattern = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conditions.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in ("value", "malware", "campaign", "threat_type", "tags", "note")) + ")")
        params += [pattern] * 6
    return conditions, params


@ioc_router.get("/api/ioc/indicators")
async def list_indicators(type: str | None = None, q: str | None = None, status: str = "active",
                          min_confidence: int = 0, malware: str | None = None, source: str | None = None,
                          seen_days: int = 0, limit: int = 50, offset: int = 0):
    """`seen_days`: only indicators your SIEMs looked up in that many days, today included."""
    limit = max(1, min(limit, 200))
    conditions, params = _indicator_conditions(type, q, status, min_confidence, malware, source, max(0, min(seen_days, 90)))
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    async with ioc_db() as db:
        cur = await db.execute(f"SELECT COUNT(*) FROM indicators{where}", params)
        total = (await cur.fetchone())[0]
        cur = await db.execute(
            f"""SELECT indicators.*,
                       (SELECT COUNT(*) FROM sightings s WHERE s.indicator_id = indicators.id AND s.active = 1) AS sources,
                       (SELECT COALESCE(SUM(count), 0) FROM indicator_hits h WHERE h.indicator_id = indicators.id AND h.day >= ?) AS hits_week
                FROM indicators{where} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?""",
            [day_of(time.time() - 6 * 86400), *params, limit, max(0, offset)],
        )
        items = [dict(r) for r in await cur.fetchall()]
    for item in items:
        item["hits_week"] += hit_counter.pending_for(item["id"])[0]
    return {"total": total, "items": items}


@ioc_router.get("/api/ioc/indicators/{indicator_id}")
async def get_indicator(indicator_id: int):
    async with ioc_db() as db:
        cur = await db.execute("SELECT * FROM indicators WHERE id = ?", (indicator_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "No such indicator")
        indicator = dict(row)
        cur = await db.execute(
            "SELECT * FROM sightings WHERE indicator_id = ? ORDER BY active DESC, confidence DESC, last_seen DESC", (indicator_id,)
        )
        sightings = []
        for r in await cur.fetchall():
            s = dict(r)
            try:
                s["context"] = json.loads(s["context"]) if s["context"] else {}
            except ValueError:
                s["context"] = {}
            sightings.append(s)
        now = time.time()
        cur = await db.execute(
            """SELECT COALESCE(SUM(CASE WHEN day = ? THEN count END), 0) AS today,
                      COALESCE(SUM(CASE WHEN day >= ? THEN count END), 0) AS week,
                      COALESCE(SUM(count), 0) AS total, MAX(last_hit) AS last_hit
               FROM indicator_hits WHERE indicator_id = ?""",
            (day_of(now), day_of(now - 6 * 86400), indicator_id),
        )
        hits = dict(await cur.fetchone())
    pending_count, pending_last = hit_counter.pending_for(indicator_id)
    indicator["siem_hits"] = {
        "today": hits["today"] + pending_count, "week": hits["week"] + pending_count, "days_90": hits["total"] + pending_count,
        "last_hit": max(hits["last_hit"] or 0, pending_last) or None,
    }
    indicator["sightings"] = sightings
    indicator["confidence_explained"] = explain_confidence(sightings, indicator["analyst_confidence"])
    indicator["type_label"] = TYPE_LABELS.get(indicator["type"], indicator["type"])
    return indicator


@ioc_router.get("/api/ioc/indicators/{indicator_id}/mentions")
async def indicator_mentions(indicator_id: int, limit: int = 5):
    """
    Where the news mentions this value: the only place the IOC side reads
    pantomath.db, and only reads. IPs, hashes and emails match the values
    extracted from articles; other types are looked for in titles and
    summaries.
    """
    async with ioc_db() as db:
        cur = await db.execute("SELECT type, value FROM indicators WHERE id = ?", (indicator_id,))
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "No such indicator")
    column = NEWS_COLUMNS.get(row["type"])
    if column:
        where, params = f"(',' || items.{column} || ',') LIKE ?", [f"%,{row['value']},%"]
    else:
        pattern = "%" + row["value"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where, params = "(items.title LIKE ? ESCAPE '\\' OR items.summary LIKE ? ESCAPE '\\')", [pattern, pattern]
    db = await get_db()
    try:
        cur = await db.execute(f"SELECT COUNT(*) FROM items WHERE {where}", params)
        count = (await cur.fetchone())[0]
        cur = await db.execute(
            f"""SELECT items.id, items.title, items.link, items.severity, items.fetched_at, sources.name AS source_name
                FROM items JOIN sources ON sources.id = items.source_id WHERE {where}
                ORDER BY items.fetched_at DESC LIMIT ?""",
            [*params, max(1, min(limit, 20))],
        )
        items = [dict(r) for r in await cur.fetchall()]
    finally:
        await db.close()
    return {"count": count, "items": items, "field": column}


# ----------------------------------------------------- analyst changes

class ManualIn(BaseModel):
    text: str
    format: str = "text"
    value_column: str = ""
    type: str = ""
    confidence: int = 70
    threat_type: str = ""
    malware: str = ""
    campaign: str = ""
    lifetime_days: int = 0
    note: str = ""
    reference: str = ""
    promoted: bool = False      # values an analyst moved over from the Indicators tab or an article


def _clean(text: str, limit: int) -> str:
    return " ".join((text or "").split())[:limit]


def _check_lifetime(days: int) -> int:
    if days < -1 or days > 3650:
        raise HTTPException(400, "Lifetime is 0 (each type's default), -1 (never expires) or up to 3,650 days.")
    return days


def _check_confidence(value: int) -> int:
    if not 0 <= value <= 100:
        raise HTTPException(400, "Confidence is a number from 0 to 100.")
    return value


@ioc_protected_router.post("/api/ioc/indicators")
async def add_indicators(body: ManualIn):
    """
    Manual entry, a pasted list or a CSV file, and values promoted from the
    news side: every value through the same rules as a feed. Promoted values
    get their own source ("Promoted from the news"), so it stays clear they
    were found in article text and checked by a person.
    """
    if len(body.text.encode()) > MAX_MANUAL_BYTES:
        raise HTTPException(413, "That's more than 20 MB. Publish the list at a URL and add it as an IOC feed instead.")
    if body.format not in LIST_FORMATS:
        raise HTTPException(400, "Format is 'text' or 'csv'.")
    if body.type and body.type not in TYPES:
        raise HTTPException(400, f"Unknown type '{body.type}'.")
    try:
        parsed = parse_list(body.text, body.format, body.type, body.value_column)
    except IocFeedError as e:
        raise HTTPException(400, str(e)) from None
    source = Source(id=PROMOTED if body.promoted else MANUAL,
                    name="Promoted from the news" if body.promoted else "Added by hand",
                    confidence=_check_confidence(body.confidence),
                    lifetime_days=_check_lifetime(body.lifetime_days), threat_type=_clean(body.threat_type, 40),
                    malware=_clean(body.malware, 100), campaign=_clean(body.campaign, 100),
                    reference=_clean(body.reference, 500), note=(body.note or "").strip()[:2000])
    async with ioc_db() as db:
        result = await ingest(db, source, parsed.arrivals, analyst_confidence=body.confidence)
    summary = parsed.summary()
    return {"added": result.new, "updated": result.refreshed + result.unchanged, "allowlisted": result.allowlisted,
            "false_positive": result.false_positive, "rejected": summary["rejected"],
            "rejected_samples": summary["rejected_samples"], "by_type": summary["by_type"]}


class IndicatorEditIn(BaseModel):
    status: str | None = None          # 'active' or 'false_positive'
    confidence: int | None = None      # analyst's number; send null to go back to the sources' number
    threat_type: str | None = None
    malware: str | None = None
    campaign: str | None = None
    tags: str | None = None
    note: str | None = None


@ioc_protected_router.patch("/api/ioc/indicators/{indicator_id}")
async def edit_indicator(indicator_id: int, body: IndicatorEditIn):
    now = time.time()
    sent = body.model_fields_set
    async with ioc_db() as db:
        cur = await db.execute("SELECT * FROM indicators WHERE id = ?", (indicator_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "No such indicator")
        sets, params = [], []
        if "status" in sent and body.status is not None:
            if body.status == "false_positive":
                sets.append("status = 'false_positive'")
            elif body.status == "active":
                # Back from a false-positive mark: active unless it has expired or is allowlisted.
                allow = await load_allowlist(db)
                back = ("allowlisted" if allow and allow.covers(row["type"], row["value"])
                        else "active" if (not row["expires_at"] or row["expires_at"] > now) else "expired")
                sets.append("status = ?")
                params.append(back)
            else:
                raise HTTPException(400, "Status is 'active' or 'false_positive'; expiry and the allowlist set the others.")
        if "confidence" in sent:
            sets.append("analyst_confidence = ?")
            params.append(None if body.confidence is None else _check_confidence(body.confidence))
        for name, limit in (("threat_type", 40), ("malware", 100), ("campaign", 100), ("tags", 300)):
            if name in sent and getattr(body, name) is not None:
                sets.append(f"{name} = ?")
                params.append(_clean(getattr(body, name), limit))
        if "note" in sent and body.note is not None:
            sets.append("note = ?")
            params.append(body.note.strip()[:2000])
        if not sets:
            raise HTTPException(400, "Nothing to change")
        await db.execute(f"UPDATE indicators SET {', '.join(sets)}, updated_at = ? WHERE id = ?", [*params, now, indicator_id])
        if "confidence" in sent:
            if body.confidence is None:
                cur = await db.execute("SELECT COUNT(*) FROM sightings WHERE indicator_id = ? AND active = 1", (indicator_id,))
                if not (await cur.fetchone())[0]:
                    await db.execute("UPDATE indicators SET confidence = 0 WHERE id = ?", (indicator_id,))
            await recompute_confidence(db, [indicator_id], now)
        await db.commit()
    return await get_indicator(indicator_id)


@ioc_protected_router.delete("/api/ioc/indicators/{indicator_id}")
async def delete_indicator(indicator_id: int):
    async with ioc_db() as db:
        cur = await db.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))
        await db.commit()
    if not cur.rowcount:
        raise HTTPException(404, "No such indicator")
    return {"ok": True}


# ------------------------------------------------------------- IOC feeds

class FeedIn(BaseModel):
    name: str
    url: str
    format: str = "text"
    value_column: str = ""
    date_column: str = ""
    malware_column: str = ""
    default_type: str = ""
    confidence: int = 50
    threat_type: str = ""
    lifetime_days: int = 0
    interval_seconds: int = 21600
    enabled: bool = True
    snapshot: bool = False
    max_mb: int = DEFAULT_MAX_MB
    key_header: str = ""
    key_value: str = ""


class FeedEditIn(BaseModel):
    name: str | None = None
    url: str | None = None
    format: str | None = None
    value_column: str | None = None
    date_column: str | None = None
    malware_column: str | None = None
    default_type: str | None = None
    confidence: int | None = None
    threat_type: str | None = None
    lifetime_days: int | None = None
    interval_seconds: int | None = None
    enabled: bool | None = None
    snapshot: bool | None = None
    max_mb: int | None = None
    key_header: str | None = None
    key_value: str | None = None      # empty or missing keeps the stored key
    clear_key: bool = False


class FeedTestIn(BaseModel):
    url: str
    format: str = "text"
    value_column: str = ""
    date_column: str = ""
    malware_column: str = ""
    default_type: str = ""
    max_mb: int = DEFAULT_MAX_MB
    key_header: str = ""
    key_value: str = ""
    feed_id: str = ""                 # editing: use the stored key when none is typed


def _check_feed_fields(values: dict) -> dict:
    """Validates whichever feed fields are present and returns them cleaned."""
    out = {}
    for name, value in values.items():
        if value is None:
            continue
        if name == "name":
            value = _clean(value, 80)
            if not value:
                raise HTTPException(400, "Give the feed a name.")
        elif name == "url":
            value = value.strip()
            if not value.lower().startswith(("http://", "https://")):
                raise HTTPException(400, "The list URL must start with http:// or https://.")
        elif name == "format" and value not in FORMATS:
            raise HTTPException(400, f"Format is one of: {', '.join(FORMATS)}.")
        elif name == "default_type" and value and value not in TYPES:
            raise HTTPException(400, f"Unknown type '{value}'.")
        elif name == "confidence":
            _check_confidence(value)
        elif name == "lifetime_days":
            _check_lifetime(value)
        elif name == "interval_seconds" and value < MIN_INTERVAL:
            raise HTTPException(400, "Fetch a feed at most every 15 minutes (900 seconds).")
        elif name == "max_mb" and not 1 <= value <= MAX_MB_LIMIT:
            raise HTTPException(400, f"The size limit is 1 to {MAX_MB_LIMIT} MB.")
        elif name in ("value_column", "date_column", "malware_column", "threat_type"):
            value = _clean(value, 60)
        elif name in ("enabled", "snapshot"):
            value = int(bool(value))
        out[name] = value
    reader = READERS.get(out.get("format", ""))
    if reader and out.get("interval_seconds", reader.min_interval) < reader.min_interval:
        raise HTTPException(400, f"{reader.label} can be fetched at most every {reader.min_interval // 3600} hours.")
    try:
        check_key_header(out.get("key_header", ""), out.get("key_value", ""))
    except IocFeedError as e:
        raise HTTPException(400, str(e)) from None
    return out


def _public_feed(row: dict) -> dict:
    feed = {k: v for k, v in row.items() if k not in ("key_value", "etag", "last_modified")}
    feed["has_key"] = bool(row.get("key_value"))
    return feed


@ioc_protected_router.get("/api/ioc/feeds")
async def list_feeds():
    async with ioc_db() as db:
        cur = await db.execute("SELECT * FROM ioc_feeds ORDER BY name")
        feeds = [_public_feed(dict(r)) for r in await cur.fetchall()]
        cur = await db.execute(
            """SELECT s.source, COUNT(*) AS n FROM sightings s JOIN indicators i ON i.id = s.indicator_id
               WHERE s.active = 1 AND i.status = 'active' GROUP BY s.source"""
        )
        counts = {r["source"]: r["n"] for r in await cur.fetchall()}
    for feed in feeds:
        feed["indicators"] = counts.get(feed["id"], 0)
    return {"feeds": feeds, "manual": counts.get(MANUAL, 0), "promoted": counts.get(PROMOTED, 0),
            "readers": [r.describe() for r in READERS.values()]}


@ioc_protected_router.post("/api/ioc/feeds/test")
async def test_feed(body: FeedTestIn):
    """Downloads and reads a list without saving anything, so the form can show what it holds before the feed is added."""
    fields = _check_feed_fields(body.model_dump(exclude={"feed_id"}))
    if body.feed_id and not body.key_value:
        async with ioc_db() as db:
            cur = await db.execute("SELECT key_header, key_value FROM ioc_feeds WHERE id = ?", (body.feed_id,))
            row = await cur.fetchone()
        if row and row["key_value"]:
            fields["key_header"] = fields.get("key_header") or row["key_header"]
            fields["key_value"] = row["key_value"]
    started = time.monotonic()
    try:
        _, parsed, _ = await download_and_parse(fields, conditional=False)
    except IocFeedError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # anything unexpected is still a failed test, not a 500
        return {"ok": False, "error": str(e)[:200] or e.__class__.__name__}
    out = {"ok": True, "duration_ms": int((time.monotonic() - started) * 1000), **parsed.summary()}
    reader = reader_for_url(fields.get("url", ""))
    if reader and fields.get("format") != reader.name:
        out["suggest_reader"] = {"name": reader.name, "label": reader.label}
    if not parsed.arrivals and parsed.rejected:
        out["warning"] = nothing_readable(fields, parsed)
    return out


@ioc_protected_router.post("/api/ioc/feeds")
async def add_feed(body: FeedIn):
    fields = _check_feed_fields(body.model_dump())
    fields["id"] = str(uuid.uuid4())
    columns = ", ".join(fields)
    async with ioc_db() as db:
        try:
            await db.execute(f"INSERT INTO ioc_feeds ({columns}) VALUES ({','.join('?' * len(fields))})", list(fields.values()))
            await db.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "A feed with this URL already exists.") from None
    return {"id": fields["id"]}


@ioc_protected_router.patch("/api/ioc/feeds/{feed_id}")
async def edit_feed(feed_id: str, body: FeedEditIn):
    sent = body.model_dump(exclude={"clear_key"}, exclude_unset=True)
    if not sent.get("key_value"):
        sent.pop("key_value", None)
    fields = _check_feed_fields(sent)
    if body.clear_key:
        fields["key_value"] = ""
        fields["key_header"] = ""
    async with ioc_db() as db:
        cur = await db.execute("SELECT * FROM ioc_feeds WHERE id = ?", (feed_id,))
        current = await cur.fetchone()
        if not current:
            raise HTTPException(404, "No such feed")
        if any(fields.get(k, current[k]) != current[k] for k in
               ("url", "format", "value_column", "date_column", "malware_column", "default_type", "key_header", "key_value")):
            # What gets read changed: download the whole list again soon, not "not modified".
            fields.update(etag="", last_modified="", last_fetched=0)
        if fields:
            try:
                await db.execute(f"UPDATE ioc_feeds SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                                 [*fields.values(), feed_id])
            except sqlite3.IntegrityError:
                raise HTTPException(400, "A feed with this URL already exists.") from None
            await db.commit()
        reader = READERS.get(fields.get("format", current["format"]))
        if "confidence" in fields and fields["confidence"] != current["confidence"] and not (reader and reader.per_value_confidence):
            # Feeds that give each value its own confidence (ThreatFox, AbuseIPDB) keep it.
            await set_source_confidence(db, feed_id, fields["confidence"])
        if "name" in fields:
            await db.execute("UPDATE sightings SET source_name = ? WHERE source = ?", (fields["name"], feed_id))
            await db.commit()
    return {"ok": True}


@ioc_protected_router.delete("/api/ioc/feeds/{feed_id}")
async def delete_feed(feed_id: str):
    async with ioc_db() as db:
        cur = await db.execute("DELETE FROM ioc_feeds WHERE id = ?", (feed_id,))
        await db.commit()
        if not cur.rowcount:
            raise HTTPException(404, "No such feed")
        await remove_source(db, feed_id)
    return {"ok": True}


@ioc_protected_router.post("/api/ioc/feeds/{feed_id}/run")
async def run_feed_now(feed_id: str):
    try:
        return await ioc_scheduler.run_now(feed_id)
    except IocUnavailable as e:
        raise HTTPException(503, str(e)) from None


# ------------------------------------------------------------ IOC settings

class IocSettingsIn(BaseModel):
    keep_expired_days: int


@ioc_protected_router.get("/api/ioc/settings")
async def get_ioc_settings():
    async with ioc_db() as db:
        return {"keep_expired_days": await keep_expired_days(db), "keep_expired_choices": list(KEEP_EXPIRED_CHOICES)}


@ioc_protected_router.patch("/api/ioc/settings")
async def update_ioc_settings(body: IocSettingsIn):
    async with ioc_db() as db:
        try:
            await set_keep_expired_days(db, body.keep_expired_days)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        return {"keep_expired_days": await keep_expired_days(db)}


# ------------------------------------------------------------------ backup

@ioc_protected_router.get("/api/ioc/backup")
async def backup_ioc_database():
    """
    A consistent copy of ioc.db (VACUUM INTO, safe while feeds are being
    written), separate from the dashboard's backup. It holds the IOC feeds'
    keys, so it needs the Settings password like the main backup.
    """
    fd, path = tempfile.mkstemp(prefix=".ioc-backup-", suffix=".db", dir=os.path.dirname(os.path.abspath(IOC_DB_PATH)))
    os.close(fd)
    os.remove(path)

    def copy():
        con = sqlite3.connect(IOC_DB_PATH)
        try:
            con.execute("VACUUM INTO ?", (path,))
        finally:
            con.close()
    try:
        await asyncio.get_running_loop().run_in_executor(None, copy)
    except sqlite3.Error as e:
        if os.path.exists(path):
            os.remove(path)
        raise HTTPException(503, f"The IOC database couldn't be copied: {e}") from None
    name = f"pantomath-ioc-backup-{time.strftime('%Y-%m-%d')}.db"
    return FileResponse(path, filename=name, media_type="application/octet-stream", background=BackgroundTask(os.remove, path))


# --------------------------------------------------------------- allowlist

class AllowIn(BaseModel):
    value: str
    reason: str = ""


@ioc_protected_router.get("/api/ioc/allowlist")
async def list_allowlist():
    async with ioc_db() as db:
        cur = await db.execute("SELECT * FROM allowlist ORDER BY type, value")
        return [dict(r) for r in await cur.fetchall()]


@ioc_protected_router.post("/api/ioc/allowlist")
async def add_allow_entry(body: AllowIn):
    try:
        entry_type, value = normalize_allow_entry(body.value)
    except IocValueError as e:
        raise HTTPException(400, f"Can't allowlist that: {e}.") from None
    entry_id = str(uuid.uuid4())
    async with ioc_db() as db:
        try:
            await db.execute("INSERT INTO allowlist (id, type, value, reason) VALUES (?,?,?,?)",
                             (entry_id, entry_type, value, _clean(body.reason, 200)))
            await db.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, f"{value} is on the allowlist already.") from None
        await apply_allowlist(db)
        cur = await db.execute("SELECT COUNT(*) FROM indicators WHERE status = 'allowlisted'")
        covered = (await cur.fetchone())[0]
    return {"id": entry_id, "type": entry_type, "value": value, "allowlisted_total": covered}


@ioc_protected_router.delete("/api/ioc/allowlist/{entry_id}")
async def delete_allow_entry(entry_id: str):
    async with ioc_db() as db:
        cur = await db.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
        await db.commit()
        if not cur.rowcount:
            raise HTTPException(404, "No such entry")
        await apply_allowlist(db)
    return {"ok": True}


# --------------------------------------------------------------- SIEM keys

class SiemKeyIn(BaseModel):
    label: str


@ioc_protected_router.post("/api/auth/siem-keys")
async def create_siem_key(body: SiemKeyIn, request: Request):
    """A key that can call /api/v1 and nothing else, shown once. Revoked like any API key."""
    label = _clean(body.label, 60)
    if not label:
        raise HTTPException(400, "Give the key a name, so you know which SIEM uses it")
    db = await get_db()
    try:
        token, key_id = await sign_in.create_session(db, sign_in.SIEM_ROLE, False, _client_ip(request), "", kind="api", label=label)
    finally:
        await db.close()
    return {"id": key_id, "key": token}


# ------------------------------------------------------------------- /api/v1

async def require_siem_key(request: Request):
    """
    Only SIEM keys (Settings, Security) open /api/v1, sent as
    `Authorization: Bearer <key>`. Browser sessions and ordinary API keys
    don't: they keep exactly the access they had before 1.0.0.
    """
    if sign_in.open_dashboard():
        return
    token = sign_in.token_from(None, request.headers.get("authorization"))
    if token:
        db = await get_db()
        try:
            session = await sign_in.validate(db, token, siem=True)
        finally:
            await db.close()
        if session:
            return
    raise HTTPException(401, "Send a SIEM key as 'Authorization: Bearer <key>'. Create one in Pantomath, Settings, Security.",
                        headers={"WWW-Authenticate": "Bearer"})


siem_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_siem_key)])


@siem_router.get("/lookup")
async def v1_lookup_one(value: str, include_expired: bool = False):
    matched: list[int] = []
    async with ioc_db() as db:
        result = await lookup_values(db, [value.strip()], include_expired, hits=matched)
    hit_counter.record(matched, 1)
    return result["results"][0]


@siem_router.post("/lookup")
async def v1_lookup(body: LookupIn):
    values = _lookup_list(body)
    matched: list[int] = []
    async with ioc_db() as db:
        result = await lookup_values(db, values, body.include_expired, hits=matched)
    hit_counter.record(matched, len(values))
    return result


EXPORT_COLUMNS = ("type", "value", "status", "confidence", "threat_type", "malware", "campaign", "first_seen", "last_seen", "expires_at")


@siem_router.get("/export")
async def v1_export(type: str | None = None, min_confidence: int = 0, malware: str | None = None, feed: str | None = None,
                    format: str = "txt", since: str | None = None, include_expired: bool = False):
    """
    Whole lists for a SIEM lookup table, a firewall's external block list
    or (cdb) a Wazuh CDB list. Without `since`: what matches now (active, or
    also expired with include_expired). With `since`: every indicator that
    changed after that time, whatever its status, so a sync can remove what
    expired; txt can't say that, so it lists only the active ones. The
    X-Pantomath-Exported-At header is the `since` to send next time.

    `cdb` is a Wazuh CDB list: `key:confidence` per line, keys with a colon
    (URLs, IPv6) in double quotes. Wazuh reloads a list only when the
    manager restarts, so it is always the whole list, never `since`.
    """
    if format not in ("txt", "csv", "json", "cdb"):
        raise HTTPException(400, "format is txt, csv, json or cdb")
    if format == "cdb" and since:
        raise HTTPException(400, "A CDB list is always the whole list: leave out since")
    since_ts = parse_since(since)
    if since_ts is not None and format != "txt":
        status = "all"
    else:
        status = "active,expired" if include_expired else "active"
    conditions, params = _indicator_conditions(type, None, status, min_confidence, malware, feed)
    if since_ts is not None:
        conditions.append("updated_at > ?")
        params.append(since_ts)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    # Check the database opens before starting a 200 response.
    async with ioc_db():
        pass
    exported_at = time.time()

    async def rows():
        db = await get_ioc_db()
        try:
            last_id = 0
            while True:
                cur = await db.execute(
                    f"SELECT * FROM indicators{where}{' AND' if where else ' WHERE'} id > ? ORDER BY id LIMIT 5000",
                    [*params, last_id],
                )
                batch = await cur.fetchall()
                if not batch:
                    return
                for r in batch:
                    yield r
                last_id = batch[-1]["id"]
        finally:
            await db.close()

    def record(r) -> dict:
        out = {k: r[k] for k in EXPORT_COLUMNS}
        for k in ("first_seen", "last_seen", "expires_at"):
            out[k] = iso(out[k])
        for k in ("threat_type", "malware", "campaign"):
            out[k] = out[k] or None
        return out

    async def body():
        if format == "txt":
            async for r in rows():
                yield r["value"] + "\n"
        elif format == "cdb":
            async for r in rows():
                value = r["value"]
                if '"' in value or "\n" in value:
                    continue                          # can't be written as a CDB key
                yield (f'"{value}"' if ":" in value else value) + f":{r['confidence']}\n"
        elif format == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(EXPORT_COLUMNS)
            async for r in rows():
                rec = record(r)
                writer.writerow(["" if rec[k] is None else rec[k] for k in EXPORT_COLUMNS])
                if buffer.tell() > 64 * 1024:
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate()
            yield buffer.getvalue()
        else:
            yield '{"exported_at": ' + json.dumps(iso(exported_at)) + ', "indicators": ['
            first = True
            async for r in rows():
                yield ("" if first else ",") + json.dumps(record(r), separators=(",", ":"))
                first = False
            yield "]}\n"

    media = {"txt": "text/plain", "cdb": "text/plain", "csv": "text/csv", "json": "application/json"}[format]
    return StreamingResponse(body(), media_type=f"{media}; charset=utf-8",
                             headers={"X-Pantomath-Exported-At": iso(exported_at)})


@siem_router.get("/health")
async def v1_health():
    """Counts and the last successful feed update, for the SIEM connector's own checks."""
    async with ioc_db() as db:
        cur = await db.execute("SELECT type, COUNT(*) AS n FROM indicators WHERE status = 'active' GROUP BY type")
        by_type = {r["type"]: r["n"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT enabled, last_status, last_success FROM ioc_feeds")
        feeds = [dict(r) for r in await cur.fetchall()]
    enabled = [f for f in feeds if f["enabled"]]
    failing = sum(1 for f in enabled if f["last_status"].startswith("error"))
    return {
        "status": "degraded" if failing else "ok",
        "version": __version__,
        "indicators": {"active": sum(by_type.values()), "by_type": by_type},
        "feeds": {"total": len(feeds), "enabled": len(enabled), "failing": failing},
        "last_feed_update": iso(max((f["last_success"] or 0 for f in feeds), default=0)),
        "generated_at": iso(time.time()),
    }
