import asyncio
import time
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

from pantomath.alerts.dispatcher import build_payload, send_webhook_sync
from pantomath.alerts.webhook_keys import check_and_consume_attempt, hash_key, mask_url, new_salt
from pantomath.connectors.registry import CONNECTOR_REGISTRY, available_connector_types
from pantomath.database.restore import (
    RestoreValidationError,
    restore_database,
    save_upload_to_temp,
    validate_sqlite_backup,
)
from pantomath.database.sqlite import DB_PATH, get_db
from pantomath.intelligence.enrichment import (
    derive_icon_url,
    fetch_and_cache_icon_sync,
    invalidate_icon_cache,
)
from pantomath.intelligence.reprocessor import reprocess_items

router = APIRouter()
active_ws: list[WebSocket] = []


async def broadcast(message: dict):
    dead = []
    for ws in active_ws:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for d in dead:
        if d in active_ws:
            active_ws.remove(d)


def _row_to_item(row: dict) -> dict:
    row["vendors"] = [v for v in (row.get("vendors") or "").split(",") if v]
    row["actors"] = [a for a in (row.get("actors") or "").split(",") if a]
    row["cves"] = [c for c in (row.get("cves") or "").split(",") if c]
    row["ips"] = [i for i in (row.get("ips") or "").split(",") if i]
    row["hashes"] = [h for h in (row.get("hashes") or "").split(",") if h]
    row["emails"] = [e for e in (row.get("emails") or "").split(",") if e]
    row["bookmarked"] = bool(row.get("bookmarked"))
    return row


class SourceIn(BaseModel):
    name: str
    url: str
    category: str = "general"
    color: str = "#5eead4"
    icon_url: str | None = None
    connector_type: str = "rss"
    interval_seconds: int = 300


# ---------------------------------------------------------------- connectors

@router.get("/api/connectors")
async def list_connectors():
    """
    Available source types. v1.0 only ever returns RSS/Atom — this exists
    so the UI (and any future automation) can discover supported types
    instead of hardcoding them, ahead of more connectors landing later.
    """
    return available_connector_types()


# ------------------------------------------------------------------ sources

@router.get("/api/sources/{source_id}/icon")
async def get_source_icon(source_id: str):
    """
    Serves the source's favicon from disk. On the very first request for a
    given source, this fetches the icon once and caches it under
    PANTOMATH_ICON_CACHE (default: alongside the database) — every
    request after that is a disk read, no repeated network calls. If the
    fetch has never succeeded, returns 404, and the frontend's onerror
    handler swaps in the category's colored dot instead.
    """
    db = await get_db()
    cur = await db.execute("SELECT url, icon_url FROM sources WHERE id = ?", (source_id,))
    src = await cur.fetchone()
    await db.close()
    if not src:
        raise HTTPException(404, "source not found")

    fetch_url = src["icon_url"] or derive_icon_url(src["url"])
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, fetch_and_cache_icon_sync, source_id, fetch_url)
    if result is None:
        raise HTTPException(404, "icon not available")
    path, content_type = result
    # These bytes are cached to disk and only change if the source's URL
    # is edited (which calls invalidate_icon_cache server-side). The
    # frontend re-requests this same URL on every feed re-render (30s
    # poll, every WS new_items broadcast) — without any Cache-Control the
    # browser sends a fresh conditional GET every time. 5 minutes cuts
    # nearly all of that repetition within a session while still picking
    # up an edited icon reasonably quickly — a full day (the more
    # "obvious" cache duration) would mean the browser keeps showing a
    # stale icon for up to 24h after an edit, since this URL never
    # changes to bust it on its own.
    return FileResponse(path, media_type=content_type, headers={"Cache-Control": "public, max-age=300"})


@router.get("/api/sources")
async def list_sources():
    db = await get_db()
    cur = await db.execute("SELECT * FROM sources ORDER BY name")
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    return rows


@router.post("/api/sources")
async def add_source(source: SourceIn):
    if source.connector_type not in CONNECTOR_REGISTRY:
        raise HTTPException(
            400,
            f"Unsupported source type '{source.connector_type}'. "
            f"v1.0 only supports: {', '.join(CONNECTOR_REGISTRY)}.",
        )

    db = await get_db()
    sid = str(uuid.uuid4())
    icon_url = source.icon_url or derive_icon_url(source.url)
    try:
        await db.execute(
            """INSERT INTO sources (id, name, url, category, color, icon_url, connector_type, interval_seconds)
               VALUES (?,?,?,?,?,?,?,?)""",
            (sid, source.name, source.url, source.category, source.color, icon_url,
             source.connector_type, source.interval_seconds),
        )
        await db.commit()
    except Exception as e:
        await db.close()
        raise HTTPException(400, f"Could not add source (maybe duplicate URL): {e}") from e
    await db.close()
    await broadcast({"type": "sources_changed"})
    return {"id": sid, "icon_url": icon_url}


@router.delete("/api/sources/{source_id}")
async def delete_source(source_id: str):
    db = await get_db()
    await db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    await db.commit()
    await db.close()
    invalidate_icon_cache(source_id)
    await broadcast({"type": "sources_changed"})
    return {"ok": True}


class SourceEditIn(BaseModel):
    name: str | None = None
    url: str | None = None
    category: str | None = None
    color: str | None = None
    icon_url: str | None = None
    connector_type: str | None = None
    interval_seconds: int | None = None
    enabled: bool | None = None


@router.patch("/api/sources/{source_id}")
async def update_source(source_id: str, payload: SourceEditIn):
    """
    Partial update — only fields actually present in the request body are
    changed; everything else is left as-is. This is what backs both the
    quick pause/resume toggle (sends only `enabled`) and the full Edit
    Source modal (sends whatever fields the user changed). Previously
    this endpoint only supported toggling `enabled`, so editing a
    source's name/URL/category/interval meant deleting and re-adding it
    — this is the actual fix for that gap.
    """
    if payload.connector_type is not None and payload.connector_type not in CONNECTOR_REGISTRY:
        raise HTTPException(
            400,
            f"Unsupported source type '{payload.connector_type}'. "
            f"v1.0 only supports: {', '.join(CONNECTOR_REGISTRY)}.",
        )

    db = await get_db()
    cur = await db.execute("SELECT id FROM sources WHERE id = ?", (source_id,))
    if not await cur.fetchone():
        await db.close()
        raise HTTPException(404, "source not found")

    updates: dict = {}
    for field in ("name", "url", "category", "color", "icon_url", "connector_type", "interval_seconds"):
        value = getattr(payload, field)
        if value is not None:
            updates[field] = value
    if payload.enabled is not None:
        updates["enabled"] = int(payload.enabled)

    if not updates:
        await db.close()
        return {"ok": True}

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    try:
        await db.execute(f"UPDATE sources SET {set_clause} WHERE id = ?", [*updates.values(), source_id])
        await db.commit()
    except Exception as e:
        await db.close()
        raise HTTPException(400, f"Could not update source (maybe duplicate URL): {e}") from e

    if "icon_url" in updates or "url" in updates:
        invalidate_icon_cache(source_id)  # force a re-fetch on next request rather than serving a stale icon

    await db.close()
    await broadcast({"type": "sources_changed"})
    return {"ok": True}


@router.get("/api/sources/export")
async def export_sources():
    db = await get_db()
    cur = await db.execute("SELECT name, url, category, color, icon_url, connector_type, interval_seconds FROM sources")
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    return {"sources": rows}


@router.post("/api/sources/import")
async def import_sources(payload: dict):
    """Bulk-add sources, e.g. from a previously exported feeds.json. Skips duplicates."""
    db = await get_db()
    added, skipped = 0, 0
    for s in payload.get("sources", []):
        icon_url = s.get("icon_url") or derive_icon_url(s["url"])
        try:
            await db.execute(
                """INSERT INTO sources (id, name, url, category, color, icon_url, connector_type, interval_seconds)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (str(uuid.uuid4()), s["name"], s["url"], s.get("category", "general"),
                 s.get("color", "#5eead4"), icon_url, s.get("connector_type", "rss"),
                 s.get("interval_seconds", 300)),
            )
            added += 1
        except Exception:
            skipped += 1
    await db.commit()
    await db.close()
    await broadcast({"type": "sources_changed"})
    return {"added": added, "skipped": skipped}


# -------------------------------------------------------------------- items

def _build_item_conditions(
    source_id=None, category=None, severity=None, keyword=None, vendor=None, actor=None,
    ioc_type=None, ioc_value=None, has_cve=False, has_actor=False, bookmarked_only=False,
    date_from=None, date_to=None,
):
    """
    Shared WHERE-condition builder for GET /api/items and GET
    /api/items/count — kept in one place so the two can never drift out
    of sync (an accurate total is meaningless if it's computed with
    different filter logic than the page of results it's counting).
    """
    conditions = []
    params = []
    if source_id:
        conditions.append("items.source_id = ?")
        params.append(source_id)
    if category:
        conditions.append("sources.category = ?")
        params.append(category)
    if severity:
        # comma-separated for multi-select (e.g. "high,medium"); a single
        # value works the same as before via a one-element IN clause.
        values = [s.strip() for s in severity.split(",") if s.strip()]
        if values:
            placeholders = ",".join("?" * len(values))
            conditions.append(f"items.severity IN ({placeholders})")
            params += values
    if keyword:
        conditions.append("(items.title LIKE ? OR items.summary LIKE ?)")
        params += [f"%{keyword}%", f"%{keyword}%"]
    if vendor:
        conditions.append("(',' || items.vendors || ',') LIKE ?")
        params.append(f"%,{vendor},%")
    if actor:
        conditions.append("(',' || items.actors || ',') LIKE ?")
        params.append(f"%,{actor},%")
    if ioc_type and ioc_value:
        ioc_column = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}.get(ioc_type)
        if not ioc_column:
            raise HTTPException(400, f"Unknown ioc_type '{ioc_type}'. Use one of: cve, ip, hash, email.")
        conditions.append(f"(',' || items.{ioc_column} || ',') LIKE ?")
        params.append(f"%,{ioc_value},%")
    elif ioc_type:
        # ioc_type given without a specific ioc_value: "has at least one IOC
        # of this type" — powers the IOC calendar's day drilldown (all CVEs
        # mentioned on a given day, not just occurrences of one specific CVE).
        ioc_column = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}.get(ioc_type)
        if not ioc_column:
            raise HTTPException(400, f"Unknown ioc_type '{ioc_type}'. Use one of: cve, ip, hash, email.")
        conditions.append(f"items.{ioc_column} != ''")
    if has_cve:
        conditions.append("items.cves != ''")
    if has_actor:
        conditions.append("items.actors != ''")
    if bookmarked_only:
        conditions.append("items.bookmarked = 1")
    if date_from:
        conditions.append("items.fetched_at >= ?")
        params.append(_day_start_ts(date_from))
    if date_to:
        conditions.append("items.fetched_at <= ?")
        params.append(_day_end_ts(date_to))
    return conditions, params


@router.get("/api/items")
async def list_items(
    limit: int = 100,
    offset: int = 0,
    source_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,  # single value, or comma-separated for multiple (e.g. "high,medium")
    keyword: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    ioc_type: str | None = None,   # 'cve' | 'ip' | 'hash' | 'email'
    ioc_value: str | None = None,
    has_cve: bool = False,  # items with at least one extracted CVE, regardless of source category
    has_actor: bool = False,  # items with at least one detected threat actor (ransomware gang/APT group)
    bookmarked_only: bool = False,
    date_from: str | None = None,  # 'YYYY-MM-DD', inclusive, matched against fetched_at
    date_to: str | None = None,    # 'YYYY-MM-DD', inclusive
):
    db = await get_db()
    q = """SELECT items.*, sources.name as source_name, sources.color as source_color,
                  sources.icon_url as source_icon, sources.category as category
           FROM items JOIN sources ON items.source_id = sources.id"""
    conditions, params = _build_item_conditions(
        source_id, category, severity, keyword, vendor, actor, ioc_type, ioc_value,
        has_cve, has_actor, bookmarked_only, date_from, date_to,
    )
    if conditions:
        q += " WHERE " + " AND ".join(conditions)
    q += " ORDER BY items.fetched_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    cur = await db.execute(q, params)
    rows = [_row_to_item(dict(r)) for r in await cur.fetchall()]
    await db.close()
    return rows


@router.get("/api/items/count")
async def count_items(
    source_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    keyword: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    ioc_type: str | None = None,
    ioc_value: str | None = None,
    has_cve: bool = False,
    has_actor: bool = False,
    bookmarked_only: bool = False,
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Total matching items for the same filters GET /api/items accepts — powers numbered pagination."""
    db = await get_db()
    q = "SELECT COUNT(*) as total FROM items JOIN sources ON items.source_id = sources.id"
    conditions, params = _build_item_conditions(
        source_id, category, severity, keyword, vendor, actor, ioc_type, ioc_value,
        has_cve, has_actor, bookmarked_only, date_from, date_to,
    )
    if conditions:
        q += " WHERE " + " AND ".join(conditions)
    cur = await db.execute(q, params)
    row = await cur.fetchone()
    await db.close()
    return {"total": row["total"]}


def _day_start_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    return dt.timestamp()


def _day_end_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d") + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
    return dt.timestamp()


def _date_range_where(date_from: str | None, date_to: str | None) -> tuple[str, list]:
    """
    Builds a `fetched_at BETWEEN ...`-style WHERE fragment (empty string if
    neither bound given) plus its params, for endpoints that scope a query
    to a date range — shared by /api/iocs, /api/iocs/summary, and
    /api/iocs/calendar so date handling can't drift out of sync between them.
    """
    clauses = []
    params: list = []
    if date_from:
        clauses.append("fetched_at >= ?")
        params.append(_day_start_ts(date_from))
    if date_to:
        clauses.append("fetched_at <= ?")
        params.append(_day_end_ts(date_to))
    return " AND ".join(clauses), params


@router.get("/api/items/range")
async def items_date_range():
    """Earliest/latest stored item timestamps — lets the UI bound a date picker to actual data."""
    db = await get_db()
    cur = await db.execute("SELECT MIN(fetched_at) as earliest, MAX(fetched_at) as latest, COUNT(*) as total FROM items")
    row = await cur.fetchone()
    await db.close()
    return {"earliest": row["earliest"], "latest": row["latest"], "total": row["total"]}


@router.patch("/api/items/{item_id}/bookmark")
async def toggle_bookmark(item_id: str, bookmarked: bool):
    db = await get_db()
    await db.execute("UPDATE items SET bookmarked = ? WHERE id = ?", (int(bookmarked), item_id))
    await db.commit()
    await db.close()
    return {"ok": True}


def _comma_column_counts_query(column: str, extra_where: str = "") -> str:
    """
    Builds a query that counts occurrences of each value in a comma-joined
    TEXT column (e.g. items.vendors = "Microsoft,Cisco") without ever
    pulling the raw column values into Python. A recursive CTE splits
    each row's comma list inside SQLite itself; only the final
    (value, count) pairs cross into the app.

    Previously these endpoints did `SELECT {col} FROM items WHERE {col}
    != ''`, loaded every matching row's full text into a Python list, and
    split/counted it there — memory and CPU cost scaling with total
    matching rows, on every request, on some of the most-hit endpoints
    (Dashboard, IOCs page). This does the same job inside the SQL engine.
    """
    where = f"{column} != ''" + (f" AND {extra_where}" if extra_where else "")
    return f"""
        WITH RECURSIVE
          base AS (SELECT {column} || ',' AS rest FROM items WHERE {where}),
          split(tag, rest) AS (
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1) FROM base
            UNION ALL
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1)
            FROM split WHERE rest != ''
          )
        SELECT tag AS name, COUNT(*) AS count FROM split WHERE tag != ''
        GROUP BY tag
    """


@router.get("/api/tags")
async def list_tags(type: str = "vendor", limit: int = 20):
    """Distinct vendor/threat-actor tags with counts, for chip filters and the Vendors/Threat Actors pages."""
    col = "vendors" if type == "vendor" else "actors"
    db = await get_db()
    query = _comma_column_counts_query(col) + " ORDER BY count DESC, name ASC LIMIT ?"
    cur = await db.execute(query, (limit,))
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    return rows


_IOC_COLUMNS = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}


@router.get("/api/iocs")
async def list_iocs(
    type: str = "cve", limit: int = 20, offset: int = 0,
    date_from: str | None = None, date_to: str | None = None,
):
    """
    Distinct IOCs of one type with occurrence counts, paginated —
    powers the IOCs page's bar chart and chip list. `offset` lets the
    frontend page through every distinct IOC of a type instead of only
    ever seeing the top `limit`; pair with GET /api/iocs/summary's
    per-type distinct count to know how many pages exist.

    Ranked by count descending, then by name ascending as a tiebreaker
    — without a deterministic tiebreak, IOCs with equal counts could
    silently swap pages between requests (dict ordering isn't a
    stable ranking), which would be confusing while paginating.

    date_from/date_to (both 'YYYY-MM-DD', inclusive) scope the count to
    just that range — used when a day is selected on the IOCs page's
    calendar, so "top CVEs" reflects that day instead of all-time.
    """
    col = _IOC_COLUMNS.get(type)
    if not col:
        raise HTTPException(400, f"Unknown IOC type '{type}'. Use one of: {', '.join(_IOC_COLUMNS)}.")
    date_where, date_params = _date_range_where(date_from, date_to)
    db = await get_db()
    query = _comma_column_counts_query(col, extra_where=date_where) + " ORDER BY count DESC, name ASC LIMIT ? OFFSET ?"
    cur = await db.execute(query, (*date_params, limit, offset))
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    return rows


@router.get("/api/iocs/summary")
async def iocs_summary(date_from: str | None = None, date_to: str | None = None):
    """
    Distinct-IOC-count per type — powers the IOC type distribution chart.
    date_from/date_to optionally scope it to a range, same as /api/iocs,
    so the donut reflects a selected calendar day instead of all-time.
    """
    date_where, date_params = _date_range_where(date_from, date_to)
    db = await get_db()
    summary = {}
    for ioc_type, col in _IOC_COLUMNS.items():
        query = f"SELECT COUNT(*) AS n FROM ({_comma_column_counts_query(col, extra_where=date_where)})"
        cur = await db.execute(query, date_params)
        row = await cur.fetchone()
        summary[ioc_type] = row["n"]
    await db.close()
    return summary


@router.get("/api/iocs/calendar")
async def iocs_calendar(type: str = "cve", date_from: str | None = None, date_to: str | None = None):
    """
    Per-day counts of items containing at least one IOC of the given
    type, for the IOCs page's calendar heatmap — 'how many articles with
    a CVE landed on July 14th' rather than 'how many times was CVE-X
    mentioned' (that's what /api/iocs already answers per-value).

    date_from/date_to (both 'YYYY-MM-DD', inclusive) scope it to the
    currently-displayed month rather than the item's entire history —
    with a database running for a year+, an unbounded version of this
    would return one row per day since install, most of them irrelevant
    to whatever month the user is currently looking at.

    Returns a plain list — [{"date": "2026-07-14", "count": 3}, ...] —
    computed entirely in SQL (a single GROUP BY), not by loading rows
    into Python and bucketing them there.
    """
    col = _IOC_COLUMNS.get(type)
    if not col:
        raise HTTPException(400, f"Unknown IOC type '{type}'. Use one of: {', '.join(_IOC_COLUMNS)}.")
    date_where, date_params = _date_range_where(date_from, date_to)
    where = f"{col} != ''" + (f" AND {date_where}" if date_where else "")
    query = f"""
        SELECT strftime('%Y-%m-%d', fetched_at, 'unixepoch', 'localtime') AS date, COUNT(*) AS count
        FROM items WHERE {where} GROUP BY date ORDER BY date
    """
    db = await get_db()
    cur = await db.execute(query, date_params)
    rows = [dict(r) for r in await cur.fetchall()]
    await db.close()
    return rows


# -------------------------------------------------------------------- stats

@router.get("/api/stats")
async def get_stats():
    db = await get_db()
    now = time.time()
    day_ago = now - 86400
    week_ago = now - (86400 * 7)

    async def scalar(query, params=()):
        cur = await db.execute(query, params)
        row = await cur.fetchone()
        return row[0] if row else 0

    total_articles = await scalar("SELECT COUNT(*) FROM items")
    new_today = await scalar("SELECT COUNT(*) FROM items WHERE fetched_at > ?", (day_ago,))
    critical_alerts = await scalar(
        "SELECT COUNT(*) FROM items WHERE severity = 'high' AND fetched_at > ?", (day_ago,)
    )
    sources_count = await scalar("SELECT COUNT(*) FROM sources WHERE enabled = 1")
    total_sources = await scalar("SELECT COUNT(*) FROM sources")

    cur = await db.execute("SELECT severity, COUNT(*) c FROM items GROUP BY severity")
    severity_dist = {r["severity"]: r["c"] for r in await cur.fetchall()}

    cur = await db.execute(
        """SELECT sources.category as category, COUNT(*) c FROM items
           JOIN sources ON items.source_id = sources.id GROUP BY sources.category"""
    )
    category_dist = {r["category"]: r["c"] for r in await cur.fetchall()}

    cur = await db.execute(
        """SELECT sources.name as name, COUNT(*) c FROM items
           JOIN sources ON items.source_id = sources.id
           GROUP BY sources.name ORDER BY c DESC LIMIT 5"""
    )
    top_sources = [{"name": r["name"], "count": r["c"]} for r in await cur.fetchall()]

    cur = await db.execute(
        _comma_column_counts_query("vendors", extra_where="fetched_at > ?") + " ORDER BY count DESC, name ASC LIMIT 5",
        (week_ago,),
    )
    top_vendors = [(r["name"], r["count"]) for r in await cur.fetchall()]

    # articles/day for the last 7 days — bucketed in SQL rather than
    # pulling every fetched_at timestamp into Python and grouping there.
    # 'localtime' matches the previous behavior (time.localtime bucketing).
    cur = await db.execute(
        """SELECT strftime('%Y-%m-%d', fetched_at, 'unixepoch', 'localtime') AS day, COUNT(*) AS c
           FROM items WHERE fetched_at > ? GROUP BY day""",
        (week_ago,),
    )
    day_buckets = {r["day"]: r["c"] for r in await cur.fetchall()}

    await db.close()
    return {
        "total_articles": total_articles,
        "new_today": new_today,
        "critical_alerts": critical_alerts,
        "sources_active": sources_count,
        "sources_total": total_sources,
        "severity_distribution": severity_dist,
        "category_distribution": category_dist,
        "top_sources": top_sources,
        "top_vendors": [{"name": n, "count": c} for n, c in top_vendors],
        "articles_by_day": day_buckets,
    }


@router.get("/api/backup")
async def backup_database():
    return FileResponse(DB_PATH, filename="pantomath-backup.db", media_type="application/octet-stream")


@router.post("/api/restore")
async def restore_database_endpoint(file: UploadFile = File(...)):
    """
    Restores the database from a previously-downloaded /api/backup file.
    This REPLACES every item, source, setting, and webhook currently
    stored — it is the one genuinely destructive endpoint in this app.

    Safety sequence (see pantomath/database/restore.py for the full
    reasoning): the upload is streamed to a temp file and fully
    validated (SQLite header, integrity check, expected tables) before
    the live database is touched at all; a bad or unrelated file never
    gets this far. Only then is the live database checkpointed and
    copied to a timestamped pantomath-pre-restore-*.db safety backup,
    before the validated upload is atomically swapped into place.

    Returns the safety-backup path so the caller always has a way back
    if the restore turns out to be the wrong file.
    """
    tmp_path = None
    try:
        tmp_path = await save_upload_to_temp(file)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, validate_sqlite_backup, tmp_path)
        # on success, restore_database consumes/moves tmp_path via os.replace
        result = await loop.run_in_executor(None, restore_database, tmp_path)
        return result
    except RestoreValidationError as e:
        raise HTTPException(400, str(e))
    finally:
        # If we're still holding tmp_path here, either validation failed
        # (raised before restore_database ran) or something else went
        # wrong before the os.replace() — in both cases it was never
        # moved, so clean it up. If restore_database() succeeded,
        # tmp_path no longer exists (os.replace already consumed it) and
        # this is a harmless no-op.
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


# ----------------------------------------------------------------- settings

@router.get("/api/settings")
async def get_settings():
    db = await get_db()
    cur = await db.execute("SELECT key, value FROM settings")
    rows = {r["key"]: r["value"] for r in await cur.fetchall()}
    await db.close()
    return {
        # 0 = keep forever (default). Otherwise, a number of days.
        "retention_days": int(rows.get("retention_days", 0)),
        # Whether new items get their full article page fetched for
        # richer severity/tag/IOC extraction. Default on — see
        # pantomath/connectors/rss.py:_deep_extraction_enabled.
        "deep_extraction": rows.get("deep_extraction", "1") != "0",
    }


@router.post("/api/settings")
async def update_settings(payload: dict):
    db = await get_db()
    for key, value in payload.items():
        await db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
    await db.commit()
    await db.close()
    return {"ok": True}


# ----------------------------------------------------------------- webhooks

class WebhookIn(BaseModel):
    name: str
    url: str
    keyword: str = ""
    source_id: str = ""
    min_severity: str = ""
    enabled: bool = True
    allow_insecure_tls: bool = False  # skip TLS certificate verification (self-signed certs, internal CAs)
    key: str | None = None  # optional — if set, this webhook is protected from creation


def _serialize_webhook(row: dict) -> dict:
    """Never sends key_hash/key_salt/attempt-tracking to the client, and
    masks the URL for protected webhooks — the whole point of protecting
    one is that loading the Settings page shouldn't hand out the real URL."""
    out = {k: v for k, v in row.items() if k not in ("key_hash", "key_salt", "key_fail_count", "key_locked_until")}
    if row.get("protected"):
        out["url"] = mask_url(row["url"])
    return out


@router.get("/api/webhooks")
async def list_webhooks():
    db = await get_db()
    cur = await db.execute("SELECT * FROM webhooks ORDER BY name")
    rows = [_serialize_webhook(dict(r)) for r in await cur.fetchall()]
    await db.close()
    return rows


@router.post("/api/webhooks")
async def add_webhook(webhook: WebhookIn):
    if webhook.min_severity and webhook.min_severity not in ("low", "medium", "high"):
        raise HTTPException(400, "min_severity must be one of: low, medium, high (or empty for any)")
    if webhook.key is not None and not webhook.key.strip():
        raise HTTPException(400, "Webhook key can't be blank")

    db = await get_db()
    wid = str(uuid.uuid4())
    protected, key_salt, key_hash = 0, None, None
    if webhook.key:
        salt = new_salt()
        protected, key_salt, key_hash = 1, salt.hex(), hash_key(webhook.key, salt)

    await db.execute(
        """INSERT INTO webhooks (id, name, url, keyword, source_id, min_severity, enabled, protected, key_salt, key_hash, allow_insecure_tls)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (wid, webhook.name, webhook.url, webhook.keyword, webhook.source_id,
         webhook.min_severity, int(webhook.enabled), protected, key_salt, key_hash, int(webhook.allow_insecure_tls)),
    )
    await db.commit()
    await db.close()
    return {"id": wid}


class WebhookEditIn(BaseModel):
    name: str | None = None
    url: str | None = None
    keyword: str | None = None
    source_id: str | None = None
    min_severity: str | None = None
    enabled: bool | None = None
    allow_insecure_tls: bool | None = None  # skip TLS certificate verification (self-signed certs, internal CAs)
    key: str | None = None            # current key — required to authorize any change to an already-protected webhook
    set_key: str | None = None        # sets a new key: adds protection if there wasn't any, or changes the existing one
    remove_protection: bool = False   # drops protection entirely (still requires the current `key`)


class WebhookKeyIn(BaseModel):
    key: str


@router.patch("/api/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, payload: WebhookEditIn):
    """Partial update, same pattern as sources — only fields present in the body are changed.
    A protected webhook requires the correct `key` before anything about it
    can change, including removing the protection itself."""
    if payload.min_severity and payload.min_severity not in ("low", "medium", "high"):
        raise HTTPException(400, "min_severity must be one of: low, medium, high (or empty for any)")

    db = await get_db()
    cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
    row = await cur.fetchone()
    if not row:
        await db.close()
        raise HTTPException(404, "webhook not found")
    row = dict(row)

    if row.get("protected"):
        ok, err = await check_and_consume_attempt(db, row, payload.key or "")
        if not ok:
            await db.close()
            raise HTTPException(401, err)

    updates: dict = {}
    for field in ("name", "url", "keyword", "source_id", "min_severity"):
        value = getattr(payload, field)
        if value is not None:
            updates[field] = value
    if payload.enabled is not None:
        updates["enabled"] = int(payload.enabled)
    if payload.allow_insecure_tls is not None:
        updates["allow_insecure_tls"] = int(payload.allow_insecure_tls)

    if payload.set_key is not None:
        if not payload.set_key.strip():
            await db.close()
            raise HTTPException(400, "Webhook key can't be blank")
        salt = new_salt()
        updates.update(
            protected=1, key_salt=salt.hex(), key_hash=hash_key(payload.set_key, salt),
            key_fail_count=0, key_locked_until=0,
        )
    elif payload.remove_protection:
        updates.update(protected=0, key_salt=None, key_hash=None, key_fail_count=0, key_locked_until=0)

    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        await db.execute(f"UPDATE webhooks SET {set_clause} WHERE id = ?", [*updates.values(), webhook_id])
        await db.commit()
    await db.close()
    return {"ok": True}


@router.post("/api/webhooks/{webhook_id}/reveal")
async def reveal_webhook_url(webhook_id: str, payload: WebhookKeyIn):
    """Returns the real URL for a webhook. Unprotected webhooks return it
    immediately; protected ones require the correct key. This — plus
    deleting and recreating — is the only way to see a protected webhook's
    full URL again."""
    db = await get_db()
    cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
    row = await cur.fetchone()
    if not row:
        await db.close()
        raise HTTPException(404, "webhook not found")
    row = dict(row)

    if not row.get("protected"):
        await db.close()
        return {"url": row["url"]}

    ok, err = await check_and_consume_attempt(db, row, payload.key)
    await db.close()
    if not ok:
        raise HTTPException(401, err)
    return {"url": row["url"]}


@router.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    db = await get_db()
    await db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    await db.commit()
    await db.close()
    return {"ok": True}


@router.post("/api/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str):
    """Sends a synthetic test payload immediately, so you can verify a webhook works without waiting for a real match."""
    db = await get_db()
    cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
    webhook = await cur.fetchone()
    if not webhook:
        await db.close()
        raise HTTPException(404, "webhook not found")
    webhook = dict(webhook)

    test_item = {
        "id": "test", "title": "Pantomath test alert",
        "summary": "This is a test payload sent from the Settings page — if you're seeing this, the webhook is working.",
        "link": "", "severity": "high", "source_id": "", "source_name": "Pantomath",
        "category": "general", "vendors": [], "actors": [], "cves": [],
    }
    payload = build_payload(test_item, webhook)
    loop = asyncio.get_event_loop()
    ok, status = await loop.run_in_executor(
        None, send_webhook_sync, webhook["url"], payload, bool(webhook.get("allow_insecure_tls"))
    )

    await db.execute(
        "UPDATE webhooks SET last_triggered = ?, last_status = ? WHERE id = ?",
        (time.time(), status, webhook_id),
    )
    await db.commit()
    await db.close()
    if not ok:
        raise HTTPException(502, f"Webhook delivery failed: {status}")
    return {"ok": True, "status": status}


# ----------------------------------------------------------------- polling

def make_poll_now_route(scheduler):
    @router.post("/api/sources/{source_id}/poll")
    async def poll_now(source_id: str):
        db = await get_db()
        cur = await db.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
        src = await cur.fetchone()
        if not src:
            await db.close()
            raise HTTPException(404, "source not found")
        await scheduler.poll_source(db, dict(src))
        await db.close()
        return {"ok": True}

    @router.post("/api/sources/poll-all")
    async def poll_all_now():
        """
        Refreshes every enabled source immediately, bypassing each
        source's normal interval throttle — an on-demand "refresh now"
        rather than waiting for the next scheduled tick. Same
        fetch -> normalize -> validate -> store pipeline as a normal
        poll; the UNIQUE(source_id, guid) constraint means this is safe
        to run as often as you like — it only ever adds genuinely new
        items, never duplicates.
        """
        db = await get_db()
        cur = await db.execute("SELECT * FROM sources WHERE enabled = 1")
        sources = [dict(r) for r in await cur.fetchall()]
        for src in sources:
            await scheduler.poll_source(db, src)
        await db.close()
        return {"ok": True, "sources_polled": len(sources)}

    return poll_now


# ------------------------------------------------------------- reprocessing

class ReprocessIn(BaseModel):
    source_id: str | None = None
    deep_extraction: bool | None = None  # None = respect the current Settings toggle


@router.post("/api/reprocess")
async def reprocess(payload: ReprocessIn | None = None):
    """
    Re-runs severity/tagging/IOC extraction against items already on
    disk — no RSS re-fetch, no network call to the source at all (only
    to each item's own article page, if deep extraction is used). This
    is what actually backfills vendors/actors/CVEs/etc. for items stored
    before those extraction features existed; adding a database column
    with a migration never retroactively computes values for old rows.
    Can take a while on a large history with deep extraction on — it's a
    foreground request deliberately (so the caller gets a real
    processed/sources count back), not fired into the background.
    """
    payload = payload or ReprocessIn()
    db = await get_db()
    result = await reprocess_items(db, payload.source_id, payload.deep_extraction)
    await db.close()
    return result


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_ws.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_ws:
            active_ws.remove(websocket)
