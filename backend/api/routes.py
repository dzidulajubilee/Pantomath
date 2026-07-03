import time
import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.database.sqlite import get_db, DB_PATH
from backend.intelligence.enrichment import derive_icon_url, fetch_and_cache_icon_sync, invalidate_icon_cache
from backend.connectors.registry import available_connector_types, CONNECTOR_REGISTRY
import asyncio

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
    return FileResponse(path, media_type=content_type)


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
        raise HTTPException(400, f"Could not add source (maybe duplicate URL): {e}")
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


@router.patch("/api/sources/{source_id}")
async def toggle_source(source_id: str, enabled: bool):
    db = await get_db()
    await db.execute("UPDATE sources SET enabled = ? WHERE id = ?", (int(enabled), source_id))
    await db.commit()
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

@router.get("/api/items")
async def list_items(
    limit: int = 100,
    offset: int = 0,
    source_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    keyword: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    bookmarked_only: bool = False,
    date_from: str | None = None,  # 'YYYY-MM-DD', inclusive, matched against fetched_at
    date_to: str | None = None,    # 'YYYY-MM-DD', inclusive
):
    db = await get_db()
    q = """SELECT items.*, sources.name as source_name, sources.color as source_color,
                  sources.icon_url as source_icon, sources.category as category
           FROM items JOIN sources ON items.source_id = sources.id"""
    conditions = []
    params = []
    if source_id:
        conditions.append("items.source_id = ?"); params.append(source_id)
    if category:
        conditions.append("sources.category = ?"); params.append(category)
    if severity:
        conditions.append("items.severity = ?"); params.append(severity)
    if keyword:
        conditions.append("(items.title LIKE ? OR items.summary LIKE ?)")
        params += [f"%{keyword}%", f"%{keyword}%"]
    if vendor:
        conditions.append("(',' || items.vendors || ',') LIKE ?"); params.append(f"%,{vendor},%")
    if actor:
        conditions.append("(',' || items.actors || ',') LIKE ?"); params.append(f"%,{actor},%")
    if bookmarked_only:
        conditions.append("items.bookmarked = 1")
    if date_from:
        conditions.append("items.fetched_at >= ?")
        params.append(_day_start_ts(date_from))
    if date_to:
        conditions.append("items.fetched_at <= ?")
        params.append(_day_end_ts(date_to))
    if conditions:
        q += " WHERE " + " AND ".join(conditions)
    q += " ORDER BY items.fetched_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    cur = await db.execute(q, params)
    rows = [_row_to_item(dict(r)) for r in await cur.fetchall()]
    await db.close()
    return rows


def _day_start_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    return dt.timestamp()


def _day_end_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d") + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
    return dt.timestamp()


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


@router.get("/api/tags")
async def list_tags(type: str = "vendor", limit: int = 20):
    """Distinct vendor/threat-actor tags with counts, for chip filters and the Vendors/Threat Actors pages."""
    col = "vendors" if type == "vendor" else "actors"
    db = await get_db()
    cur = await db.execute(f"SELECT {col} FROM items WHERE {col} != ''")
    rows = await cur.fetchall()
    await db.close()
    counts: dict[str, int] = {}
    for row in rows:
        for tag in row[0].split(","):
            if tag:
                counts[tag] = counts.get(tag, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"name": name, "count": count} for name, count in ranked]


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
        "SELECT vendors FROM items WHERE vendors != '' AND fetched_at > ?", (week_ago,)
    )
    vendor_counts: dict[str, int] = {}
    for row in await cur.fetchall():
        for v in row["vendors"].split(","):
            if v:
                vendor_counts[v] = vendor_counts.get(v, 0) + 1
    top_vendors = sorted(vendor_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

    # articles/day for the last 7 days
    cur = await db.execute(
        "SELECT fetched_at FROM items WHERE fetched_at > ?", (week_ago,)
    )
    day_buckets = {}
    for row in await cur.fetchall():
        day_key = time.strftime("%Y-%m-%d", time.localtime(row["fetched_at"]))
        day_buckets[day_key] = day_buckets.get(day_key, 0) + 1

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
    return poll_now


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
