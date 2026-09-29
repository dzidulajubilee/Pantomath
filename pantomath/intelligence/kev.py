"""
CISA's Known Exploited Vulnerabilities (KEV) catalog: CVEs confirmed to be
exploited in real attacks. Pantomath downloads the catalog (a public JSON
file) once a day and marks every item that mentions a CVE on it as
Exploited, with the date CISA added it and CISA's remediation deadline.

This is evidence, not a score: severity stays Pantomath's own keyword
rating, and "Exploited" is shown next to it. The catalog is deliberately
narrow, so a CVE that isn't on it is not therefore safe.

Servers without internet access can point `kev_url` (Settings) at an
internal mirror of the same JSON file.
"""
import asyncio
import json
import re
import socket
import time
import urllib.error
import urllib.request

from pantomath.intelligence.priority import compute_priority, content_of

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TIMEOUT = 30            # seconds per network read
KEV_HARD_LIMIT = 120        # seconds for the whole download
KEV_MAX_BYTES = 30 * 1024 * 1024
REFRESH_AFTER_SUCCESS = 24 * 3600
RETRY_AFTER_FAILURE = 3600
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_BATCH = 2000


class KevError(Exception):
    """A catalog download or parse failure, worded for the Settings page."""


def fetch_kev_sync(url: str) -> list[dict]:
    if not url.lower().startswith(("http://", "https://")):
        raise KevError("only http:// and https:// URLs are supported")
    request = urllib.request.Request(url, headers={
        "User-Agent": "Pantomath (+https://github.com/dzidulajubilee/Pantomath)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=KEV_TIMEOUT) as response:
            data = response.read(KEV_MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise KevError(f"HTTP {e.code} {e.reason}") from None
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.gaierror):
            raise KevError("could not resolve the host name (no internet access?)") from None
        raise KevError(f"could not connect: {reason}") from None
    except TimeoutError:
        raise KevError(f"no response within {KEV_TIMEOUT}s") from None
    if len(data) > KEV_MAX_BYTES:
        raise KevError("the file is larger than 30 MB, which is not a KEV catalog")
    try:
        document = json.loads(data)
    except ValueError:
        raise KevError("the URL did not return JSON") from None
    vulnerabilities = document.get("vulnerabilities") if isinstance(document, dict) else None
    if not isinstance(vulnerabilities, list):
        raise KevError("the JSON is not a KEV catalog (no 'vulnerabilities' list)")

    entries = {}
    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID", "")).strip().upper()
        if not _CVE.fullmatch(cve):
            continue
        entries[cve] = {
            "cve": cve,
            "vendor": str(v.get("vendorProject", ""))[:200],
            "product": str(v.get("product", ""))[:200],
            "name": str(v.get("vulnerabilityName", ""))[:300],
            "date_added": str(v.get("dateAdded", ""))[:10],
            "due_date": str(v.get("dueDate", ""))[:10],
            "ransomware": str(v.get("knownRansomwareCampaignUse", ""))[:20],
            "description": str(v.get("shortDescription", ""))[:600],
        }
    if not entries:
        raise KevError("the catalog contains no vulnerabilities")
    return list(entries.values())


def kev_hits(cves: list[str], kev_set: set[str]) -> list[str]:
    return [c for c in cves if c.upper() in kev_set]


async def load_kev_set(db) -> set[str]:
    cur = await db.execute("SELECT cve FROM kev")
    return {r["cve"] for r in await cur.fetchall()}


async def recompute_item_kev(db) -> int:
    """Re-marks stored items after the catalog changes; returns how many are marked."""
    kev_set = await load_kev_set(db)
    marked, last_rowid = 0, 0
    while True:
        cur = await db.execute(
            """SELECT rowid, id, cves, kev_cves, watch_hits, severity, content_severity FROM items
               WHERE rowid > ? AND (cves != '' OR kev_cves != '') ORDER BY rowid LIMIT ?""",
            (last_rowid, _BATCH),
        )
        rows = await cur.fetchall()
        if not rows:
            break
        updates = []
        for row in rows:
            hits = ",".join(kev_hits([c for c in (row["cves"] or "").split(",") if c], kev_set))
            marked += bool(hits)
            level = compute_priority(content_of(row), bool(row["watch_hits"]), bool(hits))
            if hits != (row["kev_cves"] or "") or level != row["severity"]:
                updates.append((hits, level, row["id"]))
        if updates:
            await db.executemany("UPDATE items SET kev_cves = ?, severity = ? WHERE id = ?", updates)
        last_rowid = rows[-1]["rowid"]
    return marked


async def _get(db, key: str, default: str = "") -> str:
    cur = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = await cur.fetchone()
    return row["value"] if row and row["value"] is not None else default


async def _set(db, key: str, value: str) -> None:
    await db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


async def kev_status(db) -> dict:
    cur = await db.execute("SELECT COUNT(*) FROM kev")
    count = (await cur.fetchone())[0]
    return {
        "enabled": await _get(db, "kev_enabled", "1") != "0",
        "url": await _get(db, "kev_url", ""),
        "default_url": DEFAULT_KEV_URL,
        "count": count,
        "updated_at": float(await _get(db, "kev_updated_at", "0")) or None,
        "checked_at": float(await _get(db, "kev_checked_at", "0")) or None,
        "error": await _get(db, "kev_error", ""),
    }


async def kev_due(db, now: float) -> bool:
    status = await kev_status(db)
    if not status["enabled"]:
        return False
    wait = RETRY_AFTER_FAILURE if status["error"] else REFRESH_AFTER_SUCCESS
    return now - (status["checked_at"] or 0) >= wait


async def refresh_kev(db) -> dict:
    """
    Downloads the catalog and replaces the stored copy. On any failure the
    previous copy is kept and the reason is recorded for the Settings page.
    """
    url = (await _get(db, "kev_url", "")).strip() or DEFAULT_KEV_URL
    loop = asyncio.get_running_loop()
    now = time.time()
    try:
        entries = await asyncio.wait_for(loop.run_in_executor(None, fetch_kev_sync, url), timeout=KEV_HARD_LIMIT)
    except asyncio.TimeoutError:
        error = f"no complete response within {KEV_HARD_LIMIT}s"
    except KevError as e:
        error = str(e)
    except Exception as e:  # never let a bad catalog take the scheduler down
        error = str(e)[:200] or e.__class__.__name__
    else:
        error = ""
        await db.execute("DELETE FROM kev")
        await db.executemany(
            """INSERT INTO kev (cve, vendor, product, name, date_added, due_date, ransomware, description)
               VALUES (:cve, :vendor, :product, :name, :date_added, :due_date, :ransomware, :description)""",
            entries,
        )
        await recompute_item_kev(db)
        await _set(db, "kev_updated_at", str(now))
    await _set(db, "kev_checked_at", str(now))
    await _set(db, "kev_error", error)
    await db.commit()
    return await kev_status(db)
