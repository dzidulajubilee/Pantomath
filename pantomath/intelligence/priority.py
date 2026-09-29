"""
Priority: Critical, High, Medium or Low, from three signals.

  - the article's wording (scoring.py: High, Medium or Low keywords);
  - Exploited: one of its CVEs is on CISA's Known Exploited
    Vulnerabilities catalog (kev.py);
  - Affects us: it names something on Our stack (watchlist.py).

                                   doesn't mention    mentions
                                   our stack          our stack
  Exploited (on CISA's list)       High               Critical
  Wording: serious flaw            High               Critical
  Wording: vulnerability, CVE...   Medium             High
  Anything else                    Low                Medium

In one line: anything exploited is at least High, and mentioning our
stack raises an item one level. Critical therefore always means "something
we run, with confirmed exploitation or a serious flaw" — it stays rare
enough to act on.

The result is stored in items.severity (so every filter, count, webhook and
notification threshold uses it); the keyword rating is kept separately in
items.content_severity so the priority can be worked out again whenever Our
stack or the catalog changes, without re-reading the article.
"""

LEVELS = ("low", "medium", "high", "critical")
RANK = {level: n for n, level in enumerate(LEVELS, start=1)}
_BATCH = 2000


def compute_priority(content_severity: str, affects_us: bool, exploited: bool) -> str:
    level = RANK.get(content_severity, 1)
    if exploited:
        level = max(level, RANK["high"])
    if affects_us:
        level += 1
    return LEVELS[min(level, len(LEVELS)) - 1]


def content_of(row) -> str:
    """The keyword rating for a stored row; items stored before 0.8.0 fall back to their old severity."""
    content = row["content_severity"] or row["severity"] or "low"
    return content if content in ("low", "medium", "high") else "high"


def explain_priority(content_severity: str, content_keyword: str, watch_hits: list[str], kev_cves: list[str]) -> list[str]:
    """Plain reasons, most important first, e.g. ["Exploited: CVE-… on CISA's list", "Affects us: FortiGate"]."""
    reasons = []
    if kev_cves:
        more = f" and {len(kev_cves) - 2} more" if len(kev_cves) > 2 else ""
        reasons.append(f"Exploited: {', '.join(kev_cves[:2])}{more} on CISA's list")
    if watch_hits:
        reasons.append(f"Affects us: {', '.join(watch_hits[:3])}")
    if content_keyword:
        reasons.append(f"Wording: mentions \u201c{content_keyword}\u201d")
    elif content_severity in ("high", "medium"):
        reasons.append(f"Wording rated {content_severity}")
    elif not reasons:
        reasons.append("No warning words found")
    return reasons


async def recompute_priorities(db) -> int:
    """Re-derives every item's priority from its stored signals; returns how many changed."""
    changed, last_rowid = 0, 0
    while True:
        cur = await db.execute(
            """SELECT rowid, id, severity, content_severity, watch_hits, kev_cves FROM items
               WHERE rowid > ? ORDER BY rowid LIMIT ?""",
            (last_rowid, _BATCH),
        )
        rows = await cur.fetchall()
        if not rows:
            break
        updates = []
        for row in rows:
            level = compute_priority(content_of(row), bool(row["watch_hits"]), bool(row["kev_cves"]))
            if level != row["severity"]:
                updates.append((level, row["id"]))
        if updates:
            await db.executemany("UPDATE items SET severity = ? WHERE id = ?", updates)
            changed += len(updates)
        last_rowid = rows[-1]["rowid"]
    return changed
