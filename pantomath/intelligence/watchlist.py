"""
"Our stack": the vendors, products and systems an organisation actually
runs. Every item's title and summary is checked against the list so the
dashboard can say which items affect us.

Matching rules, same spirit as tagging.py and scoring.py:
  - whole words and phrases only ("Edge" does not match "knowledge");
    the spaces in a phrase match any run of whitespace;
  - case-insensitive, except short all-capital terms (up to 4 characters,
    like "APC" or "NAS"), which must match exactly so they don't fire on
    ordinary words;
  - only the title and the RSS summary are checked, never the full article
    page that deep extraction fetches: product names in a page's sidebar or
    "related stories" would otherwise mark unrelated items, and the full
    page isn't stored, so stored items could not be re-checked the same way
    when the list changes.
"""
import re

from pantomath.intelligence.priority import compute_priority, content_of, recompute_priorities

_TAGS = re.compile(r"<[^>]+>")
_BATCH = 1000


def entry_terms(name: str, aliases: str) -> list[str]:
    terms: list[str] = []
    for term in [name, *(aliases or "").split(",")]:
        term = " ".join(term.split())
        if term and term.lower() not in {t.lower() for t in terms}:
            terms.append(term)
    return terms


def _term_pattern(term: str) -> str:
    body = r"\s+".join(re.escape(word) for word in term.split())
    guarded = rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])"
    exact = len(term) <= 4 and term.isupper()
    return guarded if exact else f"(?i:{guarded})"


def compile_watchlist(entries: list[dict]) -> list[tuple[str, re.Pattern]]:
    """[(name, pattern), ...] for entries shaped like {"name": ..., "aliases": ...}."""
    compiled = []
    for entry in entries:
        terms = entry_terms(entry["name"], entry.get("aliases", ""))
        if terms:
            compiled.append((entry["name"], re.compile("|".join(_term_pattern(t) for t in terms))))
    return compiled


def match_watchlist(compiled: list[tuple[str, re.Pattern]], title: str, summary: str) -> list[str]:
    """Names of the entries this item mentions, in list order."""
    if not compiled:
        return []
    text = f"{title or ''}\n{_TAGS.sub(' ', summary or '')}"
    return [name for name, pattern in compiled if pattern.search(text)]


async def load_watchlist(db) -> list[tuple[str, re.Pattern]]:
    cur = await db.execute("SELECT name, aliases FROM watchlist ORDER BY name COLLATE NOCASE")
    return compile_watchlist([dict(r) for r in await cur.fetchall()])


async def rematch_all(db) -> int:
    """
    Re-checks every stored item against the current list (after an entry
    is added, changed or removed) and returns how many items are marked.
    Walks the table in rowid batches so memory stays flat on a large history.
    """
    compiled = await load_watchlist(db)
    if not compiled:
        await db.execute("UPDATE items SET watch_hits = '' WHERE watch_hits != ''")
        await recompute_priorities(db)
        await db.commit()
        return 0
    marked, last_rowid = 0, 0
    while True:
        cur = await db.execute(
            """SELECT rowid, id, title, summary, watch_hits, severity, content_severity, kev_cves
               FROM items WHERE rowid > ? ORDER BY rowid LIMIT ?""",
            (last_rowid, _BATCH),
        )
        rows = await cur.fetchall()
        if not rows:
            break
        updates = []
        for row in rows:
            hits = ",".join(match_watchlist(compiled, row["title"], row["summary"]))
            marked += bool(hits)
            level = compute_priority(content_of(row), bool(hits), bool(row["kev_cves"]))
            if hits != (row["watch_hits"] or "") or level != row["severity"]:
                updates.append((hits, level, row["id"]))
        if updates:
            await db.executemany("UPDATE items SET watch_hits = ?, severity = ? WHERE id = ?", updates)
        last_rowid = rows[-1]["rowid"]
    await db.commit()
    return marked
