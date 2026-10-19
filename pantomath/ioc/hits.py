"""
SIEM hit counts: which indicators your network actually touched.

Every /api/v1 lookup that matches counts a hit for that indicator. Lookups
must never write to ioc.db (a SIEM can send thousands a minute), so hits
are added up in memory and written once a minute by the IOC scheduler, per
indicator and day. Exports don't count: they are whole lists, not events.
Up to half a minute of counts is lost if the service stops abruptly.
"""
import time


def day_of(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class HitCounter:
    def __init__(self):
        self._hits: dict[tuple[str, int], list] = {}      # (day, indicator id) -> [count, last hit]
        self._lookups: dict[str, list] = {}               # day -> [values looked up, matches]

    def record(self, matched_ids: list[int], values: int, now: float | None = None) -> None:
        now = now or time.time()
        day = day_of(now)
        totals = self._lookups.setdefault(day, [0, 0])
        totals[0] += values
        totals[1] += len(matched_ids)
        for indicator_id in matched_ids:
            entry = self._hits.setdefault((day, indicator_id), [0, 0.0])
            entry[0] += 1
            entry[1] = now

    def pending(self, day: str) -> tuple[int, int, dict[int, list]]:
        """What hasn't been written yet for one day: (lookups, matches, {indicator id: [count, last hit]})."""
        lookups, matches = self._lookups.get(day, [0, 0])
        return lookups, matches, {i: v for (d, i), v in self._hits.items() if d == day}

    def pending_since(self, day: str) -> set[int]:
        """Indicators with hits not written yet, on `day` or later."""
        return {i for (d, i) in self._hits if d >= day}

    def pending_for(self, indicator_id: int) -> list:
        """[count, last hit] not written yet for one indicator, over every day."""
        count, last = 0, 0.0
        for (_, i), (n, ts) in self._hits.items():
            if i == indicator_id:
                count, last = count + n, max(last, ts)
        return [count, last]

    async def flush(self, db) -> int:
        """Writes the counts and starts again. Returns how many indicator-days were written."""
        hits, lookups = self._hits, self._lookups
        if not hits and not lookups:
            return 0
        self._hits, self._lookups = {}, {}
        await db.executemany(
            """INSERT INTO indicator_hits (indicator_id, day, count, last_hit)
               SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM indicators WHERE id = ?)
               ON CONFLICT(indicator_id, day) DO UPDATE SET
                   count = indicator_hits.count + excluded.count, last_hit = MAX(indicator_hits.last_hit, excluded.last_hit)""",
            [(i, day, n, ts, i) for (day, i), (n, ts) in hits.items()],
        )
        await db.executemany(
            """INSERT INTO lookup_stats (day, lookups, matches) VALUES (?, ?, ?)
               ON CONFLICT(day) DO UPDATE SET lookups = lookup_stats.lookups + excluded.lookups,
                                              matches = lookup_stats.matches + excluded.matches""",
            [(day, n, m) for day, (n, m) in lookups.items()],
        )
        await db.commit()
        return len(hits)


hit_counter = HitCounter()
