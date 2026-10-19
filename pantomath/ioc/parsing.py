"""
Reading a downloaded list into values: plain text (one per line) and CSV,
for IOC feeds and for lists added by hand. The built-in readers for
well-known feeds (readers.py) produce the same ParseResult.
"""
import csv
import io
from collections import Counter
from dataclasses import dataclass, field

from pantomath.ioc.normalize import TYPES, IocValueError, NotPublicError, normalize_typed
from pantomath.ioc.store import Arrival

_EMPTY_CELLS = {"", "n/a", "na", "none", "null", "unknown", "-"}
_COMMENT_PREFIXES = ("#", ";", "//")


class IocFeedError(Exception):
    """A list couldn't be downloaded or read. str() is shown in Settings, IOC feeds."""


@dataclass
class ParseResult:
    arrivals: list = field(default_factory=list)
    lines: int = 0
    skipped: int = 0              # blank and comment lines, and a CSV header
    rejected: int = 0
    rejected_samples: list = field(default_factory=list)   # [(value, reason)], the first few
    by_type: Counter = field(default_factory=Counter)
    columns: list = field(default_factory=list)            # CSV: what the test shows to pick from
    preview_rows: list = field(default_factory=list)
    value_column: str = ""                                 # CSV: the column that was used

    def summary(self) -> dict:
        return {
            "lines": self.lines, "valid": len(self.arrivals), "skipped": self.skipped, "rejected": self.rejected,
            "rejected_samples": [{"value": v[:120], "reason": r} for v, r in self.rejected_samples],
            "by_type": dict(self.by_type.most_common()), "sample": [a.value for a in self.arrivals[:8]],
            "columns": self.columns, "preview_rows": self.preview_rows, "value_column": self.value_column,
        }


def decode(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]
    if text.lstrip()[:15].lower().startswith(("<!doctype html", "<html")):
        raise IocFeedError("the URL returned a web page, not a list")
    return text


def reject(result: ParseResult, value: str, reason: str) -> None:
    result.rejected += 1
    if len(result.rejected_samples) < 5:
        result.rejected_samples.append((value, reason))


def _accept(result: ParseResult, default_type: str, raw: str, malware: str = "", reported: str = "") -> None:
    try:
        type_, value, context = normalize_typed(default_type or None, raw)
    except IocValueError as e:
        reject(result, raw, str(e))
        return
    if reported:
        context["reported"] = reported[:40]
    malware = (malware or "").strip()
    result.arrivals.append(Arrival(type_, value, context, "" if malware.lower() in _EMPTY_CELLS else malware[:100]))
    result.by_type[type_] += 1


def parse_list(text: str, fmt: str = "text", default_type: str = "", value_column: str = "",
               date_column: str = "", malware_column: str = "") -> ParseResult:
    if default_type and default_type not in TYPES:
        raise IocFeedError(f"unknown indicator type '{default_type}'")
    if fmt == "csv":
        return _parse_csv(text, default_type, value_column, date_column, malware_column)
    if fmt != "text":
        raise IocFeedError(f"unknown format '{fmt}'")
    result = ParseResult()
    for line in text.splitlines():
        result.lines += 1
        line = line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            result.skipped += 1
            continue
        # "203.0.113.10  # added 2026-10-01": the value is the first word
        _accept(result, default_type, line.split()[0].rstrip(",;"))
    return result


def _find_column(name: str, header: list[str] | None) -> int | None:
    if not name:
        return None
    if name.strip().isdigit():
        return int(name.strip()) - 1
    wanted = name.strip().lower()
    for i, h in enumerate(header or []):
        if h.strip().strip('"').lower() == wanted:
            return i
    return None


def _parse_csv(text, default_type, value_column, date_column, malware_column) -> ParseResult:
    result = ParseResult()
    data_lines, comment_header = [], None
    for line in text.splitlines():
        result.lines += 1
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            result.skipped += 1
            # abuse.ch puts the header in the last comment line: # "first_seen_utc","sha256_hash",...
            if stripped.startswith("#") and "," in stripped and not data_lines:
                comment_header = next(csv.reader([stripped.lstrip("#").strip()], skipinitialspace=True), None)
            continue
        data_lines.append(line)
    rows = list(csv.reader(io.StringIO("\n".join(data_lines)), skipinitialspace=True))
    if not rows:
        return result

    def looks_like_header(row):
        return not any(_detectable(cell, default_type) for cell in row)
    header = rows[0] if looks_like_header(rows[0]) else None
    if header is not None:
        rows = rows[1:]
        result.skipped += 1
    names = header or comment_header
    width = max(len(r) for r in rows[:50]) if rows else len(names or [])
    result.columns = [(names[i].strip() if names and i < len(names) and names[i].strip() else f"Column {i + 1}") for i in range(width)]
    result.preview_rows = [r[:12] for r in rows[:5]]

    index = _find_column(value_column, names)
    if value_column and index is None:
        raise IocFeedError(f"there is no column '{value_column}'. Columns: {', '.join(result.columns) or 'none'}")
    if index is None:
        # No column chosen yet (the first test): pick the one holding the most indicators.
        scores = Counter()
        for row in rows[:50]:
            for i, cell in enumerate(row):
                if _detectable(cell, default_type):
                    scores[i] += 1
        if not scores:
            raise IocFeedError("no column holds values that look like indicators")
        index = scores.most_common(1)[0][0]
    result.value_column = result.columns[index] if index < len(result.columns) else str(index + 1)
    date_index = _find_column(date_column, names)
    malware_index = _find_column(malware_column, names)

    def cell(row, i):
        return row[i].strip() if i is not None and 0 <= i < len(row) else ""
    for row in rows:
        raw = cell(row, index)
        if not raw:
            reject(result, ",".join(row)[:60], "the value column is empty")
            continue
        _accept(result, default_type, raw, cell(row, malware_index), cell(row, date_index))
    return result


def _detectable(cell: str, default_type: str) -> bool:
    try:
        normalize_typed(default_type or None, cell)
        return True
    except NotPublicError:
        return True   # a private address is still an IP column, just not a usable value
    except IocValueError:
        return False
