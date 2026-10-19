"""
Built-in readers for well-known IOC feeds, the way Yeti pulls them: one
small function per feed that turns what the publisher sends into values
with their context (malware family, threat type, the publisher's own
confidence, a link back to its page).

A reader is picked as an IOC feed's `format`. Everything else about the
feed is the same as for a plain list: the URL can point at an internal
mirror, the key header is optional where the publisher allows it, and the
download, limits and storage are feeds.py's and store.py's.

The formats are the publishers' public exports as of October 2026:

  ThreatFox      JSON, IOCs added in the last 48 hours (ip:port, domain, url, hashes)
  URLhaus        CSV, malware download URLs from the last 30 days
  MalwareBazaar  CSV, recent samples: SHA-256, MD5 and SHA-1, each its own indicator
  Feodo Tracker  JSON, the current botnet C2 blocklist
  SSLBL          CSV, SHA-1 fingerprints of certificates used by malware C2
  AbuseIPDB      JSON blacklist (needs its free API key)

Check each publisher's terms before relying on its data, especially for
commercial use (the terms URL is part of each reader below).
"""
import csv
import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field

from pantomath.ioc.normalize import IocValueError, normalize_typed
from pantomath.ioc.parsing import IocFeedError, ParseResult, reject
from pantomath.ioc.store import Arrival


@dataclass(frozen=True)
class Reader:
    name: str
    label: str
    url: str
    gives: str                  # what the feed holds, for the form
    parse: Callable = field(repr=False, compare=False)
    key_header: str = ""
    key_required: bool = False
    key_note: str = ""
    terms_url: str = ""
    interval: int = 3600        # default download interval, seconds
    min_interval: int = 900
    snapshot: bool = False
    confidence: int = 75        # when the feed gives no confidence of its own
    per_value_confidence: bool = False
    threat_type: str = ""
    accept: str = ""

    def describe(self) -> dict:
        return {k: getattr(self, k) for k in (
            "name", "label", "url", "gives", "key_header", "key_required", "key_note", "terms_url",
            "interval", "min_interval", "snapshot", "confidence", "per_value_confidence", "threat_type")}


def _text(value) -> str:
    value = "" if value is None else str(value).strip()
    return "" if value.lower() in ("none", "null", "n/a", "unknown") else value


def _add(result, raw, type_hint=None, *, malware="", confidence=None, threat_type="", reference="",
         tags="", context=None) -> None:
    """One value into a ParseResult (feeds.py), with whatever the publisher said about it."""
    try:
        type_, value, extra = normalize_typed(type_hint, str(raw or ""))
    except IocValueError as e:
        reject(result, str(raw or ""), str(e))
        return
    if context:
        extra.update({k: v for k, v in context.items() if v not in (None, "")})
    try:
        confidence = None if confidence in (None, "") else max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = None
    result.arrivals.append(Arrival(type_, value, extra, _text(malware)[:100], confidence,
                                   _text(threat_type)[:40], _text(reference)[:500], _text(tags)[:300]))
    result.by_type[type_] += 1


def _json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        raise IocFeedError("the response is not JSON (is the URL right?)") from None


def _csv_rows(text: str, result):
    """Rows of a CSV whose comment lines start with '#', as abuse.ch publishes them."""
    data = []
    for line in text.splitlines():
        result.lines += 1
        if not line.strip() or line.lstrip().startswith("#"):
            result.skipped += 1
            continue
        data.append(line)
    return csv.reader(io.StringIO("\n".join(data)), skipinitialspace=True)


# ------------------------------------------------------------------- readers

_THREATFOX_TYPES = {"ip:port": None, "domain": "domain", "url": "url",
                    "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}


def parse_threatfox(text: str):
    document = _json(text)
    if isinstance(document, dict) and document.get("query_status") not in (None, "ok"):
        raise IocFeedError(f"ThreatFox answered '{document.get('query_status')}'")
    if isinstance(document, dict) and isinstance(document.get("data"), list):   # the API's shape
        entries = [(e.get("id"), e) for e in document["data"]]
    elif isinstance(document, dict):                                              # the export's shape
        entries = [(ioc_id, e) for ioc_id, rows in document.items() for e in (rows if isinstance(rows, list) else [])]
    else:
        raise IocFeedError("this isn't ThreatFox's JSON export")
    result = ParseResult()
    for ioc_id, e in entries:
        result.lines += 1
        if not isinstance(e, dict):
            continue
        kind = e.get("ioc_type", "")
        if kind not in _THREATFOX_TYPES:
            reject(result, str(e.get("ioc_value") or e.get("ioc")), f"type '{kind}' isn't stored")
            continue
        _add(result, e.get("ioc_value") or e.get("ioc"), _THREATFOX_TYPES[kind],
             malware=e.get("malware_printable") or e.get("malware"), confidence=e.get("confidence_level"),
             threat_type=e.get("threat_type"), tags=e.get("tags") if isinstance(e.get("tags"), str) else ",".join(e.get("tags") or []),
             reference=f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else e.get("reference"),
             context={"reported": _text(e.get("first_seen_utc") or e.get("first_seen"))})
    return result


def parse_urlhaus(text: str):
    result = ParseResult()
    for row in _csv_rows(text, result):
        # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 8:
            reject(result, ",".join(row)[:60], "not a URLhaus row")
            continue
        _add(result, row[2], "url", threat_type=row[5] or "malware_download", tags=row[6], reference=row[7],
             context={"reported": row[1], "url_status": row[3]})
    return result


def parse_malwarebazaar(text: str):
    result = ParseResult()
    for row in _csv_rows(text, result):
        # first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, ...
        if len(row) < 9:
            reject(result, ",".join(row)[:60], "not a MalwareBazaar row")
            continue
        sha256, md5, sha1 = row[1].lower(), row[2].lower(), row[3].lower()
        # One sample, three indicators: a SIEM holding only the MD5 still matches,
        # and each one's context names the other two.
        same_file = {"sha256": sha256, "md5": md5, "sha1": sha1}
        for value, type_ in ((sha256, "sha256"), (md5, "md5"), (sha1, "sha1")):
            _add(result, value, type_, malware=row[8], threat_type="payload",
                 reference=f"https://bazaar.abuse.ch/sample/{sha256}/",
                 context={"reported": row[0], "file_type": _text(row[6]),
                          "same_file": {k: v for k, v in same_file.items() if k != type_}})
    return result


def parse_feodo(text: str):
    document = _json(text)
    if not isinstance(document, list):
        raise IocFeedError("this isn't Feodo Tracker's JSON blocklist")
    result = ParseResult()
    for e in document:
        result.lines += 1
        if not isinstance(e, dict):
            continue
        ip = _text(e.get("ip_address"))
        _add(result, ip, None, malware=e.get("malware"), threat_type="c2",
             reference=f"https://feodotracker.abuse.ch/browse/host/{ip}/" if ip else "",
             context={"port": e.get("port"), "status": _text(e.get("status")), "reported": _text(e.get("first_seen")),
                      "last_online": _text(e.get("last_online")), "as_name": _text(e.get("as_name")), "country": _text(e.get("country"))})
    return result


def parse_sslbl(text: str):
    result = ParseResult()
    for row in _csv_rows(text, result):
        # Listingdate, SHA1, Listingreason ("QakBot C&C")
        if len(row) < 3:
            reject(result, ",".join(row)[:60], "not an SSLBL row")
            continue
        reason = row[2].strip()
        family = reason[:-4].strip() if reason.endswith(" C&C") else reason
        _add(result, row[1], "x509", malware="" if family.lower() == "malware" else family, threat_type="c2",
             reference=f"https://sslbl.abuse.ch/ssl-certificates/sha1/{row[1].strip().lower()}/",
             context={"reported": row[0], "reason": reason})
    return result


def parse_abuseipdb(text: str):
    document = _json(text)
    if isinstance(document, dict) and document.get("errors"):
        detail = (document["errors"][0] or {}).get("detail", "an error")
        raise IocFeedError(f"AbuseIPDB answered: {detail}")
    rows = document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise IocFeedError("this isn't AbuseIPDB's blacklist")
    result = ParseResult()
    for e in rows:
        result.lines += 1
        if not isinstance(e, dict):
            continue
        ip = _text(e.get("ipAddress"))
        _add(result, ip, None, confidence=e.get("abuseConfidenceScore"), threat_type="abuse",
             reference=f"https://www.abuseipdb.com/check/{ip}" if ip else "",
             context={"country": _text(e.get("countryCode")), "reported": _text(e.get("lastReportedAt"))})
    return result


READERS: dict[str, Reader] = {r.name: r for r in (
    Reader("threatfox", "ThreatFox (abuse.ch)", "https://threatfox.abuse.ch/export/json/recent/",
           "IPs with ports, domains, URLs and hashes added in the last 48 hours, with malware family, threat type and ThreatFox's confidence",
           parse_threatfox, key_header="Auth-Key",
           key_note="abuse.ch's free Auth-Key. The export works without one today; add it if abuse.ch asks for it.",
           terms_url="https://threatfox.abuse.ch/faq/#tos", interval=3600, per_value_confidence=True),
    Reader("urlhaus", "URLhaus (abuse.ch)", "https://urlhaus.abuse.ch/downloads/csv_recent/",
           "Malware download URLs from the last 30 days, with tags and whether each is still online",
           parse_urlhaus, key_header="Auth-Key", key_note="abuse.ch's free Auth-Key, if abuse.ch asks for it.",
           terms_url="https://urlhaus.abuse.ch/api/", interval=3600, threat_type="malware_download"),
    Reader("malwarebazaar", "MalwareBazaar (abuse.ch)", "https://bazaar.abuse.ch/export/csv/recent/",
           "SHA-256, MD5 and SHA-1 of recently submitted malware samples, with the malware family",
           parse_malwarebazaar, key_header="Auth-Key", key_note="abuse.ch's free Auth-Key, if abuse.ch asks for it.",
           terms_url="https://bazaar.abuse.ch/faq/#tos", interval=1800, threat_type="payload"),
    Reader("feodo", "Feodo Tracker (abuse.ch)", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
           "The current botnet C2 blocklist (Emotet, QakBot, Dridex...), with ports and malware family",
           parse_feodo, key_header="Auth-Key", key_note="Not needed for the blocklist today.",
           terms_url="https://feodotracker.abuse.ch/blocklist/", interval=1800, snapshot=True, threat_type="c2"),
    Reader("sslbl", "SSLBL (abuse.ch)", "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
           "SHA-1 fingerprints of TLS certificates used by malware C2 servers, with the malware family",
           parse_sslbl, key_header="Auth-Key", key_note="Not needed for the blacklist today.",
           terms_url="https://sslbl.abuse.ch/blacklist/", interval=21600, snapshot=True, threat_type="c2"),
    Reader("abuseipdb", "AbuseIPDB blacklist", "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000",
           "IPs reported for abuse (scanning, brute force, spam) with AbuseIPDB's abuse confidence score",
           parse_abuseipdb, key_header="Key", key_required=True,
           key_note="A free AbuseIPDB API key (APIv2). The free plan allows 5 blacklist downloads a day, so this feed is fetched at most every 5 hours.",
           terms_url="https://www.abuseipdb.com/legal", interval=21600, min_interval=18000, snapshot=True,
           per_value_confidence=True, threat_type="abuse", accept="application/json"),
)}
