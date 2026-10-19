"""
Schema for ioc.db, the IOC database's own SQLite file (see db.py for why
it is a separate file). Plain SQL DDL, like database/models.py.

An indicator is stored once per (type, value). Each source that reports
it adds one sighting: that is where per-source confidence, references and
"last reported" live, and what decides when the indicator expires.
"""

IOC_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_feeds (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,         -- http(s); an internal mirror works the same way
    format TEXT DEFAULT 'text',       -- 'text' (one value per line) or 'csv'
    value_column TEXT DEFAULT '',     -- csv: header name or 1-based column number
    date_column TEXT DEFAULT '',      -- csv, optional: first-seen date
    malware_column TEXT DEFAULT '',   -- csv, optional: malware family
    default_type TEXT DEFAULT '',     -- '' = detect each value; otherwise only this type is accepted
    confidence INTEGER DEFAULT 50,    -- 0-100, given to every value from this feed
    threat_type TEXT DEFAULT '',      -- c2, phishing, malware_download...
    lifetime_days INTEGER DEFAULT 0,  -- 0 = each type's default, -1 = never expires
    interval_seconds INTEGER DEFAULT 21600,
    enabled INTEGER DEFAULT 1,
    snapshot INTEGER DEFAULT 0,       -- 1: a value that drops off the list stops counting for this feed
    max_mb INTEGER DEFAULT 30,        -- download size limit
    key_header TEXT DEFAULT '',       -- optional header name, e.g. Auth-Key
    key_value TEXT DEFAULT '',        -- never returned by the API or logged
    etag TEXT DEFAULT '',             -- conditional download: skip an unchanged list
    last_modified TEXT DEFAULT '',
    last_fetched REAL DEFAULT 0,
    last_success REAL DEFAULT 0,
    last_status TEXT DEFAULT 'pending',
    last_duration_ms INTEGER DEFAULT 0,
    last_count INTEGER DEFAULT 0,     -- values in the last download that changed
    last_new INTEGER DEFAULT 0,
    last_dropped INTEGER DEFAULT 0,   -- snapshot feeds: values no longer listed
    last_rejected INTEGER DEFAULT 0,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,               -- see normalize.TYPES
    value TEXT NOT NULL,              -- normalized, see normalize.py
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,          -- last time any source reported it
    expires_at REAL DEFAULT 0,        -- 0 = never
    confidence INTEGER DEFAULT 50,    -- worked out from the sightings, see store.confidence_for
    analyst_confidence INTEGER,       -- set by hand; wins over the sightings when not NULL
    threat_type TEXT DEFAULT '',
    malware TEXT DEFAULT '',
    campaign TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    status TEXT DEFAULT 'active',     -- active | expired | false_positive | allowlisted
    note TEXT DEFAULT '',
    updated_at REAL DEFAULT 0,        -- any change a SIEM should sync (export?since=)
    UNIQUE(type, value)
);

CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY,
    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source TEXT NOT NULL,             -- an ioc_feeds id, or 'manual'
    source_name TEXT DEFAULT '',
    reference TEXT DEFAULT '',        -- a URL or note saying where it was reported
    confidence INTEGER DEFAULT 50,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    active INTEGER DEFAULT 1,         -- 0 once a snapshot feed no longer lists it
    context TEXT DEFAULT '',          -- small JSON: port, first seen according to the feed...
    UNIQUE(indicator_id, source)
);

CREATE TABLE IF NOT EXISTS ioc_settings (
    key TEXT PRIMARY KEY,             -- e.g. keep_expired_days (see store.keep_expired_days)
    value TEXT
);

CREATE TABLE IF NOT EXISTS allowlist (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,               -- 'cidr', 'domain' (and subdomains) or 'exact'
    value TEXT NOT NULL,
    reason TEXT DEFAULT '',
    created_at REAL DEFAULT (strftime('%s','now')),
    UNIQUE(type, value)
);
"""

IOC_INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_indicators_status_expires ON indicators(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_indicators_updated ON indicators(updated_at);
CREATE INDEX IF NOT EXISTS idx_sightings_source ON sightings(source, last_seen);
"""

# Same pattern as database/models.py's MIGRATIONS: (table, column,
# definition) for columns added after ioc.db first shipped.
IOC_MIGRATIONS: list[tuple[str, str, str]] = []
