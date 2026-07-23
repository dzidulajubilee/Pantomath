"""
Schema definitions for Pantomath's SQLite store.
Kept as plain SQL DDL (no ORM) — the dataset is small and the queries are simple.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    category TEXT DEFAULT 'general',
    color TEXT DEFAULT '#5eead4',
    icon_url TEXT,
    connector_type TEXT DEFAULT 'rss',
    interval_seconds INTEGER DEFAULT 300,
    enabled INTEGER DEFAULT 1,
    last_fetched REAL DEFAULT 0,
    last_status TEXT DEFAULT 'pending',
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    title TEXT NOT NULL,
    link TEXT,
    summary TEXT,
    published REAL,
    fetched_at REAL,
    guid TEXT,
    severity TEXT DEFAULT 'low',
    vendors TEXT DEFAULT '',
    actors TEXT DEFAULT '',
    cves TEXT DEFAULT '',
    ips TEXT DEFAULT '',
    hashes TEXT DEFAULT '',
    emails TEXT DEFAULT '',
    bookmarked INTEGER DEFAULT 0,
    read INTEGER DEFAULT 0,
    UNIQUE(source_id, guid),
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_items_fetched ON items(fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_source ON items(source_id);
CREATE INDEX IF NOT EXISTS idx_items_severity ON items(severity);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    keyword TEXT DEFAULT '',       -- comma-separated, OR-matched against title+summary; empty = any
    source_id TEXT DEFAULT '',     -- specific source to restrict to; empty = any source
    min_severity TEXT DEFAULT '',  -- 'low'/'medium'/'high'; empty = any severity
    created_at REAL DEFAULT (strftime('%s','now')),
    last_triggered REAL DEFAULT 0,
    last_status TEXT DEFAULT 'pending',
    protected INTEGER DEFAULT 0,     -- opt-in per-webhook: 1 if a key gates viewing the real URL / editing
    key_salt TEXT,                   -- hex-encoded random salt, NULL unless protected
    key_hash TEXT,                   -- salted PBKDF2 hash of the key — the plaintext key is never stored
    key_fail_count INTEGER DEFAULT 0,
    key_locked_until REAL DEFAULT 0, -- unix timestamp; failed-attempt lockout for the key, see pantomath/alerts/webhook_keys.py
    allow_insecure_tls INTEGER DEFAULT 0  -- opt-in per-webhook: 1 skips TLS certificate verification (self-signed certs, internal CAs)
);
"""

# Columns added after the original CREATE TABLE statements above.
# `CREATE TABLE IF NOT EXISTS` is a no-op against an already-existing
# table, so a column added here needs an explicit ALTER TABLE against any
# database that predates it — that's what this list drives (see
# pantomath/database/sqlite.py: _run_migrations). Each entry is
# (table, column, column_definition); adding a new column later should
# come with a new entry here, not just a change to SCHEMA above.
MIGRATIONS: list[tuple[str, str, str]] = [
    ("sources", "icon_url", "TEXT"),
    ("sources", "connector_type", "TEXT DEFAULT 'rss'"),
    ("items", "severity", "TEXT DEFAULT 'low'"),
    ("items", "vendors", "TEXT DEFAULT ''"),
    ("items", "actors", "TEXT DEFAULT ''"),
    ("items", "bookmarked", "INTEGER DEFAULT 0"),
    ("items", "cves", "TEXT DEFAULT ''"),
    ("items", "ips", "TEXT DEFAULT ''"),
    ("items", "hashes", "TEXT DEFAULT ''"),
    ("items", "emails", "TEXT DEFAULT ''"),
    ("webhooks", "protected", "INTEGER DEFAULT 0"),
    ("webhooks", "key_salt", "TEXT"),
    ("webhooks", "key_hash", "TEXT"),
    ("webhooks", "key_fail_count", "INTEGER DEFAULT 0"),
    ("webhooks", "key_locked_until", "REAL DEFAULT 0"),
    ("webhooks", "allow_insecure_tls", "INTEGER DEFAULT 0"),
]
