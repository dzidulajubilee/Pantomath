"""
Schema definitions for Pantomath's SQLite store.
Kept as plain SQL DDL (no ORM) — the dataset is small and the queries are simple.
"""

TABLE_SCHEMA = """
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

CREATE TABLE IF NOT EXISTS watchlist (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,           -- shown on items as the reason they "affect us"
    aliases TEXT DEFAULT '',      -- comma-separated extra terms, matched like the name
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,         -- CISA Known Exploited Vulnerabilities catalog, see intelligence/kev.py
    vendor TEXT DEFAULT '',
    product TEXT DEFAULT '',
    name TEXT DEFAULT '',
    date_added TEXT DEFAULT '',   -- YYYY-MM-DD
    due_date TEXT DEFAULT '',     -- CISA's remediation deadline (binding on US federal agencies)
    ransomware TEXT DEFAULT '',   -- 'Known' / 'Unknown'
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,              -- shown in Settings; not the secret
    token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 of the cookie / API key; the token itself is never stored
    kind TEXT DEFAULT 'browser',      -- 'browser' or 'api'
    role TEXT DEFAULT 'team',         -- 'team' (team password), 'admin' (Settings password), 'api'
    label TEXT DEFAULT '',            -- "Chrome on Windows", or the API key's name
    remember INTEGER DEFAULT 0,       -- 1 = 90 days since last use; 0 = 12 idle hours
    created_at REAL DEFAULT 0,
    last_seen REAL DEFAULT 0,
    expires_at REAL DEFAULT 0,        -- 0 = never (API keys, until revoked)
    ip TEXT DEFAULT ''
);
"""

# Kept separate from TABLE_SCHEMA above and applied AFTER _run_migrations()
# in sqlite.py's init_db() — deliberately, not just for tidiness. An index
# here can reference a column (e.g. items.severity) that only exists on a
# genuinely old/pre-migration database once _run_migrations() has added it;
# CREATE TABLE IF NOT EXISTS is a no-op against an already-existing table,
# so if this ran BEFORE migrations, indexing a column that migration hasn't
# added yet would fail with "no such column" on any database old enough to
# be missing it. This bit a real restore-of-an-old-backup scenario during
# development (see tests/test_database_restore.py) before being caught.
INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_items_fetched ON items(fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_source ON items(source_id);
CREATE INDEX IF NOT EXISTS idx_items_severity ON items(severity);
"""

# Concatenation of the two above — kept for callers that just want a
# complete, ready-to-use schema in one executescript() call (e.g. tests
# building a standalone fixture .db file from scratch, where there's no
# pre-existing-table-missing-a-column concern since everything is created
# fresh in the right order regardless of statement grouping).
SCHEMA = TABLE_SCHEMA + INDEX_SCHEMA

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
    # 0.6.0 — source health history for the Sources page and dashboard
    ("sources", "last_success", "REAL DEFAULT 0"),
    ("sources", "failing_since", "REAL DEFAULT 0"),
    ("sources", "last_duration_ms", "INTEGER DEFAULT 0"),
    # 0.7.0 — "Our stack" and CISA KEV marks on items, and webhook filters for them
    ("items", "watch_hits", "TEXT DEFAULT ''"),
    ("items", "kev_cves", "TEXT DEFAULT ''"),
    ("webhooks", "only_affects_us", "INTEGER DEFAULT 0"),
    ("webhooks", "only_exploited", "INTEGER DEFAULT 0"),
    # 0.8.0 — items.severity now holds the priority; the keyword rating
    # and the phrase that decided it are kept here (see intelligence/priority.py)
    ("items", "content_severity", "TEXT DEFAULT ''"),
    ("items", "content_keyword", "TEXT DEFAULT ''"),
]
