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
    bookmarked INTEGER DEFAULT 0,
    read INTEGER DEFAULT 0,
    UNIQUE(source_id, guid),
    FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_items_fetched ON items(fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_source ON items(source_id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""
