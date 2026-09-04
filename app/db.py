"""SQLite storage for ReconLens.

Tables track the current attack surface (assets, services, findings), a log of
every scan, and a drift/event timeline of what changed between scans.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("RECONLENS_DB", "data/reconlens.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    profile      TEXT NOT NULL,
    status       TEXT NOT NULL,          -- queued|running|done|error
    started_at   REAL,
    finished_at  REAL,
    log          TEXT DEFAULT '',
    error        TEXT DEFAULT '',
    stats        TEXT DEFAULT '{}'       -- json summary
);

CREATE TABLE IF NOT EXISTS assets (
    hostname     TEXT PRIMARY KEY,
    ip           TEXT,
    source       TEXT,
    first_seen   REAL,
    last_seen    REAL,
    alive        INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    scheme       TEXT,
    url          TEXT,
    status_code  INTEGER,
    title        TEXT,
    webserver    TEXT,
    tech         TEXT,
    tls_host     TEXT,
    tls_expiry   TEXT,
    first_seen   REAL,
    last_seen    REAL,
    open         INTEGER DEFAULT 1,
    UNIQUE(host, port)
);

-- Every open TCP port naabu finds, whether or not it's a web service.
-- Backs the IP Inventory view (host-centric device/service map).
CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,          -- scan target (IP for CIDR sweeps, hostname otherwise)
    ip           TEXT,                   -- resolved IP when known
    hostname     TEXT,                   -- reverse-DNS (PTR) name when available
    port         INTEGER NOT NULL,
    first_seen   REAL,
    last_seen    REAL,
    open         INTEGER DEFAULT 1,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,
    template_id  TEXT NOT NULL,
    name         TEXT,
    severity     TEXT,
    matched_at   TEXT,
    first_seen   REAL,
    last_seen    REAL,
    status       TEXT DEFAULT 'open',    -- open|resolved
    UNIQUE(host, template_id, matched_at)
);

-- Inbound honeypot hits: who connected to a decoy port, when.
-- This is the "Threat Radar" (inbound) half, vs the scan tables (outbound).
CREATE TABLE IF NOT EXISTS inbound_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL,
    src_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    hostname     TEXT,                   -- reverse-DNS of src_ip (NULL = not yet tried)
    banner       TEXT,                   -- first bytes the client sent, if any
    country      TEXT,                   -- GeoIP country name (offline DB)
    country_code TEXT,                   -- ISO alpha-2
    org          TEXT                    -- GeoIP AS org
);
CREATE INDEX IF NOT EXISTS idx_inbound_ts ON inbound_events(ts);
CREATE INDEX IF NOT EXISTS idx_inbound_src ON inbound_events(src_ip);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL,
    kind         TEXT,                   -- new_asset|new_host|new_port|new_service|closed_service|new_finding|resolved_finding
    severity     TEXT,                   -- info|low|medium|high|critical (for sorting/coloring)
    subject      TEXT,
    detail       TEXT,
    scan_id      INTEGER
);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn) -> None:
    """Additive migrations for DBs created by older versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(ports)")}
    if "hostname" not in cols:
        conn.execute("ALTER TABLE ports ADD COLUMN hostname TEXT")
    icols = {r["name"] for r in conn.execute("PRAGMA table_info(inbound_events)")}
    for col in ("country", "country_code", "org"):
        if col not in icols:
            conn.execute(f"ALTER TABLE inbound_events ADD COLUMN {col} TEXT")


def now() -> float:
    return time.time()
