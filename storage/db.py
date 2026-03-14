"""
storage/db.py

Owns the SQLite connection and schema for the findings database.
Nothing in here knows about Finding objects or query logic — that's
storage/models.py (typed rows) and storage/event_store.py (queries)
respectively. This file's only job is: where's the DB file, what does
the table look like, how do you get a connection to it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "events.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detector_name TEXT NOT NULL,
    timestamp REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,  -- JSON blob
    interface_name TEXT NOT NULL,
    interface_human_name TEXT NOT NULL,
    incident_id TEXT,        -- NULL until grouped by correlation/grouper.py
    pcap_file TEXT,
    pcap_packet_number INTEGER,
    pcap_offset INTEGER,
    pcap_length INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector_name);
CREATE INDEX IF NOT EXISTS idx_findings_incident ON findings(incident_id);
CREATE INDEX IF NOT EXISTS idx_findings_interface ON findings(interface_name);

CREATE TABLE IF NOT EXISTS cases (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    assignee TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""


def get_connection() -> sqlite3.Connection:
    """
    Opens a connection to the findings DB, creating the data directory
    if needed. row_factory is set to sqlite3.Row so callers can access
    columns by name (row["src_ip"]) instead of by position.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Creates the findings table and indexes if they don't already exist. Safe to call every startup."""
    with get_connection() as conn:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        if columns and "interface_name" not in columns:
            # Development-only schema reset: interface attribution is required
            # and existing databases were explicitly declared disposable.
            conn.executescript(
                """
                DROP TABLE IF EXISTS findings;
                DROP TABLE IF EXISTS cases;
                DROP TABLE IF EXISTS audit_log;
                """
            )
        conn.executescript(_SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "pcap_packet_number" not in columns:
            conn.execute("ALTER TABLE findings ADD COLUMN pcap_packet_number INTEGER")
