"""Tests for case workflow persistence."""

import sqlite3

import storage.case_store as case_store


def case_database():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE findings (
            incident_id TEXT, detector_name TEXT, timestamp REAL, src_ip TEXT
        );
        CREATE TABLE cases (
            incident_id TEXT PRIMARY KEY, title TEXT, status TEXT, assignee TEXT,
            notes TEXT, created_at REAL, updated_at REAL
        );
        """
    )
    connection.executemany(
        "INSERT INTO findings VALUES (?, ?, ?, ?)",
        [("case-1", "arp_spoof", 10.0, "192.0.2.1"), ("case-1", "port_scan", 20.0, "192.0.2.1")],
    )
    return connection


def test_case_update_is_persisted(monkeypatch):
    connection = case_database()
    monkeypatch.setattr(case_store, "get_connection", lambda: connection)

    updated = case_store.update_case(
        "case-1",
        {"status": "investigating", "assignee": "alice", "notes": "Review gateway"},
    )
    cases = case_store.list_cases()

    assert updated["status"] == "investigating"
    assert cases[0]["finding_count"] == 2
    assert cases[0]["assignee"] == "alice"


def test_resolved_cases_are_hidden_from_case_management(monkeypatch):
    connection = case_database()
    monkeypatch.setattr(case_store, "get_connection", lambda: connection)
    case_store.update_case("case-1", {"status": "resolved"})
    assert case_store.list_cases() == []
