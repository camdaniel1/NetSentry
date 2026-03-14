"""Tests for case workflow persistence and role enforcement."""

import sqlite3

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import storage.case_store as case_store
from api.main import _require


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
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, timestamp REAL, actor TEXT, role TEXT,
            action TEXT, target TEXT, details TEXT
        );
        """
    )
    connection.executemany(
        "INSERT INTO findings VALUES (?, ?, ?, ?)",
        [("case-1", "arp_spoof", 10.0, "192.0.2.1"), ("case-1", "port_scan", 20.0, "192.0.2.1")],
    )
    return connection


def test_case_update_is_persisted_and_audited(monkeypatch):
    connection = case_database()
    monkeypatch.setattr(case_store, "get_connection", lambda: connection)

    updated = case_store.update_case(
        "case-1",
        {"status": "investigating", "assignee": "alice", "notes": "Review gateway"},
        actor="alice",
        role="analyst",
    )
    cases = case_store.list_cases()
    audit = case_store.list_audit_log()

    assert updated["status"] == "investigating"
    assert cases[0]["finding_count"] == 2
    assert cases[0]["assignee"] == "alice"
    assert audit[0]["action"] == "case.updated"
    assert audit[0]["details"]["notes"] == "Review gateway"


def test_resolved_cases_are_hidden_from_case_management(monkeypatch):
    connection = case_database()
    monkeypatch.setattr(case_store, "get_connection", lambda: connection)
    case_store.update_case("case-1", {"status": "resolved"}, actor="alice", role="analyst")
    assert case_store.list_cases() == []


def test_viewer_cannot_update_cases():
    request = Request({"type": "http", "headers": [(b"x-netsentry-role", b"viewer")]})

    with pytest.raises(HTTPException) as error:
        _require(request, "cases:update")

    assert error.value.status_code == 403


def test_analyst_can_update_cases():
    request = Request({
        "type": "http",
        "headers": [(b"x-netsentry-role", b"analyst"), (b"x-netsentry-actor", b"alice")],
    })

    assert _require(request, "cases:update") == ("alice", "analyst")
