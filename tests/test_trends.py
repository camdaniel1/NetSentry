"""Tests for dashboard trend aggregation."""

import sqlite3

import storage.event_store as event_store


def test_get_trend_summary_aggregates_activity_and_offenders(monkeypatch):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE findings (
            detector_name TEXT NOT NULL, timestamp REAL NOT NULL,
            src_ip TEXT, dst_ip TEXT
        )"""
    )
    now = 1_000_000.0
    connection.executemany(
        "INSERT INTO findings VALUES (?, ?, ?, ?)",
        [
            ("arp_spoof", now - 100, "192.0.2.10", None),
            ("arp_spoof", now - 200, "192.0.2.10", None),
            ("port_scan", now - 4_000, "192.0.2.20", None),
            ("old", now - 30_000, "192.0.2.30", None),
        ],
    )
    monkeypatch.setattr(event_store, "get_connection", lambda: connection)
    monkeypatch.setattr(event_store.time, "time", lambda: now)

    trends = event_store.get_trend_summary(hours=6, top_limit=2)

    assert trends["summary"] == {"total": 3, "detectors": 2, "offenders": 2, "last_hour": 2}
    assert sum(point["count"] for point in trends["activity"]) == 3
    assert trends["detectors"] == [
        {"detector_name": "arp_spoof", "count": 2},
        {"detector_name": "port_scan", "count": 1},
    ]
    assert trends["top_offenders"][0]["src_ip"] == "192.0.2.10"
    assert trends["top_offenders"][0]["count"] == 2

