import sqlite3

import storage.event_store as event_store


def test_timeline_hides_findings_from_resolved_cases(monkeypatch):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE findings (
            id INTEGER, detector_name TEXT, timestamp REAL, src_ip TEXT, dst_ip TEXT,
            summary TEXT, details TEXT, interface_name TEXT, interface_human_name TEXT,
            incident_id TEXT, pcap_file TEXT, pcap_packet_number INTEGER,
            pcap_offset INTEGER, pcap_length INTEGER
        );
        CREATE TABLE cases (incident_id TEXT PRIMARY KEY, status TEXT);
        INSERT INTO findings VALUES
            (1, 'port_scan', 1, '192.0.2.1', '192.0.2.2', 'open', '{}', 'if-a', 'Wi-Fi', 'open-case', NULL, NULL, NULL, NULL),
            (2, 'port_scan', 2, '192.0.2.3', '192.0.2.4', 'resolved', '{}', 'if-a', 'Wi-Fi', 'resolved-case', NULL, NULL, NULL, NULL);
        INSERT INTO cases VALUES ('open-case', 'open'), ('resolved-case', 'resolved');
        """
    )
    monkeypatch.setattr(event_store, "get_connection", lambda: connection)

    records = event_store.get_timeline_findings()

    assert [record.incident_id for record in records] == ["open-case"]
    assert event_store.get_timeline_findings(incident_id="resolved-case") == []
