"""
storage/event_store.py

Query layer for Findings. Connection management and schema live in
storage/db.py; typed row objects live in storage/models.py — this file
is just the SQL that answers specific questions ("recent findings",
"findings for this host", etc.) using those two.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.base import Finding
from storage.db import get_connection, init_db
from storage.models import FindingRecord

__all__ = ["init_db", "save_finding", "get_recent_findings", "get_findings_by_detector",
           "count_findings_by_detector", "get_findings_by_src_ip", "get_distinct_source_ips",
           "get_ungrouped_findings", "assign_incident_id", "get_findings_by_incident",
           "get_trend_summary", "get_timeline_findings", "get_finding_by_id",
           "find_related_incident"]


def save_finding(
    finding: Finding,
    interface_name: str,
    interface_human_name: str,
    pcap_file: str = None,
    pcap_packet_number: int = None,
    pcap_offset: int = None,
    pcap_length: int = None,
) -> int:
    """Writes one Finding to the DB, returns its new row id. Evidence fields are optional."""
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO findings
                (detector_name, timestamp, src_ip, dst_ip, summary, details,
                 interface_name, interface_human_name, pcap_file, pcap_packet_number,
                 pcap_offset, pcap_length)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.detector_name,
                finding.timestamp,
                finding.src_ip,
                finding.dst_ip,
                finding.summary,
                json.dumps(finding.details),
                interface_name,
                interface_human_name,
                pcap_file,
                pcap_packet_number,
                pcap_offset,
                pcap_length,
            ),
        )
        return cur.lastrowid


def get_recent_findings(limit: int = 50, interface_name: str | None = None) -> List[FindingRecord]:
    """Most recent findings first — what a dashboard's live feed would call."""
    with get_connection() as conn:
        if interface_name:
            rows = conn.execute(
                "SELECT * FROM findings WHERE interface_name = ? ORDER BY timestamp DESC LIMIT ?",
                (interface_name, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [FindingRecord.from_row(r) for r in rows]


def get_findings_by_detector(detector_name: str, limit: int = 50) -> List[FindingRecord]:
    """Findings from one detector type — for a per-detector analytics view."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE detector_name = ? ORDER BY timestamp DESC LIMIT ?",
            (detector_name, limit),
        ).fetchall()
        return [FindingRecord.from_row(r) for r in rows]


def count_findings_by_detector(interface_name: str | None = None) -> dict:
    """{'arp_spoof': 12, 'port_scan': 4, ...} — for a summary/analytics view."""
    with get_connection() as conn:
        if interface_name:
            rows = conn.execute(
                """SELECT detector_name, COUNT(*) as count FROM findings
                   WHERE interface_name = ? GROUP BY detector_name""",
                (interface_name,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT detector_name, COUNT(*) as count FROM findings GROUP BY detector_name"
            ).fetchall()
        return {row["detector_name"]: row["count"] for row in rows}


def get_trend_summary(hours: int = 24, top_limit: int = 8) -> dict:
    """Aggregate recent finding activity for dashboard charts."""
    hours = max(1, min(int(hours), 168))
    top_limit = max(1, min(int(top_limit), 25))
    now = time.time()
    cutoff = now - (hours * 3600)
    bucket_seconds = 3600

    with get_connection() as conn:
        summary = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT detector_name) AS detectors,
                   COUNT(DISTINCT CASE WHEN src_ip IS NOT NULL AND src_ip != '' THEN src_ip END) AS offenders,
                   SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS last_hour
            FROM findings WHERE timestamp >= ?
            """,
            (now - 3600, cutoff),
        ).fetchone()
        detector_rows = conn.execute(
            """SELECT detector_name, COUNT(*) AS count
               FROM findings WHERE timestamp >= ?
               GROUP BY detector_name ORDER BY count DESC""",
            (cutoff,),
        ).fetchall()
        offender_rows = conn.execute(
            """SELECT src_ip, COUNT(*) AS count, COUNT(DISTINCT detector_name) AS detectors,
                      MAX(timestamp) AS last_seen
               FROM findings
               WHERE timestamp >= ? AND src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip ORDER BY count DESC, last_seen DESC LIMIT ?""",
            (cutoff, top_limit),
        ).fetchall()
        activity_rows = conn.execute(
            """SELECT CAST((timestamp - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS count
               FROM findings WHERE timestamp >= ?
               GROUP BY bucket""",
            (cutoff, bucket_seconds, cutoff),
        ).fetchall()

    activity_counts = {int(row["bucket"]): row["count"] for row in activity_rows}
    return {
        "hours": hours,
        "summary": {
            "total": summary["total"] or 0,
            "detectors": summary["detectors"] or 0,
            "offenders": summary["offenders"] or 0,
            "last_hour": summary["last_hour"] or 0,
        },
        "activity": [
            {"timestamp": cutoff + (index * bucket_seconds), "count": activity_counts.get(index, 0)}
            for index in range(hours)
        ],
        "detectors": [dict(row) for row in detector_rows],
        "top_offenders": [dict(row) for row in offender_rows],
    }


def get_findings_by_src_ip(src_ip: str, limit: int = 50) -> List[FindingRecord]:
    """All findings involving one source IP, most recent first — used by session_tracker."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?",
            (src_ip, limit),
        ).fetchall()
        return [FindingRecord.from_row(r) for r in rows]


def get_distinct_source_ips() -> List[str]:
    """Every src_ip that has at least one finding — used by session_tracker to know who to check."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT src_ip FROM findings WHERE src_ip IS NOT NULL"
        ).fetchall()
        return [row["src_ip"] for row in rows]


def get_ungrouped_findings(limit: int = 500) -> List[FindingRecord]:
    """Findings that haven't been assigned to an incident yet — what grouper.py works through."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE incident_id IS NULL ORDER BY timestamp ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [FindingRecord.from_row(r) for r in rows]


def assign_incident_id(finding_id: int, incident_id: str) -> None:
    """Back-fills incident_id onto one finding row, called by grouper.py."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE findings SET incident_id = ? WHERE id = ?", (incident_id, finding_id)
        )


def find_related_incident(finding: FindingRecord, since: float) -> str | None:
    """Find the most recent compatible incident for incremental grouping."""
    interface = finding.interface_name
    if finding.detector_name in {"rogue_dhcp", "evil_twin"}:
        clause = "interface_name = ? AND detector_name = ?"
        values = [interface, finding.detector_name]
    elif finding.detector_name in {"syn_flood", "icmp_flood", "udp_flood"}:
        clause = "interface_name = ? AND detector_name = ? AND dst_ip = ?"
        values = [interface, finding.detector_name, finding.dst_ip]
    elif finding.src_ip:
        clause = "interface_name = ? AND src_ip = ?"
        values = [interface, finding.src_ip]
    elif finding.dst_ip:
        clause = "interface_name = ? AND dst_ip = ?"
        values = [interface, finding.dst_ip]
    else:
        clause = "interface_name = ? AND detector_name = ?"
        values = [interface, finding.detector_name]
    with get_connection() as conn:
        row = conn.execute(
            f"""SELECT incident_id FROM findings
                WHERE incident_id IS NOT NULL AND timestamp >= ? AND {clause}
                ORDER BY timestamp DESC LIMIT 1""",
            (since, *values),
        ).fetchone()
    return row["incident_id"] if row else None


def get_findings_by_incident(incident_id: str) -> List[FindingRecord]:
    """All findings grouped under one incident, oldest first — for a timeline view."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        ).fetchall()
        return [FindingRecord.from_row(r) for r in rows]


def get_finding_by_id(finding_id: int) -> FindingRecord | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return FindingRecord.from_row(row) if row is not None else None


def get_timeline_findings(
    limit: int = 200,
    incident_id: str | None = None,
    src_ip: str | None = None,
) -> List[FindingRecord]:
    """Chronological findings with optional incident or source filters."""
    clauses = []
    values: list = []
    if incident_id:
        clauses.append("f.incident_id = ?")
        values.append(incident_id)
    if src_ip:
        clauses.append("f.src_ip = ?")
        values.append(src_ip)
    clauses.insert(0, "COALESCE(c.status, 'open') != 'resolved'")
    where = f"WHERE {' AND '.join(clauses)}"
    values.append(max(1, min(int(limit), 1000)))
    with get_connection() as conn:
        rows = conn.execute(
            f"""SELECT f.* FROM findings f
                LEFT JOIN cases c ON c.incident_id = f.incident_id
                {where} ORDER BY f.timestamp DESC LIMIT ?""",
            values,
        ).fetchall()
    return [FindingRecord.from_row(row) for row in reversed(rows)]
