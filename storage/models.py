"""
storage/models.py

Typed representation of a row in the findings table. detectors/base.py's
Finding is what a detector produces before it's ever been stored — it
has no id, no incident_id (those don't exist until the DB assigns
them). FindingRecord is what comes back out of storage/db.py: a
Finding plus the fields SQLite adds.

Kept as a plain dataclass, not an ORM model — there's one table, no
relationships to map, so an ORM would be overhead without benefit at
this scale.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class FindingRecord:
    """A Finding as it exists in the database — includes id and incident_id."""

    id: int
    detector_name: str
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    summary: str
    details: dict
    incident_id: Optional[str]
    interface_name: str
    interface_human_name: str
    pcap_file: Optional[str] = None
    pcap_packet_number: Optional[int] = None
    pcap_offset: Optional[int] = None
    pcap_length: Optional[int] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "FindingRecord":
        """Builds a FindingRecord from a raw sqlite3.Row, deserializing the JSON details blob."""
        keys = row.keys()
        return cls(
            id=row["id"],
            detector_name=row["detector_name"],
            timestamp=row["timestamp"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            summary=row["summary"],
            details=json.loads(row["details"]),
            incident_id=row["incident_id"],
            interface_name=row["interface_name"],
            interface_human_name=row["interface_human_name"],
            pcap_file=row["pcap_file"] if "pcap_file" in keys else None,
            pcap_packet_number=row["pcap_packet_number"] if "pcap_packet_number" in keys else None,
            pcap_offset=row["pcap_offset"] if "pcap_offset" in keys else None,
            pcap_length=row["pcap_length"] if "pcap_length" in keys else None,
        )
