"""
forensics/timeline.py

Reconstructs a single incident as an ordered timeline of what was
detected, and when. An "incident" here is a group of findings sharing
one incident_id, assigned by correlation/grouper.py.

If a finding has evidence attached (pcap_file/pcap_offset/pcap_length —
see core/event.py), the timeline entry includes that so a caller could
go pull the actual packet bytes. 
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity, score
from storage.event_store import get_findings_by_incident
from storage.models import FindingRecord


@dataclass
class TimelineEntry:
    timestamp: float
    detector_name: str
    summary: str
    severity: Severity
    src_ip: Optional[str]
    pcap_file: Optional[str] = None
    pcap_packet_number: Optional[int] = None
    pcap_offset: Optional[int] = None
    pcap_length: Optional[int] = None


@dataclass
class IncidentTimeline:
    """The full reconstructed picture of one incident."""

    incident_id: str
    entries: List[TimelineEntry]

    @property
    def first_seen(self) -> Optional[float]:
        return self.entries[0].timestamp if self.entries else None

    @property
    def last_seen(self) -> Optional[float]:
        return self.entries[-1].timestamp if self.entries else None

    @property
    def event_count(self) -> int:
        return len(self.entries)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.entries:
            return None
        rank = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}
        return max((e.severity for e in self.entries), key=lambda s: rank[s])

    @property
    def involved_detectors(self) -> List[str]:
        return sorted({e.detector_name for e in self.entries})


def _record_to_entry(record: FindingRecord) -> TimelineEntry:
    return TimelineEntry(
        timestamp=record.timestamp,
        detector_name=record.detector_name,
        summary=record.summary,
        severity=score(_record_to_pseudo_finding(record)),
        src_ip=record.src_ip,
        pcap_file=record.pcap_file,
        pcap_packet_number=record.pcap_packet_number,
        pcap_offset=record.pcap_offset,
        pcap_length=record.pcap_length,
    )


def _record_to_pseudo_finding(record: FindingRecord):
    """severity.score() expects a Finding-shaped object; build a minimal one from the record."""
    from detectors.base import Finding
    return Finding(
        detector_name=record.detector_name,
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        summary=record.summary,
        details=record.details,
    )


def build_timeline(incident_id: str) -> IncidentTimeline:
    """Fetches every finding grouped under incident_id and returns them as an ordered timeline."""
    records = get_findings_by_incident(incident_id)  # already ordered oldest-first by the query
    entries = [_record_to_entry(r) for r in records]
    return IncidentTimeline(incident_id=incident_id, entries=entries)
