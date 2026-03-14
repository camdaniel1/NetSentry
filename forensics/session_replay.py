"""
forensics/session_replay.py

Reconstructs everything a single host has been involved in, across
every incident, as one chronological narrative.

Useful for tracing lateral movement or a repeat offender across time —
e.g. a host that ARP-spoofed the gateway last week and is now doing it
again shows up as one continuous replay, not two disconnected incidents
you'd have to notice were related yourself.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity, score
from detectors.base import Finding
from storage.event_store import get_findings_by_src_ip
from storage.models import FindingRecord


@dataclass
class ReplayStep:
    timestamp: float
    detector_name: str
    summary: str
    severity: Severity
    incident_id: Optional[str]  # None if this finding hasn't been grouped yet


@dataclass
class HostSessionReplay:
    """The full chronological narrative of one host's activity."""

    ip: str
    steps: List[ReplayStep]

    @property
    def distinct_incidents(self) -> List[str]:
        """Every incident_id this host has been part of, in first-appearance order."""
        seen = []
        for step in self.steps:
            if step.incident_id and step.incident_id not in seen:
                seen.append(step.incident_id)
        return seen

    @property
    def spans_multiple_incidents(self) -> bool:
        """True if this host's activity has been split across more than one incident."""
        return len(self.distinct_incidents) > 1


def _record_to_step(record: FindingRecord) -> ReplayStep:
    pseudo_finding = Finding(
        detector_name=record.detector_name,
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        summary=record.summary,
        details=record.details,
    )
    return ReplayStep(
        timestamp=record.timestamp,
        detector_name=record.detector_name,
        summary=record.summary,
        severity=score(pseudo_finding),
        incident_id=record.incident_id,
    )


def replay_host(ip: str, limit: int = 500) -> HostSessionReplay:
    """
    Builds the full chronological replay for one host. get_findings_by_src_ip
    returns most-recent-first, so this reverses it to present the
    narrative in the order things actually happened.
    """
    records = get_findings_by_src_ip(ip, limit=limit)
    records_chronological = list(reversed(records))
    steps = [_record_to_step(r) for r in records_chronological]
    return HostSessionReplay(ip=ip, steps=steps)