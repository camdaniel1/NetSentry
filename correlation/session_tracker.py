"""
correlation/session_tracker.py

Cross-finding host tracing. Session_tracker answers which hosts look
the most suspicious overall?"
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity, score
from detectors.base import Finding
from storage.event_store import get_distinct_source_ips, get_findings_by_src_ip


@dataclass
class HostSummary:
    ip: str
    finding_count: int
    detector_types: List[str]        # which detectors have flagged this host
    highest_severity: Severity
    first_seen: float                 # earliest finding timestamp
    last_seen: float                   # most recent finding timestamp
    is_repeat_offender: bool            # flagged by more than one finding


def _dict_to_finding(record) -> Finding:
    return Finding(
        detector_name=record.detector_name,
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        summary=record.summary,
        details=record.details,
    )


_SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def summarize_host(ip: str, limit: int = 200) -> HostSummary:
    """Builds a HostSummary for one IP from everything currently stored about it."""
    rows = get_findings_by_src_ip(ip, limit=limit)
    findings = [_dict_to_finding(r) for r in rows]

    if not findings:
        return HostSummary(
            ip=ip, finding_count=0, detector_types=[],
            highest_severity=Severity.low, first_seen=0.0, last_seen=0.0,
            is_repeat_offender=False,
        )

    severities = [score(f) for f in findings]
    highest = max(severities, key=lambda s: _SEVERITY_RANK[s])
    detector_types = sorted({f.detector_name for f in findings})
    timestamps = [f.timestamp for f in findings]

    return HostSummary(
        ip=ip,
        finding_count=len(findings),
        detector_types=detector_types,
        highest_severity=highest,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        is_repeat_offender=len(findings) > 1,
    )


def get_repeat_offenders(limit: int = 200) -> List[HostSummary]:
    """
    All hosts with more than one finding, sorted by finding_count
    descending — the "who should I actually look at" view.
    """
    ips = get_distinct_source_ips()
    summaries = [summarize_host(ip, limit=limit) for ip in ips]
    repeat_offenders = [s for s in summaries if s.is_repeat_offender]
    return sorted(repeat_offenders, key=lambda s: s.finding_count, reverse=True)