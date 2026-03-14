"""
correlation/grouper.py

Groups related Findings into incidents.

Grouping rule (deliberately simple): findings from the same interface and
src_ip, within TIME_WINDOW_SECONDS of each other, belong to the same incident.

Run periodically (e.g. every 30s from core/pipeline.py once that
exists), or manually:

    python -m correlation.grouper
"""

from __future__ import annotations

import os
import sys
import uuid
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.event_store import (
    assign_incident_id,
    find_related_incident,
    get_ungrouped_findings,
    init_db,
)

# findings from the same src_ip within this many seconds of each other
# get grouped into the same incident
TIME_WINDOW_SECONDS = 15 * 60


def _correlation_key(finding) -> tuple:
    """Choose the network entity that best represents each detector's incident."""
    interface = getattr(finding, "interface_name", None)
    detector = finding.detector_name
    if detector in {"rogue_dhcp", "evil_twin"}:
        return interface, detector
    if detector in {"syn_flood", "icmp_flood", "udp_flood"}:
        return interface, detector, finding.dst_ip
    return interface, finding.src_ip or finding.dst_ip or detector


def _cluster_by_ip_and_time(findings: List) -> List[List]:
    """
    Groups findings first by interface and src_ip, then splits each source's findings into
    time-based clusters wherever the gap between consecutive findings
    exceeds TIME_WINDOW_SECONDS. Findings with no src_ip are each their
    own single-finding cluster, since there's nothing to group them by.
    """
    by_source: Dict[tuple, List] = {}

    for finding in findings:
        by_source.setdefault(_correlation_key(finding), []).append(finding)

    clusters: List[List] = []

    for source_findings in by_source.values():
        source_findings.sort(key=lambda f: f.timestamp)
        current_cluster = [source_findings[0]]

        for finding in source_findings[1:]:
            gap = finding.timestamp - current_cluster[-1].timestamp
            if gap <= TIME_WINDOW_SECONDS:
                current_cluster.append(finding)
            else:
                clusters.append(current_cluster)
                current_cluster = [finding]

        clusters.append(current_cluster)

    return clusters


def run_grouping(limit: int = 500) -> int:
    """
    Pulls all ungrouped findings, clusters them, assigns a fresh
    incident_id to each cluster. Returns the number of incidents created.
    """
    ungrouped = get_ungrouped_findings(limit=limit)
    if not ungrouped:
        return 0

    clusters = _cluster_by_ip_and_time(ungrouped)

    for cluster in clusters:
        existing_incident = find_related_incident(
            cluster[0], cluster[0].timestamp - TIME_WINDOW_SECONDS
        )
        incident_id = existing_incident or str(uuid.uuid4())
        for finding in cluster:
            assign_incident_id(finding.id, incident_id)
    # Report clusters processed, including clusters appended to an existing
    # incident, so callers do not incorrectly report that nothing happened.
    return len(clusters)
