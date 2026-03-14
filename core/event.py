"""
core/event.py

The unit that flows through the pipeline once a detector's raw Finding
has been enriched with everything downstream stages need. Event is that
same Finding plus its computed severity and, if available, exactly
where the evidence for it lives on disk.

"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity, score
from detectors.base import Finding


@dataclass
class Event:
    """
    A Finding enriched with severity and (optionally) an evidence
    location.
    """

    finding: Finding
    severity: Severity
    pcap_file: Optional[str] = None
    pcap_packet_number: Optional[int] = None
    pcap_offset: Optional[int] = None
    pcap_length: Optional[int] = None

    @property
    def detector_name(self) -> str:
        return self.finding.detector_name

    @property
    def summary(self) -> str:
        return self.finding.summary

    @property
    def src_ip(self) -> Optional[str]:
        return self.finding.src_ip

    @property
    def has_evidence(self) -> bool:
        """True if this event has a pcap location attached to it."""
        return self.pcap_file is not None

    @classmethod
    def from_finding(cls, finding: Finding) -> "Event":
        """
        Builds an Event from a bare Finding, computing severity via
        correlation/severity.py.
        """
        return cls(finding=finding, severity=score(finding))

    def attach_evidence(self, pcap_file: str, pcap_offset: int, pcap_length: int,
                        pcap_packet_number: int | None = None) -> None:
        """Records where the raw packet(s) behind this event were written to disk."""
        self.pcap_file = pcap_file
        self.pcap_packet_number = pcap_packet_number
        self.pcap_offset = pcap_offset
        self.pcap_length = pcap_length
