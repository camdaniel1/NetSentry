"""Base interface for pluggable detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from capture.packet_normalizer import NormalizedPacket


@dataclass(slots=True)
class Finding:
    """A single generic detection result."""

    detector_name: str
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    summary: str = ""
    details: dict = field(default_factory=dict)


class Detector(ABC):
    """Base class for detectors that consume normalized packets."""

    name: str = "unnamed_detector"

    @abstractmethod
    def process_packet(self, packet: NormalizedPacket) -> Optional[Finding]:
        """Return a Finding when the packet triggers detection, otherwise None."""
        raise NotImplementedError

    def flush(self) -> List[Finding]:
        """Optionally emit findings buffered by a stateful detector."""
        return []
