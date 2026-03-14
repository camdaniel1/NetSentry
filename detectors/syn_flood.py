"""Detect bursts of initial TCP SYN packets targeting a host and port."""

from __future__ import annotations

from collections import defaultdict, deque

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding


class SynFloodDetector(Detector):
    name = "syn_flood"

    def __init__(self, syn_threshold: int = 100, window_seconds: float = 5.0) -> None:
        self.syn_threshold = syn_threshold
        self.window_seconds = window_seconds
        self._attempts = defaultdict(deque)
        self._last_alert: dict[tuple[str, int], float] = {}

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("tcp"):
            return None
        flags = str(packet.get("tcp", "flags", ""))
        if "S" not in flags or "A" in flags:
            return None
        src_ip = packet.get("ip", "src") or packet.get("ipv6", "src") or packet.src
        dst_ip = packet.get("ip", "dst") or packet.get("ipv6", "dst") or packet.dst
        dst_port = packet.get("tcp", "dport")
        src_port = packet.get("tcp", "sport")
        if not src_ip or not dst_ip or dst_port is None:
            return None
        key = (str(dst_ip), int(dst_port))
        window = self._attempts[key]
        window.append((packet.timestamp, str(src_ip), int(src_port or 0)))
        cutoff = packet.timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        if len(window) < self.syn_threshold:
            return None
        if packet.timestamp - self._last_alert.get(key, -self.window_seconds) < self.window_seconds:
            return None
        self._last_alert[key] = packet.timestamp
        sources = {source for _, source, _ in window}
        source_ports = {port for _, _, port in window}
        duration = max(0.001, packet.timestamp - window[0][0])
        rate = len(window) / duration
        pattern = "distributed" if len(sources) >= 5 else "single_source"
        return Finding(
            detector_name=self.name, timestamp=packet.timestamp,
            src_ip=str(src_ip), dst_ip=str(dst_ip),
            summary=(f"{pattern.replace('_', ' ').title()} SYN flood against "
                     f"{dst_ip}:{dst_port}: {len(window)} SYNs at {rate:.1f}/s "
                     f"from {len(sources)} source(s)"),
            details={"flood_pattern": pattern, "syn_count": len(window),
                     "syn_rate": round(rate, 2), "source_count": len(sources),
                     "unique_source_ports": len(source_ports),
                     "destination_port": int(dst_port), "duration_seconds": duration},
        )
