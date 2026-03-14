"""Detect concentrated ICMP echo-request floods."""
from collections import defaultdict, deque

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding


class IcmpFloodDetector(Detector):
    name = "icmp_flood"

    def __init__(self, threshold=100, window_seconds=5.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.windows = defaultdict(deque)
        self.alerted = {}

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("icmp") or int(packet.get("icmp", "type", -1)) != 8:
            return None

        src = packet.get("ip", "src") or packet.src
        dst = packet.get("ip", "dst") or packet.dst
        key = str(dst)

        window = self.windows[key]
        window.append((packet.timestamp, str(src)))
        cutoff = packet.timestamp - self.window_seconds

        while window and window[0][0] < cutoff:
            window.popleft()

        if (
            len(window) < self.threshold
            or packet.timestamp - self.alerted.get(key, -self.window_seconds) < self.window_seconds
        ):
            return None

        self.alerted[key] = packet.timestamp
        sources = {source for _, source in window}
        duration = max(.001, packet.timestamp - window[0][0])
        rate = len(window) / duration
        pattern = "distributed" if len(sources) >= 5 else "single_source"

        return Finding(
            self.name,
            packet.timestamp,
            str(src),
            str(dst),
            f"{pattern.replace('_', ' ').title()} ICMP flood against {dst}: "
            f"{len(window)} echo requests at {rate:.1f}/s",
            {
                "flood_pattern": pattern,
                "packet_count": len(window),
                "packet_rate": round(rate, 2),
                "source_count": len(sources),
                "duration_seconds": duration
            }
        )