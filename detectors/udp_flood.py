"""Detect high-rate UDP traffic targeting a host and port."""
from collections import defaultdict, deque

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding


class UdpFloodDetector(Detector):
    name = "udp_flood"

    def __init__(self, threshold=150, window_seconds=5.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.windows = defaultdict(deque)
        self.alerted = {}

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("udp"):
            return None

        src = packet.get("ip", "src") or packet.src
        dst = packet.get("ip", "dst") or packet.dst
        port = packet.get("udp", "dport")

        if not src or not dst or port is None:
            return None

        key = (str(dst), int(port))
        window = self.windows[key]
        window.append((packet.timestamp, str(src), packet.caplen))
        cutoff = packet.timestamp - self.window_seconds

        while window and window[0][0] < cutoff:
            window.popleft()

        if (
            len(window) < self.threshold
            or packet.timestamp - self.alerted.get(key, -self.window_seconds) < self.window_seconds
        ):
            return None

        self.alerted[key] = packet.timestamp
        sources = {source for _, source, _ in window}
        total = sum(size for _, _, size in window)
        duration = max(.001, packet.timestamp - window[0][0])
        rate = len(window) / duration
        pattern = "distributed" if len(sources) >= 5 else "single_source"

        return Finding(
            self.name,
            packet.timestamp,
            str(src),
            str(dst),
            f"{pattern.replace('_', ' ').title()} UDP flood against {dst}:{port}: "
            f"{len(window)} datagrams at {rate:.1f}/s",
            {
                "flood_pattern": pattern,
                "packet_count": len(window),
                "packet_rate": round(rate, 2),
                "byte_count": total,
                "source_count": len(sources),
                "destination_port": int(port),
                "duration_seconds": duration
            }
        )