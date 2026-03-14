"""Detect DNS query patterns commonly associated with encoded-data tunneling."""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding
from settings import setting

DEFAULT_IGNORED_SUFFIXES = tuple(setting("detectors.dns_tunneling.ignored_suffixes"))
QUERY_THRESHOLD = int(setting("detectors.dns_tunneling.query_threshold"))
WINDOW_SECONDS = float(setting("detectors.dns_tunneling.window_seconds"))
LONG_LABEL_LENGTH = int(setting("detectors.dns_tunneling.long_label_length"))
ENTROPY_THRESHOLD = float(setting("detectors.dns_tunneling.entropy_threshold"))


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value.lower())
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class DnsTunnelingDetector(Detector):
    name = "dns_tunneling"

    def __init__(self, query_threshold: int = QUERY_THRESHOLD, window_seconds: float = WINDOW_SECONDS,
                 long_label: int = LONG_LABEL_LENGTH, entropy_threshold: float = ENTROPY_THRESHOLD,
                 ignored_suffixes: tuple[str, ...] = DEFAULT_IGNORED_SUFFIXES) -> None:
        self.query_threshold = query_threshold
        self.window_seconds = window_seconds
        self.long_label = long_label
        self.entropy_threshold = entropy_threshold
        self.ignored_suffixes = tuple(suffix.lower().lstrip(".") for suffix in ignored_suffixes)
        self._queries = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], float] = {}

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("dns"):
            return None
        qr = packet.get("dns", "qr", 0)
        if int(qr or 0) != 0:
            return None
        raw_name = packet.get("dnsqr", "qname") or packet.get("dns", "qname")
        if not raw_name:
            questions = packet.get("dns", "qd", ()) or ()
            if isinstance(questions, dict):
                questions = (questions,)
            if questions and isinstance(questions[0], dict):
                raw_name = questions[0].get("qname")
        if isinstance(raw_name, bytes):
            raw_name = raw_name.decode("ascii", errors="ignore")
        qname = str(raw_name or "").rstrip(".").lower()
        if not qname:
            return None
        if any(qname == suffix or qname.endswith(f".{suffix}") for suffix in self.ignored_suffixes):
            return None
        src_ip = packet.get("ip", "src") or packet.get("ipv6", "src") or packet.src
        dst_ip = packet.get("ip", "dst") or packet.get("ipv6", "dst") or packet.dst
        label = qname.split(".")[0]
        entropy = _entropy(label)
        labels = qname.split(".")
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
        window_key = (str(src_ip), base_domain)
        window = self._queries[window_key]
        window.append((packet.timestamp, qname, label, entropy))
        cutoff = packet.timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        unique_queries = {name for _, name, _, _ in window}
        unique_labels = {item_label for _, _, item_label, _ in window}
        average_label_length = sum(len(item_label) for _, _, item_label, _ in window) / len(window)
        average_entropy = sum(item_entropy for _, _, _, item_entropy in window) / len(window)
        encoded_label = len(label) >= self.long_label and entropy >= self.entropy_threshold
        high_volume = (
            len(unique_queries) >= self.query_threshold
            and len(unique_labels) >= self.query_threshold
            and average_label_length >= 12
            and average_entropy >= 3.0
        )
        if not encoded_label and not high_volume:
            return None
        if packet.timestamp - self._last_alert.get(window_key, -self.window_seconds) < self.window_seconds:
            return None
        self._last_alert[window_key] = packet.timestamp
        pattern = "encoded_label" if encoded_label else "high_query_variation"
        duration = packet.timestamp - window[0][0]
        return Finding(
            detector_name=self.name, timestamp=packet.timestamp,
            src_ip=str(src_ip), dst_ip=str(dst_ip),
            summary=(f"Possible DNS tunnel from {src_ip}: {pattern.replace('_', ' ')} "
                     f"with {len(unique_queries)} unique queries in {duration:.1f}s; "
                     f"sample {qname[:80]}"),
            details={"tunnel_pattern": pattern, "query_name": qname,
                     "label_length": len(label), "label_entropy": round(entropy, 2),
                     "base_domain": base_domain, "unique_queries": len(unique_queries),
                     "average_label_length": round(average_label_length, 2),
                     "average_label_entropy": round(average_entropy, 2),
                     "duration_seconds": duration},
        )
