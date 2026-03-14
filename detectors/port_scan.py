"""Detect TCP vertical port scans and horizontal host sweeps."""

from __future__ import annotations

import ipaddress
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding

PORT_THRESHOLD = 15
HOST_THRESHOLD = 10
WINDOW_SECONDS = 10.0
COMMON_SERVICE_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080}
COMMON_WEB_PORTS = {80, 443}


def _destination_network(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    prefix = 24 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


def _vertical_pattern(ports: set[int]) -> tuple[str, str]:
    ordered = sorted(ports)
    sequential = len(ordered) > 1 and all(
        right - left == 1 for left, right in zip(ordered, ordered[1:])
    )
    if sequential:
        return "sequential", f"ports {ordered[0]}–{ordered[-1]}"
    common_count = len(ports & COMMON_SERVICE_PORTS)
    sample = ", ".join(str(port) for port in ordered[:5])
    if common_count >= max(3, len(ports) // 2):
        return "service-focused", f"common services including {sample}"
    return "distributed", f"ports including {sample}"


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self, port_threshold: int = PORT_THRESHOLD,
                 host_threshold: int = HOST_THRESHOLD,
                 window_seconds: float = WINDOW_SECONDS,
                 web_host_threshold: int = 30) -> None:
        self._port_threshold = port_threshold
        self._host_threshold = host_threshold
        self._window_seconds = window_seconds
        self._web_host_threshold = max(host_threshold, web_host_threshold)
        self._ports: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = {}
        self._hosts: Dict[Tuple[str, int], Deque[Tuple[float, str]]] = {}
        self._last_alert: Dict[Tuple[str, object], float] = {}

    def _recent_distinct(self, window: Deque, timestamp: float) -> set:
        cutoff = timestamp - self._window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        return {value for _, value in window}

    def _can_alert(self, key: Tuple[str, object], timestamp: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and timestamp - last < self._window_seconds:
            return False
        self._last_alert[key] = timestamp
        return True

    def process_packet(self, packet: NormalizedPacket) -> Optional[Finding]:
        if not packet.has_protocol("tcp"):
            return None
        flags = str(packet.get("tcp", "flags", ""))
        if "S" not in flags or "A" in flags:
            return None

        src_ip = packet.get("ip", "src") or packet.get("ipv6", "src") or packet.src
        dst_ip = packet.get("ip", "dst") or packet.get("ipv6", "dst") or packet.dst
        dst_port = packet.get("tcp", "dport")
        if not src_ip or not dst_ip or dst_port is None:
            return None
        dst_port = int(dst_port)

        port_key = (str(src_ip), str(dst_ip))
        port_window = self._ports.setdefault(port_key, deque())
        port_window.append((packet.timestamp, dst_port))
        distinct_ports = self._recent_distinct(port_window, packet.timestamp)
        alert_key = ("vertical", port_key)
        if len(distinct_ports) >= self._port_threshold and self._can_alert(alert_key, packet.timestamp):
            pattern, port_description = _vertical_pattern(distinct_ports)
            duration = max(0.0, packet.timestamp - port_window[0][0])
            return Finding(
                detector_name=self.name, timestamp=packet.timestamp,
                src_ip=str(src_ip), dst_ip=str(dst_ip),
                summary=(f"{pattern.title()} vertical scan: {src_ip} probed {port_description} "
                         f"on {dst_ip} in {duration:.1f}s"),
                details={"scan_type": "vertical", "scan_pattern": pattern,
                         "port_count": len(distinct_ports), "duration_seconds": duration,
                         "window_seconds": self._window_seconds,
                         "sample_ports": sorted(distinct_ports)[:20]},
            )

        try:
            destination_network = _destination_network(str(dst_ip))
        except ValueError:
            return None
        host_key = (str(src_ip), dst_port, destination_network)
        host_window = self._hosts.setdefault(host_key, deque())
        host_window.append((packet.timestamp, str(dst_ip)))
        distinct_hosts = self._recent_distinct(host_window, packet.timestamp)
        alert_key = ("horizontal", host_key)
        required_hosts = self._web_host_threshold if dst_port in COMMON_WEB_PORTS else self._host_threshold
        if len(distinct_hosts) >= required_hosts and self._can_alert(alert_key, packet.timestamp):
            ordered_hosts = sorted(distinct_hosts)
            duration = max(0.0, packet.timestamp - host_window[0][0])
            host_sample = ", ".join(ordered_hosts[:3])
            return Finding(
                detector_name=self.name, timestamp=packet.timestamp,
                src_ip=str(src_ip), dst_ip=str(dst_ip),
                summary=(f"Horizontal sweep: {src_ip} probed TCP/{dst_port} across "
                         f"{len(distinct_hosts)} hosts in {destination_network} over {duration:.1f}s "
                         f"(including {host_sample})"),
                details={"scan_type": "horizontal", "host_count": len(distinct_hosts),
                         "destination_port": dst_port, "destination_network": destination_network,
                         "required_hosts": required_hosts, "duration_seconds": duration,
                         "window_seconds": self._window_seconds,
                         "sample_hosts": ordered_hosts[:20]},
            )
        return None
