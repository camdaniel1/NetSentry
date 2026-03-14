"""Detect competing or explicitly unauthorized DHCP servers."""

from __future__ import annotations

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding
from settings import setting


def _dhcp_options(packet: NormalizedPacket) -> dict[str, object]:
    options = packet.get("dhcp", "options", ()) or ()
    result = {}
    for option in options:
        if isinstance(option, (list, tuple)) and len(option) >= 2:
            result[str(option[0])] = option[1]
    return result


class RogueDhcpDetector(Detector):
    name = "rogue_dhcp"

    def __init__(self, trusted_server_ips: set[str] | None = None,
                 trusted_server_macs: set[str] | None = None) -> None:
        configured_ips = set(setting("detectors.rogue_dhcp.trusted_server_ips"))
        configured_macs = set(setting("detectors.rogue_dhcp.trusted_server_macs"))
        self.trusted_server_ips = configured_ips if trusted_server_ips is None else trusted_server_ips
        macs = configured_macs if trusted_server_macs is None else trusted_server_macs
        self.trusted_server_macs = {mac.lower() for mac in macs}
        self._baseline_server: tuple[str, str] | None = None
        self._alerted_servers: set[tuple[str, str]] = set()

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("dhcp"):
            return None
        options = _dhcp_options(packet)
        message_type = options.get("message-type")
        if isinstance(message_type, bytes):
            message_type = message_type.decode(errors="ignore")
        message_type = str(message_type).lower()
        if message_type not in {"2", "5", "offer", "ack"}:
            return None
        server_ip = str(options.get("server_id") or packet.get("ip", "src") or "0.0.0.0")
        server_mac = str(packet.get("ether", "src") or packet.get("bootp", "chaddr") or "unknown").lower()
        server = (server_ip, server_mac)
        trusted = server_ip in self.trusted_server_ips or server_mac in self.trusted_server_macs
        if self.trusted_server_ips or self.trusted_server_macs:
            if trusted:
                return None
            pattern = "unauthorized_server"
        elif self._baseline_server is None:
            self._baseline_server = server
            return None
        elif server == self._baseline_server:
            return None
        else:
            pattern = "competing_server"
        if server in self._alerted_servers:
            return None
        self._alerted_servers.add(server)
        baseline = self._baseline_server
        return Finding(
            detector_name=self.name, timestamp=packet.timestamp,
            src_ip=server_ip, dst_ip=packet.dst or None,
            summary=(f"{pattern.replace('_', ' ').title()}: DHCP {message_type.upper()} "
                     f"from {server_ip} ({server_mac})"
                     + (f" conflicts with {baseline[0]} ({baseline[1]})" if baseline else "")),
            details={"dhcp_pattern": pattern, "message_type": message_type,
                     "server_ip": server_ip, "server_mac": server_mac,
                     "baseline_server_ip": baseline[0] if baseline else None,
                     "baseline_server_mac": baseline[1] if baseline else None},
        )
