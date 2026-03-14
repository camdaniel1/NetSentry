"""Detect martian IP sources and rapid IP-to-MAC identity conflicts."""
import ipaddress

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding


class IpSpoofingDetector(Detector):
    name = "ip_spoofing"

    def __init__(self):
        self.identities = {}
        self.alerted = set()

    def process_packet(self, packet: NormalizedPacket):
        if not (packet.has_protocol("ip") or packet.has_protocol("ipv6")):
            return None

        src = str(
            packet.get("ip", "src")
            or packet.get("ipv6", "src")
            or packet.src
            or ""
        )
        dst = str(
            packet.get("ip", "dst")
            or packet.get("ipv6", "dst")
            or packet.dst
            or ""
        )
        mac = str(packet.get("ether", "src") or "").lower()

        try:
            address = ipaddress.ip_address(src)
        except ValueError:
            return None

        martian = (
            address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_reserved
        )

        if martian:
            key = ("martian", src)

            if key in self.alerted:
                return None

            self.alerted.add(key)
            pattern = "martian_source"
            summary = f"Impossible source address observed: {src} sent traffic to {dst}"
        else:
            previous = self.identities.get(src)
            self.identities[src] = mac

            if not mac or not previous or previous == mac:
                return None

            key = (src, mac)

            if key in self.alerted:
                return None

            self.alerted.add(key)
            pattern = "layer2_identity_conflict"
            summary = (
                f"Possible IP spoofing: {src} changed Ethernet identity "
                f"from {previous} to {mac}"
            )

        return Finding(
            self.name,
            packet.timestamp,
            src,
            dst,
            summary,
            {
                "spoof_pattern": pattern,
                "source_mac": mac,
                "previous_mac": locals().get("previous")
            }
        )