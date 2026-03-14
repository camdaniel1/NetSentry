"""Detect observable responses to promiscuous-mode probes; passive sniffers remain silent."""
from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding

PROMISCUOUS_PROBE_MAC = "01:00:5e:00:00:01"


class PacketSniffingDetector(Detector):
    name = "packet_sniffing"

    def __init__(self):
        self.alerted = set()

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("icmp") or int(packet.get("icmp", "type", -1)) != 0:
            return None

        dst_mac = str(packet.get("ether", "dst") or "").lower()
        if dst_mac != PROMISCUOUS_PROBE_MAC:
            return None

        src = str(packet.get("ip", "src") or packet.src)
        dst = str(packet.get("ip", "dst") or packet.dst)

        if src in self.alerted:
            return None

        self.alerted.add(src)

        return Finding(
            self.name,
            packet.timestamp,
            src,
            dst,
            f"Promiscuous-mode probe response from {src}: "
            f"ICMP reply accepted through probe MAC {dst_mac}",
            {
                "sniffing_indicator": "promiscuous_probe_response",
                "probe_mac": dst_mac,
                "limitation": "passive sniffers emit no detectable traffic"
            }
        )