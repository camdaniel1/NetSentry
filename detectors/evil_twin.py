"""Detect duplicate Wi-Fi SSIDs advertised by changing BSSIDs."""
from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding


class EvilTwinDetector(Detector):
    name = "evil_twin"

    def __init__(self):
        self.ssids = {}
        self.alerted = set()

    def process_packet(self, packet: NormalizedPacket):
        if not packet.has_protocol("dot11") or not packet.has_protocol("dot11elt"):
            return None

        if int(packet.get("dot11elt", "ID", -1)) != 0:
            return None

        raw = packet.get("dot11elt", "info", b"")
        ssid = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
        bssid = str(
            packet.get("dot11", "addr3") or packet.get("dot11", "addr2") or ""
        ).lower()

        if not ssid or not bssid:
            return None

        known = self.ssids.setdefault(ssid, set())

        if not known:
            known.add(bssid)
            return None

        if bssid in known:
            return None

        prior = sorted(known)
        known.add(bssid)
        key = (ssid, bssid)

        if key in self.alerted:
            return None

        self.alerted.add(key)

        return Finding(
            self.name,
            packet.timestamp,
            bssid,
            None,
            f"Possible evil twin: SSID '{ssid}' appeared from new BSSID {bssid}; "
            f"known BSSID(s): {', '.join(prior[:3])}",
            {
                "wireless_pattern": "duplicate_ssid",
                "ssid": ssid,
                "new_bssid": bssid,
                "known_bssids": prior,
                "requires_monitor_mode": True
            }
        )