"""Detect conflicting and unstable ARP address claims."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from capture.packet_normalizer import NormalizedPacket
from detectors.base import Detector, Finding
from settings import setting

FLAP_WINDOW_SECONDS = float(setting("detectors.arp_spoof.flap_window_seconds"))
INVALID_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


class ArpSpoofDetector(Detector):
    name = "arp_spoof"

    def __init__(self, flap_window_seconds: float = FLAP_WINDOW_SECONDS) -> None:
        self._ip_to_mac: Dict[str, str] = {}
        self._last_change: Dict[str, float] = {}
        self._recent_macs: Dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        self._flap_window_seconds = flap_window_seconds

    def process_packet(self, packet: NormalizedPacket) -> Optional[Finding]:
        if not packet.has_protocol("arp") or packet.get("arp", "op") != 2:
            return None

        claimed_ip = str(packet.get("arp", "psrc") or "").strip()
        claimed_mac = str(packet.get("arp", "hwsrc") or "").lower().strip()
        target_ip = str(packet.get("arp", "pdst") or "").strip()
        if not claimed_ip or not claimed_mac or claimed_mac in INVALID_MACS:
            return None

        previous_mac = self._ip_to_mac.get(claimed_ip)
        if previous_mac is None:
            self._ip_to_mac[claimed_ip] = claimed_mac
            self._recent_macs[claimed_ip].append((packet.timestamp, claimed_mac))
            return None
        if previous_mac == claimed_mac:
            return None

        history = self._recent_macs[claimed_ip]
        cutoff = packet.timestamp - self._flap_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()
        history.append((packet.timestamp, claimed_mac))
        distinct_macs = {mac for _, mac in history}
        seconds_since_change = packet.timestamp - self._last_change.get(claimed_ip, packet.timestamp)
        is_gratuitous = target_ip == claimed_ip
        is_reversal = any(mac == claimed_mac for _, mac in list(history)[:-1])

        if len(distinct_macs) >= 3:
            pattern = "multiple_claimants"
            summary = (f"Multiple ARP claimants: {claimed_ip} rotated across "
                       f"{len(distinct_macs)} MAC addresses; latest is {claimed_mac}")
        elif is_reversal:
            pattern = "mac_flapping"
            summary = (f"ARP mapping flapped: {claimed_ip} reverted from {previous_mac} "
                       f"to {claimed_mac} after {seconds_since_change:.1f}s")
        elif is_gratuitous:
            pattern = "gratuitous_conflict"
            summary = (f"Conflicting gratuitous ARP claim: {claimed_ip} announced "
                       f"{claimed_mac}, replacing {previous_mac}")
        else:
            pattern = "mapping_change"
            summary = f"ARP mapping changed: {claimed_ip} moved from {previous_mac} to {claimed_mac}"

        self._ip_to_mac[claimed_ip] = claimed_mac
        self._last_change[claimed_ip] = packet.timestamp
        return Finding(
            detector_name=self.name,
            timestamp=packet.timestamp,
            src_ip=claimed_ip,
            dst_ip=target_ip or None,
            summary=summary,
            details={
                "claim_pattern": pattern,
                "old_mac": previous_mac,
                "new_mac": claimed_mac,
                "target_ip": target_ip or None,
                "gratuitous": is_gratuitous,
                "distinct_recent_macs": sorted(distinct_macs),
                "seconds_since_change": seconds_since_change,
                "flap_window_seconds": self._flap_window_seconds,
            },
        )
