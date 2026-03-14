"""
tests/test_arp_spoof.py

Validates ArpSpoofDetector using hand-crafted Scapy packets that are first
normalized through capture.packet_normalizer.normalize_packet().

No real network traffic is required.

Run with:
    python -m pytest tests/test_arp_spoof.py -v

or standalone:
    python tests/test_arp_spoof.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import ARP, Ether, IP, TCP, raw

from capture.packet_normalizer import NormalizedPacket, normalize_packet
from capture.sniffer import RawPacket
from detectors.arp_spoof import ArpSpoofDetector
from scripts.simulate_arp_spoof import DIFFICULTY_PROFILES, difficulty_meter, nearby_targets


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
TEST_TARGET_IP = "192.168.1.1"


def normalize(scapy_packet):
    raw_bytes = raw(scapy_packet)

    packet = RawPacket(
        timestamp=time.time(),
        caplen=len(raw_bytes),
        length=len(raw_bytes),
        data=raw_bytes,
        scapy_packet=scapy_packet,
    )

    return normalize_packet(packet)


def make_arp_reply(src_ip: str, src_mac: str, target_ip: str = TEST_TARGET_IP) -> NormalizedPacket:
    scapy_packet = (
        Ether(
            src=src_mac,
            dst=BROADCAST_MAC,
        )
        / ARP(
            op=2,
            psrc=src_ip,
            hwsrc=src_mac,
            pdst=target_ip,
            hwdst=BROADCAST_MAC,
        )
    )

    packet = normalize(scapy_packet)

    assert packet.protocol == "arp"
    return packet


def make_arp_request(src_ip: str, src_mac: str) -> NormalizedPacket:
    scapy_packet = (
        Ether(
            src=src_mac,
            dst=BROADCAST_MAC,
        )
        / ARP(
            op=1,
            psrc=src_ip,
            hwsrc=src_mac,
            pdst=TEST_TARGET_IP,
            hwdst=ZERO_MAC,
        )
    )

    packet = normalize(scapy_packet)

    assert packet.protocol == "arp"
    return packet


def test_first_sighting_is_not_flagged():
    detector = ArpSpoofDetector()

    packet = make_arp_reply(
        "192.168.1.10",
        "aa:aa:aa:aa:aa:aa",
    )

    finding = detector.process_packet(packet)

    assert finding is None


def test_same_mac_again_is_not_flagged():
    detector = ArpSpoofDetector()

    packet = make_arp_reply(
        "192.168.1.10",
        "aa:aa:aa:aa:aa:aa",
    )

    detector.process_packet(packet)
    finding = detector.process_packet(packet)

    assert finding is None


def test_mac_change_is_flagged():
    detector = ArpSpoofDetector()

    first = make_arp_reply(
        "192.168.1.10",
        "aa:aa:aa:aa:aa:aa",
    )

    spoofed = make_arp_reply(
        "192.168.1.10",
        "bb:bb:bb:bb:bb:bb",
    )

    detector.process_packet(first)
    finding = detector.process_packet(spoofed)

    assert finding is not None
    assert finding.detector_name == "arp_spoof"
    assert finding.src_ip == "192.168.1.10"
    assert finding.details["old_mac"] == "aa:aa:aa:aa:aa:aa"
    assert finding.details["new_mac"] == "bb:bb:bb:bb:bb:bb"
    assert finding.details["claim_pattern"] == "mapping_change"
    assert "192.168.1.10" in finding.summary


def test_arp_request_is_ignored():
    detector = ArpSpoofDetector()

    request = make_arp_request(
        "192.168.1.10",
        "aa:aa:aa:aa:aa:aa",
    )

    finding = detector.process_packet(request)

    assert finding is None


def test_non_arp_packet_is_ignored():
    detector = ArpSpoofDetector()

    scapy_packet = (
        Ether(
            src="aa:aa:aa:aa:aa:aa",
            dst="bb:bb:bb:bb:bb:bb",
        )
        / IP(
            src="192.168.1.10",
            dst="192.168.1.20",
        )
        / TCP(
            sport=12345,
            dport=80,
        )
    )

    packet = normalize(scapy_packet)

    assert isinstance(packet, NormalizedPacket)
    assert packet.protocol == "tcp"

    finding = detector.process_packet(packet)

    assert finding is None


def test_different_ips_do_not_interfere():
    detector = ArpSpoofDetector()

    detector.process_packet(
        make_arp_reply(
            "192.168.1.10",
            "aa:aa:aa:aa:aa:aa",
        )
    )

    detector.process_packet(
        make_arp_reply(
            "192.168.1.20",
            "cc:cc:cc:cc:cc:cc",
        )
    )

    finding = detector.process_packet(
        make_arp_reply(
            "192.168.1.20",
            "dd:dd:dd:dd:dd:dd",
        )
    )

    assert finding is not None
    assert finding.src_ip == "192.168.1.20"


def test_gratuitous_conflict_has_specific_summary():
    detector = ArpSpoofDetector()
    detector.process_packet(make_arp_reply("192.168.1.10", "aa:aa:aa:aa:aa:aa"))
    finding = detector.process_packet(
        make_arp_reply("192.168.1.10", "bb:bb:bb:bb:bb:bb", "192.168.1.10")
    )
    assert finding.details["claim_pattern"] == "gratuitous_conflict"
    assert "gratuitous" in finding.summary.lower()


def test_reversal_is_reported_as_flapping():
    detector = ArpSpoofDetector()
    detector.process_packet(make_arp_reply("192.168.1.10", "aa:aa:aa:aa:aa:aa"))
    detector.process_packet(make_arp_reply("192.168.1.10", "bb:bb:bb:bb:bb:bb"))
    finding = detector.process_packet(make_arp_reply("192.168.1.10", "aa:aa:aa:aa:aa:aa"))
    assert finding.details["claim_pattern"] == "mac_flapping"
    assert "flapped" in finding.summary


def test_three_macs_are_reported_as_multiple_claimants():
    detector = ArpSpoofDetector()
    detector.process_packet(make_arp_reply("192.168.1.10", "aa:aa:aa:aa:aa:aa"))
    detector.process_packet(make_arp_reply("192.168.1.10", "bb:bb:bb:bb:bb:bb"))
    finding = detector.process_packet(make_arp_reply("192.168.1.10", "cc:cc:cc:cc:cc:cc"))
    assert finding.details["claim_pattern"] == "multiple_claimants"
    assert len(finding.details["distinct_recent_macs"]) == 3


def test_arp_difficulty_profiles_and_nearby_targets():
    assert difficulty_meter("easy") == "[#----] EASY"
    assert difficulty_meter("hard") == "[#####] HARD"
    assert DIFFICULTY_PROFILES["hard"]["scenario"] == "rotating_claimants"
    targets = nearby_targets("192.168.1.87")
    assert targets[0] == "192.168.1.87"
    assert len(targets) == 3


if __name__ == "__main__":
    tests = [
        obj
        for name, obj in list(globals().items())
        if name.startswith("test_")
    ]

    passed = 0

    for test_fn in tests:
        try:
            test_fn()
            print(f"  PASS: {test_fn.__name__}")
            passed += 1
        except AssertionError as exc:
            print(f"  FAIL: {test_fn.__name__} — {exc}")

    print(f"\n{passed}/{len(tests)} passed")
