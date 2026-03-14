from capture.packet_normalizer import NormalizedPacket
from correlation.severity import Severity, score
from detectors.base import Finding
from detectors.dns_tunneling import DnsTunnelingDetector
from detectors.rogue_dhcp import RogueDhcpDetector
from detectors.syn_flood import SynFloodDetector
from scripts.simulate_dns_tunneling import PROFILES as DNS_PROFILES
from scripts.simulate_rogue_dhcp import PROFILES as DHCP_PROFILES
from scripts.simulate_syn_flood import PROFILES as SYN_PROFILES


def normalized(timestamp, protocols, fields, src="192.0.2.10", dst="192.0.2.53"):
    return NormalizedPacket(timestamp, 60, 60, src, dst, protocols[-1], "test", protocols, fields)


def dns_packet(timestamp, name):
    return normalized(timestamp, ("ip", "udp", "dns", "dnsqr"), {
        "ip": {"src": "192.0.2.10", "dst": "192.0.2.53"},
        "dns": {"qr": 0}, "dnsqr": {"qname": name},
    })


def syn_packet(timestamp, source="192.0.2.10", flags="S"):
    return normalized(timestamp, ("ip", "tcp"), {
        "ip": {"src": source, "dst": "192.0.2.80"},
        "tcp": {"sport": 20000 + int(timestamp), "dport": 443, "flags": flags},
    }, source, "192.0.2.80")


def dhcp_packet(timestamp, server_ip, server_mac, message="offer"):
    return normalized(timestamp, ("ether", "ip", "udp", "bootp", "dhcp"), {
        "ether": {"src": server_mac}, "ip": {"src": server_ip, "dst": "255.255.255.255"},
        "dhcp": {"options": (("message-type", message), ("server_id", server_ip), "end")},
    }, server_ip, "255.255.255.255")


def test_dns_encoded_label_and_query_variation_detection():
    detector = DnsTunnelingDetector(query_threshold=3, long_label=20, entropy_threshold=3.0)
    encoded = detector.process_packet(dns_packet(1, "abcdefghijklmnopqrstuvwxyz234567.tunnel.test"))
    assert encoded.details["tunnel_pattern"] == "encoded_label"
    varied = DnsTunnelingDetector(query_threshold=3, long_label=100)
    assert varied.process_packet(dns_packet(1, "abcdefghijkl01.tunnel.test")) is None
    assert varied.process_packet(dns_packet(2, "bcdefghijklm02.tunnel.test")) is None
    assert varied.process_packet(dns_packet(3, "cdefghijklmn03.tunnel.test")).details["unique_queries"] == 3


def test_dns_ignores_google_and_local_device_discovery_names():
    detector = DnsTunnelingDetector(query_threshold=1, long_label=5, entropy_threshold=1)
    assert detector.process_packet(dns_packet(1, "speaker._googlecast._tcp.local")) is None
    assert detector.process_packet(dns_packet(2, "long-random-device-id.clients4.google.com")) is None


def test_syn_flood_counts_syn_only_and_describes_distribution():
    detector = SynFloodDetector(syn_threshold=3, window_seconds=5)
    assert detector.process_packet(syn_packet(1, flags="SA")) is None
    assert detector.process_packet(syn_packet(1, "192.0.2.10")) is None
    assert detector.process_packet(syn_packet(2, "192.0.2.11")) is None
    finding = detector.process_packet(syn_packet(3, "192.0.2.12"))
    assert finding.details["syn_count"] == 3
    assert "SYN flood" in finding.summary


def test_rogue_dhcp_detects_competing_and_configured_unauthorized_server():
    detector = RogueDhcpDetector()
    assert detector.process_packet(dhcp_packet(1, "192.0.2.1", "02:00:00:00:00:01")) is None
    finding = detector.process_packet(dhcp_packet(2, "192.0.2.200", "02:de:ad:be:ef:01"))
    assert finding.details["dhcp_pattern"] == "competing_server"
    trusted = RogueDhcpDetector(trusted_server_ips={"192.0.2.1"})
    assert trusted.process_packet(dhcp_packet(1, "192.0.2.1", "02:00:00:00:00:01")) is None
    assert trusted.process_packet(dhcp_packet(2, "192.0.2.201", "02:de:ad:be:ef:02")) is not None


def test_new_severity_rules():
    assert score(Finding("dns_tunneling", 1, details={"tunnel_pattern": "encoded_label"})) == Severity.high
    assert score(Finding("syn_flood", 1, details={"syn_rate": 600})) == Severity.critical
    assert score(Finding("rogue_dhcp", 1, details={"message_type": "ack"})) == Severity.critical


def test_simulation_profiles_cross_detector_thresholds():
    assert all(profile["count"] >= 12 for profile in DNS_PROFILES.values())
    assert all(profile["count"] >= 100 for profile in SYN_PROFILES.values())
    assert DHCP_PROFILES["hard"]["scenario"] == "multiple_servers"
