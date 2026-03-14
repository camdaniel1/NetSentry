from capture.packet_normalizer import NormalizedPacket
from detectors.port_scan import PortScanDetector
from scripts.simulate_port_scan import DIFFICULTY_PROFILES, difficulty_meter


def packet(timestamp, dst_port, dst_ip="192.0.2.50", flags="S"):
    return NormalizedPacket(
        timestamp=timestamp, caplen=60, length=60,
        src="192.0.2.10", dst=dst_ip, protocol="tcp", info="TCP SYN",
        protocols=("ip", "tcp"),
        fields={
            "ip": {"src": "192.0.2.10", "dst": dst_ip},
            "tcp": {"dport": dst_port, "flags": flags},
        },
    )


def test_detects_vertical_scan_of_distinct_ports():
    detector = PortScanDetector(port_threshold=4, window_seconds=10)
    assert detector.process_packet(packet(1, 20)) is None
    assert detector.process_packet(packet(2, 21)) is None
    assert detector.process_packet(packet(3, 22)) is None
    finding = detector.process_packet(packet(4, 23))
    assert finding is not None
    assert finding.details["scan_type"] == "vertical"
    assert finding.details["scan_pattern"] == "sequential"
    assert finding.details["port_count"] == 4
    assert "ports 20–23" in finding.summary


def test_duplicate_ports_and_syn_ack_do_not_trigger_vertical_scan():
    detector = PortScanDetector(port_threshold=3, window_seconds=10)
    assert detector.process_packet(packet(1, 80)) is None
    assert detector.process_packet(packet(2, 80)) is None
    assert detector.process_packet(packet(3, 81, flags="SA")) is None
    assert detector.process_packet(packet(4, 81)) is None


def test_detects_horizontal_sweep_of_same_port_across_hosts():
    detector = PortScanDetector(
        port_threshold=99, host_threshold=3, web_host_threshold=3, window_seconds=10
    )
    assert detector.process_packet(packet(1, 22, "192.0.2.20")) is None
    assert detector.process_packet(packet(2, 22, "192.0.2.21")) is None
    finding = detector.process_packet(packet(3, 22, "192.0.2.22"))
    assert finding is not None
    assert finding.details["scan_type"] == "horizontal"
    assert finding.details["host_count"] == 3
    assert "TCP/22" in finding.summary
    assert "192.0.2.20" in finding.summary


def test_https_connections_to_different_cdn_subnets_are_not_a_horizontal_scan():
    detector = PortScanDetector(
        port_threshold=99, host_threshold=3, web_host_threshold=3, window_seconds=10
    )
    destinations = ("142.251.153.119", "142.251.154.119", "142.251.155.119")
    for timestamp, destination in enumerate(destinations, start=1):
        assert detector.process_packet(packet(timestamp, 443, destination)) is None


def test_random_ports_get_an_evidence_specific_summary():
    detector = PortScanDetector(port_threshold=4, window_seconds=10)
    for timestamp, port in enumerate((81, 443, 2048), start=1):
        assert detector.process_packet(packet(timestamp, port)) is None
    finding = detector.process_packet(packet(4, 49152))
    assert finding.details["scan_pattern"] == "distributed"
    assert "81, 443, 2048, 49152" in finding.summary


def test_difficulty_profiles_remain_above_default_detector_threshold():
    assert all(profile["count"] >= 15 for profile in DIFFICULTY_PROFILES.values())
    assert difficulty_meter("easy") == "[#----] EASY"
    assert difficulty_meter("hard") == "[#####] HARD"
