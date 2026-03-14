from capture.packet_normalizer import NormalizedPacket
from correlation.severity import Severity, score
from detectors.base import Finding
from detectors.evil_twin import EvilTwinDetector
from detectors.icmp_flood import IcmpFloodDetector
from detectors.ip_spoofing import IpSpoofingDetector
from detectors.packet_sniffing import PacketSniffingDetector
from detectors.udp_flood import UdpFloodDetector
from scripts.simulate_icmp_flood import PROFILES as ICMP_PROFILES
from scripts.simulate_udp_flood import PROFILES as UDP_PROFILES

def packet(t, protocols, fields, src="192.0.2.10", dst="192.0.2.20", caplen=60):
    return NormalizedPacket(t,caplen,caplen,src,dst,protocols[-1],"test",protocols,fields)

def test_icmp_flood_detection():
    detector=IcmpFloodDetector(threshold=3)
    for t in (1,2): assert detector.process_packet(packet(t,("ip","icmp"),{"ip":{"src":"192.0.2.10","dst":"192.0.2.20"},"icmp":{"type":8}})) is None
    finding=detector.process_packet(packet(3,("ip","icmp"),{"ip":{"src":"192.0.2.10","dst":"192.0.2.20"},"icmp":{"type":8}}))
    assert finding.details["packet_count"]==3

def test_udp_flood_detection():
    detector=UdpFloodDetector(threshold=3)
    for t in (1,2): assert detector.process_packet(packet(t,("ip","udp"),{"ip":{"src":"192.0.2.10","dst":"192.0.2.20"},"udp":{"dport":9999}})) is None
    finding=detector.process_packet(packet(3,("ip","udp"),{"ip":{"src":"192.0.2.10","dst":"192.0.2.20"},"udp":{"dport":9999}}))
    assert finding.details["destination_port"]==9999

def test_ip_spoofing_martian_and_mac_conflict():
    detector=IpSpoofingDetector()
    martian=packet(1,("ether","ip"),{"ether":{"src":"02:00:00:00:00:01"},"ip":{"src":"127.0.0.2","dst":"192.0.2.20"}},"127.0.0.2")
    assert detector.process_packet(martian).details["spoof_pattern"]=="martian_source"
    normal=lambda t,mac: packet(t,("ether","ip"),{"ether":{"src":mac},"ip":{"src":"192.0.2.10","dst":"192.0.2.20"}})
    assert detector.process_packet(normal(2,"02:00:00:00:00:01")) is None
    assert detector.process_packet(normal(3,"02:00:00:00:00:02")).details["spoof_pattern"]=="layer2_identity_conflict"

def test_promiscuous_probe_response_indicator():
    detector=PacketSniffingDetector()
    finding=detector.process_packet(packet(1,("ether","ip","icmp"),{
        "ether":{"dst":"01:00:5e:00:00:01"},"ip":{"src":"192.0.2.10","dst":"192.0.2.1"},"icmp":{"type":0}}))
    assert finding.details["sniffing_indicator"]=="promiscuous_probe_response"

def test_evil_twin_duplicate_ssid_detection():
    detector=EvilTwinDetector()
    def beacon(t,bssid): return packet(t,("radiotap","dot11","dot11beacon","dot11elt"),{
        "dot11":{"addr2":bssid,"addr3":bssid},"dot11elt":{"ID":0,"info":b"LabWifi"}})
    assert detector.process_packet(beacon(1,"02:00:00:00:00:01")) is None
    finding=detector.process_packet(beacon(2,"02:de:ad:be:ef:01"))
    assert finding.details["ssid"]=="LabWifi"

def test_severity_and_profiles():
    assert score(Finding("evil_twin",1))==Severity.critical
    assert score(Finding("icmp_flood",1,details={"packet_rate":300}))==Severity.high
    assert min(v[0] for v in ICMP_PROFILES.values())>=100
    assert min(v[0] for v in UDP_PROFILES.values())>=150
