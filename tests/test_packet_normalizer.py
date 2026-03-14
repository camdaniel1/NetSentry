"""Tests for generic packet normalization across arbitrary Scapy layers."""

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, TCP, UDP, Raw, raw

from capture.packet_normalizer import NormalizedPacket, normalize_packet
from capture.sniffer import RawPacket


def wrapped(packet, timestamp=123.5):
    payload = raw(packet)
    return RawPacket(timestamp, len(payload), len(payload), payload, packet)


def test_normalize_packet_collects_layer_stack_and_fields():
    packet = Ether(src="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2", ttl=31) / TCP(
        sport=12345, dport=443, flags="SA"
    )

    normalized = normalize_packet(wrapped(packet))

    assert isinstance(normalized, NormalizedPacket)
    assert normalized.protocol == "tcp"
    assert normalized.src == "192.0.2.1"
    assert normalized.dst == "198.51.100.2"
    assert "TCP" in normalized.info
    assert normalized.protocols == ("ether", "ip", "tcp")
    assert normalized.get("ether", "src") == "00:11:22:33:44:55"
    assert normalized.get("ip", "src") == "192.0.2.1"
    assert normalized.get("ip", "ttl") == 31
    assert normalized.get("tcp", "sport") == 12345
    assert str(normalized.get("tcp", "flags")) == "SA"
    assert normalized.timestamp == 123.5


def test_normalize_packet_is_protocol_agnostic():
    normalized = normalize_packet(wrapped(
        IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=42) / UDP(sport=53, dport=53000)
    ))

    assert normalized.protocol == "udp"
    assert normalized.src == "2001:db8::1"
    assert normalized.dst == "2001:db8::2"
    assert normalized.has_protocol("IPv6")
    assert normalized.get("ipv6", "src") == "2001:db8::1"
    assert normalized.get("udp", "sport") == 53


def test_dns_fields_are_retained_without_dns_specific_model():
    packet = IP() / UDP() / DNS(
        id=77, qr=0, qdcount=1, qd=DNSQR(qname=b"example.test.", qtype="AAAA")
    )

    normalized = normalize_packet(wrapped(packet))

    assert normalized.protocol == "dns"
    assert normalized.get("dns", "id") == 77
    assert normalized.get("dns", "qr") == 0
    assert "qd" in normalized.fields["dns"]


def test_icmp_and_arp_require_no_normalizer_branches():
    icmp = normalize_packet(wrapped(IP() / ICMP(type=3, code=1)))
    arp = normalize_packet(wrapped(Ether() / ARP(
        op=2,
        psrc="192.0.2.1",
        hwsrc="00:11:22:33:44:55",
    )))

    assert icmp.protocol == "icmp"
    assert icmp.get("icmp", "type") == 3
    assert arp.protocol == "arp"
    assert arp.src == "192.0.2.1"
    assert arp.get("arp", "op") == 2
    assert arp.get("arp", "psrc") == "192.0.2.1"


def test_raw_payload_is_preserved_but_not_selected_as_primary_protocol():
    normalized = normalize_packet(wrapped(Ether() / IP() / UDP() / Raw(b"payload")))

    assert normalized.protocol == "udp"
    assert normalized.get("raw", "load") == b"payload"


def test_get_returns_default_for_absent_field():
    normalized = normalize_packet(wrapped(Ether()))

    assert normalized.get("tcp", "sport") is None
    assert normalized.get("tcp", "sport", 0) == 0
