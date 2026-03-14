"""Tests for exporting complete source traffic from the PCAP evidence vault."""

from pathlib import Path

import pytest
from scapy.all import ARP, Ether, IP, IPv6, TCP, PcapReader, wrpcap

from correlation.traffic_export import export_source_traffic
from evidence.vault import EvidenceVault


def _write_vault(vault_dir: Path) -> EvidenceVault:
    vault_dir.mkdir()
    wrpcap(
        str(vault_dir / "capture_1000.pcap"),
        [
            Ether(src="00:11:22:33:44:55") / IP(src="192.0.2.10", dst="198.51.100.1") / TCP(),
            Ether(src="00:11:22:33:44:55") / IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(),
            Ether(src="aa:bb:cc:dd:ee:ff") / ARP(psrc="192.0.2.10", pdst="192.0.2.1"),
            Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="203.0.113.5", dst="198.51.100.1") / TCP(),
        ],
    )
    return EvidenceVault(vault_dir)


def _packets(path: Path):
    with PcapReader(str(path)) as reader:
        return list(reader)


def test_exports_all_ip_source_packets_across_protocols(monkeypatch, tmp_path):
    vault = _write_vault(tmp_path / "vault")
    monkeypatch.setattr("correlation.traffic_export.record_custody_event", lambda *_args, **_kwargs: None)

    result = export_source_traffic("192.0.2.10", vault=vault, output_dir=tmp_path / "exports")

    assert result.source_type == "ip"
    assert result.packet_count == 2
    assert result.files_scanned == 1
    assert len(_packets(result.path)) == 2


def test_exports_all_mac_source_packets(monkeypatch, tmp_path):
    vault = _write_vault(tmp_path / "vault")
    monkeypatch.setattr("correlation.traffic_export.record_custody_event", lambda *_args, **_kwargs: None)

    result = export_source_traffic("AA:BB:CC:DD:EE:FF", vault=vault, output_dir=tmp_path / "exports")

    assert result.source_type == "mac"
    assert result.packet_count == 2
    assert all(packet[Ether].src == "aa:bb:cc:dd:ee:ff" for packet in _packets(result.path))


def test_rejects_invalid_source_without_creating_an_export(tmp_path):
    output_dir = tmp_path / "exports"

    with pytest.raises(ValueError, match="valid IPv4, IPv6"):
        export_source_traffic("not-an-address", vault=EvidenceVault(tmp_path / "vault"), output_dir=output_dir)

    assert not output_dir.exists()


def test_removes_empty_export_when_no_packets_match(tmp_path):
    vault = _write_vault(tmp_path / "vault")
    output_dir = tmp_path / "exports"

    with pytest.raises(LookupError, match="no captured packets"):
        export_source_traffic("192.0.2.99", vault=vault, output_dir=output_dir)

    assert list(output_dir.iterdir()) == []
