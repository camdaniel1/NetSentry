"""Tests for capture.pcap_writer using temporary classic-PCAP files."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from scapy.all import Ether, IP, TCP, raw

from capture.pcap_writer import PCAP_GLOBAL_HEADER_SIZE, PcapWriter


class StaticVault:
    def __init__(self, path: Path):
        self.path = path

    def get_active_file(self) -> Path:
        return self.path


def packet(payload_size=0):
    scapy_packet = Ether() / IP() / TCP() / (b"x" * payload_size)
    data = raw(scapy_packet)
    return SimpleNamespace(timestamp=1.0, caplen=len(data), data=data, scapy_packet=scapy_packet)


def test_write_returns_exact_locations_for_first_and_later_packets(tmp_path):
    path = tmp_path / "capture.pcap"
    writer = PcapWriter(StaticVault(path))
    first_packet = packet(3)
    second_packet = packet(7)

    first = writer.write(first_packet)
    second = writer.write(second_packet)
    writer.close()

    assert first.file == second.file == str(path)
    assert first.packet_number == 1
    assert second.packet_number == 2
    assert first.offset == PCAP_GLOBAL_HEADER_SIZE
    assert first.len == 16 + len(first_packet.data)
    assert second.offset == first.offset + first.len
    assert second.len == 16 + len(second_packet.data)
    assert path.stat().st_size == PCAP_GLOBAL_HEADER_SIZE + first.len + second.len


def test_writer_switches_files_when_vault_rotates(tmp_path):
    first_path = tmp_path / "one.pcap"
    second_path = tmp_path / "two.pcap"
    vault = StaticVault(first_path)
    writer = PcapWriter(vault)

    first = writer.write(packet())
    vault.path = second_path
    second = writer.write(packet())

    assert first.file == str(first_path)
    assert second.file == str(second_path)
    assert first.packet_number == second.packet_number == 1
    assert second.offset == PCAP_GLOBAL_HEADER_SIZE
    assert writer.current_file == second_path
    writer.close()


def test_close_is_idempotent_and_clears_current_file(tmp_path):
    writer = PcapWriter(StaticVault(tmp_path / "capture.pcap"))
    writer.write(packet())

    writer.close()
    writer.close()

    assert writer.current_file is None


def test_context_manager_closes_writer(tmp_path):
    with PcapWriter(StaticVault(tmp_path / "capture.pcap")) as writer:
        writer.write(packet())
        assert writer.current_file is not None

    assert writer.current_file is None


def test_appending_continues_existing_pcap_packet_numbers(tmp_path):
    path = tmp_path / "capture.pcap"
    first_writer = PcapWriter(StaticVault(path))
    first_writer.write(packet())
    first_writer.close()

    second_writer = PcapWriter(StaticVault(path))
    location = second_writer.write(packet())
    second_writer.close()

    assert location.packet_number == 2


def test_write_raises_if_file_does_not_grow(monkeypatch, tmp_path):
    class FakeScapyWriter:
        def __init__(self, *_args, **_kwargs):
            pass

        def write(self, _packet):
            pass

        def close(self):
            pass

    monkeypatch.setattr("capture.pcap_writer.ScapyPcapWriter", FakeScapyWriter)
    writer = PcapWriter(StaticVault(tmp_path / "capture.pcap"))

    with pytest.raises(IOError, match="did not increase PCAP file size"):
        writer.write(packet())
