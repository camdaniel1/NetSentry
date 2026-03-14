"""Export all captured packets originating from one IP or MAC address."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader, PcapWriter

from evidence.custody import record_custody_event
from evidence.vault import EvidenceVault


EXPORT_DIR = Path(__file__).parent.parent / "data" / "exports"
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@dataclass(frozen=True)
class TrafficExport:
    path: Path
    source: str
    source_type: str
    packet_count: int
    files_scanned: int


def _source_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        if MAC_PATTERN.fullmatch(value):
            return "mac"
    raise ValueError("source must be a valid IPv4, IPv6, or colon-separated MAC address")


def _matches_source(packet, source: str, source_type: str) -> bool:
    if source_type == "mac":
        return packet.haslayer(Ether) and str(packet[Ether].src).lower() == source.lower()
    if packet.haslayer(IP) and str(packet[IP].src) == source:
        return True
    if packet.haslayer(IPv6) and str(packet[IPv6].src) == source:
        return True
    return packet.haslayer(ARP) and str(packet[ARP].psrc) == source


def export_source_traffic(
    source: str,
    *,
    vault: EvidenceVault | None = None,
    output_dir: Path | None = None,
) -> TrafficExport:
    """Write every matching source packet across the PCAP vault to one PCAP."""
    source = source.strip()
    source_type = _source_type(source)
    vault = vault or EvidenceVault()
    vault_files = vault.list_files()
    destination_dir = Path(output_dir or EXPORT_DIR)
    destination_dir.mkdir(parents=True, exist_ok=True)
    safe_source = re.sub(r"[^0-9A-Za-z]+", "_", source).strip("_")
    path = destination_dir / f"traffic_{source_type}_{safe_source}_{int(time.time() * 1000)}.pcap"
    writer = PcapWriter(str(path), sync=True)
    packet_count = 0

    try:
        for vault_file in vault_files:
            reader = PcapReader(str(vault_file.path))
            try:
                for packet in reader:
                    if _matches_source(packet, source, source_type):
                        writer.write(packet)
                        packet_count += 1
            finally:
                reader.close()
    finally:
        writer.close()

    if packet_count == 0:
        path.unlink(missing_ok=True)
        raise LookupError(f"no captured packets found with source {source}")

    record_custody_event(path, "exported", note=f"all traffic from {source_type} source {source}")
    return TrafficExport(
        path=path,
        source=source,
        source_type=source_type,
        packet_count=packet_count,
        files_scanned=len(vault_files),
    )
