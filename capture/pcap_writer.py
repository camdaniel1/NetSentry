"""
capture/pcap_writer.py

This file is used to write scapy packets one at a time to a PCAP file.

This file handles the current PCAP file write location at current_file().
Once a scapy packet has been recieved, it just needs to be passed to the
write() function on this object in order to be written.

The PcapWriter object class stores a writer, path, and threading lock.

Each write returns a PcapLocation containing:
    - pcap_file: path to the PCAP file
    - pcap_offset: byte offset of the packet's PCAP record header
    - pcap_length: total bytes occupied by that PCAP record
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from scapy.packet import Packet as ScapyPacket
from scapy.utils import PcapReader, PcapWriter as ScapyPcapWriter

from evidence.vault import EvidenceVault


PCAP_GLOBAL_HEADER_SIZE = 24


class PacketLike(Protocol):
    timestamp: float
    caplen: int
    data: bytes
    scapy_packet: ScapyPacket


@dataclass(frozen=True)
class PcapLocation:
    file: str
    offset: int
    len: int
    packet_number: int


class PcapWriter:

    def __init__(self, vault: Optional[EvidenceVault] = None) -> None:
        self.vault = vault or EvidenceVault()

        self._writer: Optional[ScapyPcapWriter] = None
        self._current_path: Optional[Path] = None
        self._packet_number = 0
        self._lock = threading.Lock()

    @property
    def current_file(self) -> Optional[Path]:
        return self._current_path

    def write(self, packet: PacketLike) -> PcapLocation:
        """
        Write one RawPacket and return its exact location in the PCAP file.
        """
        with self._lock:
            active_path = self.vault.get_active_file()

            if self._writer is None or active_path != self._current_path:
                self._open(active_path)

            assert self._writer is not None
            assert self._current_path is not None

            size_before = self._file_size()
            self._writer.write(packet.scapy_packet)
            size_after = self._file_size()

            # The first packet also causes Scapy to emit the 24-byte global
            # PCAP header. That header is file metadata, not part of the packet.
            if size_before == 0:
                packet_offset = PCAP_GLOBAL_HEADER_SIZE
                packet_length = size_after - PCAP_GLOBAL_HEADER_SIZE
            else:
                packet_offset = size_before
                packet_length = size_after - size_before

            if packet_length <= 0:
                raise IOError(f"packet write did not increase PCAP file size: {self._current_path}")

            self._packet_number += 1
            return PcapLocation(
                file=str(self._current_path),
                offset=packet_offset,
                len=packet_length,
                packet_number=self._packet_number,
            )

    def close(self) -> None:
        with self._lock:
            self._close_current()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    def _open(self, path: Path) -> None:
        self._close_current()
        self._current_path = path
        self._packet_number = self._count_existing_packets(path)
        self._writer = ScapyPcapWriter(str(path), append=path.exists(), sync=True)

    def _close_current(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._writer = None
        self._current_path = None

    def _file_size(self) -> int:
        if self._current_path is None:
            return 0
        try:
            return os.path.getsize(self._current_path)
        except FileNotFoundError:
            return 0

    @staticmethod
    def _count_existing_packets(path: Path) -> int:
        if not path.exists() or path.stat().st_size == 0:
            return 0
        reader = PcapReader(str(path))
        try:
            return sum(1 for _ in reader)
        finally:
            reader.close()
