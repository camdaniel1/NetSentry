"""
capture/sniffer.py

This file is used to capture network packets using scapy. Each Sniffer object
stores an interface, bpf_filter, and a packet queue.

Packets can be fetched using sniffer.packet_queue.get() and then passed to
a writer object.

If packet capture fails it may be due to improper interruption of the service.
You can fix this by terminating the process and restarting it.

For macOS/Linux users:
  - libpcap must be installed (usually already present, or:
    `sudo apt install libpcap-dev` on Linux / `brew install libpcap` on macOS)
  - run with sudo, or grant the interpreter capture permissions:
    `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`

For Windows users:
  - install Npcap from https://npcap.com
  - during setup, check "Install Npcap in WinPcap API-compatible Mode"
  - run your terminal/IDE as Administrator when capturing
"""

from __future__ import annotations

import queue
from dataclasses import dataclass
from typing import Optional

from scapy.all import Packet as ScapyPacket
from scapy.all import AsyncSniffer, raw
from settings import setting

DEFAULT_BPF_FILTER = str(setting("capture.bpf_filter"))
DEFAULT_QUEUE_SIZE = int(setting("capture.queue_size"))


@dataclass
class RawPacket:
    timestamp: float        # seconds since epoch
    caplen: int              # bytes captured
    length: int               # original length on the wire
    data: bytes                # raw packet bytes
    scapy_packet: ScapyPacket   # parsed Scapy packet


class Sniffer:
    """
    Captures packets using Scapy and pushes each to a bounded queue. Capture runs on
    Scapy's background thread (AsyncSniffer) so it doesn't block the caller
    """

    def __init__(self, interface: str, bpf_filter: str = DEFAULT_BPF_FILTER,
                 queue_maxsize: int = DEFAULT_QUEUE_SIZE) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_queue: "queue.Queue[RawPacket]" = queue.Queue(maxsize=queue_maxsize)

        self._sniffer: Optional[AsyncSniffer] = None

    # -- lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Starts capture thread on the configured interface."""
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self._on_captured,
            store=False,  # storage is handled separately
        )
        self._sniffer.start()

    def stop(self) -> None:
        """Stops the background capture thread."""
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

    def __enter__(self) -> "Sniffer":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # -- internals ------------------------------------------------------

    def _on_captured(self, pkt: ScapyPacket) -> None:
        """Scapy calls this once per captured packet."""
        raw_bytes = raw(pkt)
        packet = RawPacket(
            timestamp=float(pkt.time),
            caplen=len(raw_bytes),
            length=len(raw_bytes),
            data=raw_bytes,
            scapy_packet=pkt,
        )
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # drop rather than block capture
            pass
