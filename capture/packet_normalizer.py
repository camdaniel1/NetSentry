"""Turn any Scapy-backed packet into one generic detector-facing model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scapy.packet import NoPayload
from scapy.packet import Packet as ScapyPacket

from capture.sniffer import RawPacket


@dataclass(slots=True)
class NormalizedPacket:
    """Protocol-agnostic packet data with fields grouped by Scapy layer."""

    timestamp: float
    caplen: int
    length: int
    src: str
    dst: str
    protocol: str
    info: str
    protocols: tuple[str, ...]
    fields: dict[str, dict[str, Any]] = field(default_factory=dict)

    def has_protocol(self, protocol: str) -> bool:
        return protocol.lower() in self.protocols

    def get(self, protocol: str, field_name: str, default: Any = None) -> Any:
        """Read a field without exposing Scapy objects to detectors."""
        return self.fields.get(protocol.lower(), {}).get(field_name, default)


def _plain_value(value: Any) -> Any:
    """Convert Scapy field values into plain Python data."""
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, ScapyPacket):
        return {
            descriptor.name: _plain_value(value.getfieldval(descriptor.name))
            for descriptor in value.fields_desc
        }
    if isinstance(value, (list, tuple)):
        return tuple(_plain_value(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _plain_value(item) for key, item in value.items()}
    return str(value)


def normalize_packet(packet: RawPacket) -> NormalizedPacket:
    """Normalize all layers generically; new protocols require no parser changes."""
    protocols: list[str] = []
    fields: dict[str, dict[str, Any]] = {}
    src = ""
    dst = ""
    layer = packet.scapy_packet

    while not isinstance(layer, NoPayload):
        protocol = layer.__class__.__name__.lower()
        protocols.append(protocol)
        # fields_desc includes protocol defaults as well as explicitly set
        # values, so required endpoints are not lost when Scapy supplies them.
        layer_fields = {
            descriptor.name: _plain_value(layer.getfieldval(descriptor.name))
            for descriptor in layer.fields_desc
        }
        fields[protocol] = layer_fields

        # Prefer network endpoints (including ARP protocol addresses) over
        # link-layer addresses while remaining independent of layer types.
        layer_src = next(
            (layer_fields[name] for name in ("psrc", "src", "hwsrc") if layer_fields.get(name) not in (None, "")),
            None,
        )
        layer_dst = next(
            (layer_fields[name] for name in ("pdst", "dst", "hwdst") if layer_fields.get(name) not in (None, "")),
            None,
        )
        if layer_src is not None:
            src = str(layer_src)
        if layer_dst is not None:
            dst = str(layer_dst)
        layer = layer.payload

    meaningful = [name for name in protocols if name not in {"ether", "raw", "padding"}]
    protocol = meaningful[-1] if meaningful else (protocols[-1] if protocols else "unknown")

    return NormalizedPacket(
        timestamp=packet.timestamp,
        caplen=packet.caplen,
        length=packet.length,
        src=src,
        dst=dst,
        protocol=protocol,
        info=str(packet.scapy_packet.summary()),
        protocols=tuple(protocols),
        fields=fields,
    )
