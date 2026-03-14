"""
This class contains ease of use interface operations.

List available interfaces, find an interface based on string name/ip,
print an interface related run error.

"""

from dataclasses import dataclass


from typing import List

from scapy.all import IFACES


@dataclass
class InterfaceInfo:
    index: int
    human_name: str
    sys_name: str
    pcap_name: str
    ip_addr: str


def list_interfaces() -> List[InterfaceInfo]:
    """
    Enumerates capturable interfaces on the current OS via Scapy.
    """
    interfaces: List[InterfaceInfo] = []
    for iface_name in IFACES.data:
        iface = IFACES.data[iface_name]

        interfaces.append(InterfaceInfo(
            index=iface.index,
            human_name=iface.description,
            pcap_name=iface.network_name,
            sys_name=iface.name,
            ip_addr=iface.ip
        ))

    return interfaces


def find_interface(value: str) -> InterfaceInfo | None:
    """Find an interface by IP, PCAP name, system name, or human-readable name."""
    return next(
        (
            info
            for info in list_interfaces()
            if value
            in {
                info.ip_addr,
                info.pcap_name,
                info.sys_name,
                info.human_name,
            }
        ),
        None,
    )


def interface_payload(info: InterfaceInfo) -> dict[str, object]:
    """Return the stable, JSON-safe interface shape used by the dashboard."""
    return {
        "index": info.index,
        "human_name": info.human_name,
        "sys_name": info.sys_name,
        "pcap_name": info.pcap_name,
        "ip_addr": info.ip_addr,
    }


def print_interface_err(interfaces: List[InterfaceInfo]) -> None:
    for info in interfaces:
        print(f"  NAME: \'{info.human_name}\'")
        print(f"  PCAP: \'{info.pcap_name}\'")
        print(f"  IP: \'{info.ip_addr or "no IP"}\'\n")
    print("rerun as: python -m core.pipeline <name | pcap_name | ip>")
