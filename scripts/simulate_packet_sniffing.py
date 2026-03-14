"""
scripts/simulate_packet_sniffing.py

Sends observable promiscuous-mode probe-response indicators.

Usage:
    python -m scripts.simulate_packet_sniffing --target 192.168.1.50 --interface <ip>

Important notes:
    Passive packet sniffers are silent and cannot be reliably detected from
    traffic alone. This script tests only the observable probe-response signal.

Optional commands:
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "promiscuous_probe_response": emit ICMP replies using the detector's
                                   synthetic multicast probe MAC

"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

PROFILES = {
    "easy": (4, .1),
    "medium": (3, .3),
    "hard": (2, .6)
}


def meter(x):
    n = {"easy": 1, "medium": 3, "hard": 5}[x]
    return f"[{'#' * n}{'-' * (5 - n)}] {x.upper()}"


def run(target, iface, count, interval, difficulty):
    from scapy.all import Ether, ICMP, IP, sendp

    print(
        f"detector test difficulty: {meter(difficulty)}\n"
        f"indicator: promiscuous_probe_response"
    )

    for i in range(count):
        sendp(
            Ether(dst="01:00:5e:00:00:01") /
            IP(src=target, dst="192.0.2.1") /
            ICMP(type=0, id=31337, seq=i),
            iface=iface,
            verbose=False
        )
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(
        description="This tests an observable indicator; passive sniffers cannot be reliably detected"
    )
    p.add_argument("--target", help="synthetic responding host IP")
    p.add_argument("--interface")
    p.add_argument("--difficulty", choices=PROFILES, default="medium")
    p.add_argument("--list-interfaces", action="store_true")
    a = p.parse_args()

    if a.list_interfaces:
        print_interface_err(list_interfaces())
        return 0

    i = find_interface(a.interface or "")
    if not a.target or not i:
        p.error("--target and valid --interface required")

    c, t = PROFILES[a.difficulty]
    run(a.target, i.pcap_name, c, t, a.difficulty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
