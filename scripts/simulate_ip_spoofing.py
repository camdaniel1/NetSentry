"""
scripts/simulate_ip_spoofing.py

Sends synthetic source-address anomalies for IP spoofing detector testing.

Usage:
    python -m scripts.simulate_ip_spoofing --target 192.168.1.50 --interface <ip>

Important notes:
    Use only an authorized lab target. Sources are documentation or martian
    addresses and are intended to be observed locally rather than routed.

Optional commands:
    (--count #)
    (--interval seconds)
    (--scenario mixed)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "martian_source"   : use a loopback source on a non-loopback interface
  - "mac_conflict"     : claim one source IP from changing Ethernet MACs
  - "rotating_sources" : rotate through documentation-range source IPs
  - "mixed"            : combine martian and rotating-source indicators

"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

PROFILES = {
    "easy": (3, .1, "martian_source"),
    "medium": (5, .25, "mac_conflict"),
    "hard": (8, .4, "mixed")
}
SCENARIOS = ("martian_source", "mac_conflict", "rotating_sources", "mixed")


def meter(x):
    n = {"easy": 1, "medium": 3, "hard": 5}[x]
    return f"[{'#' * n}{'-' * (5 - n)}] {x.upper()}"


def run(target, iface, count, interval, scenario, difficulty):
    from scapy.all import Ether, IP, UDP, sendp

    print(f"detector test difficulty: {meter(difficulty)}\nscenario: {scenario}")

    for i in range(count):
        src = (
            "127.0.0.2"
            if scenario in {"martian_source", "mixed"} and i % 2 == 0
            else "192.0.2.10"
            if scenario == "mac_conflict"
            else f"192.0.2.{10 + i % 20}"
        )
        mac = f"02:de:ad:be:ef:{i % 4 + 1:02x}"

        sendp(
            Ether(src=mac) / IP(src=src, dst=target) /
            UDP(sport=40000 + i, dport=9999),
            iface=iface,
            verbose=False
        )
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target")
    p.add_argument("--interface")
    p.add_argument("--difficulty", choices=PROFILES, default="medium")
    p.add_argument("--scenario", choices=SCENARIOS)
    p.add_argument("--count", type=int)
    p.add_argument("--interval", type=float)
    p.add_argument("--list-interfaces", action="store_true")
    a = p.parse_args()

    if a.list_interfaces:
        print_interface_err(list_interfaces())
        return 0

    i = find_interface(a.interface or "")
    if not a.target or not i:
        p.error("--target and valid --interface required")

    c, t, s = PROFILES[a.difficulty]
    run(
        a.target,
        i.pcap_name,
        a.count or c,
        a.interval if a.interval is not None else t,
        a.scenario or s,
        a.difficulty
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
