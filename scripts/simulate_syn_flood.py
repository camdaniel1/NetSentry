"""
scripts/simulate_syn_flood.py

Sends a bounded burst of TCP SYN packets for flood-detector testing.

Usage:
    python -m scripts.simulate_syn_flood --target 192.168.1.50 --interface <ip>

Important notes:
    Use only a host you own or are authorized to test. The default destination
    port is 8080, and the selected interface must match NetSentry's interface.

Optional commands:
    (--port #)
    (--count #)
    (--interval seconds)
    (--scenario random)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "single_source"       : reuse one synthetic source and source port
  - "rotating_ports"      : vary the TCP source port for each SYN
  - "distributed_sources" : rotate through multiple synthetic source IPs
  - "mixed"               : vary both source IPs and source ports
  - "random"              : randomly select one of the above scenarios

"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

PROFILES = {
    "easy": {"count": 140, "interval": .005, "scenario": "single_source"},
    "medium": {"count": 120, "interval": .015, "scenario": "rotating_ports"},
    "hard": {"count": 105, "interval": .025, "scenario": "distributed_sources"},
}
SCENARIOS = ("single_source", "rotating_ports", "distributed_sources", "mixed", "random")


def difficulty_meter(level):
    n = {"easy": 1, "medium": 3, "hard": 5}[level]
    return f"[{'#' * n}{'-' * (5 - n)}] {level.upper()}"


def run(target, port, interface, count, interval, scenario, difficulty):
    from scapy.all import Ether, IP, TCP, sendp

    if scenario == "random":
        scenario = random.choice(SCENARIOS[:-1])

    print(
        f"interface: {interface}\n"
        f"detector test difficulty: {difficulty_meter(difficulty)}\n"
        f"scenario: {scenario}"
    )

    for index in range(count):
        source = "192.0.2.10"
        sport = 40000

        if scenario in {"rotating_ports", "mixed"}:
            sport = 20000 + index
        if scenario in {"distributed_sources", "mixed"}:
            source = f"192.0.2.{10 + index % 20}"

        sendp(
            Ether() / IP(src=source, dst=target) /
            TCP(sport=sport, dport=port, flags="S"),
            iface=interface,
            verbose=False
        )

        if index % 10 == 0 or index + 1 == count:
            print(f"  SYN -> {target}:{port} ({index + 1}/{count})")

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Simulate a bounded SYN flood in an authorized lab"
    )
    parser.add_argument("--target")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--interface")
    parser.add_argument("--difficulty", choices=PROFILES, default="medium")
    parser.add_argument("--scenario", choices=SCENARIOS)
    parser.add_argument("--count", type=int)
    parser.add_argument("--interval", type=float)
    parser.add_argument("--list-interfaces", action="store_true")
    args = parser.parse_args()

    if args.list_interfaces:
        print_interface_err(list_interfaces())
        return 0

    info = find_interface(args.interface or "")
    if not args.target or not info:
        parser.error("--target and a valid --interface are required")

    p = PROFILES[args.difficulty]
    run(
        args.target, args.port, info.pcap_name,
        args.count or p["count"],
        args.interval if args.interval is not None else p["interval"],
        args.scenario or p["scenario"],
        args.difficulty
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
