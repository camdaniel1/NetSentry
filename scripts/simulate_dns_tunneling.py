"""
scripts/simulate_dns_tunneling.py

Sends synthetic DNS queries that exercise DNS tunneling detection.

Usage:
    python -m scripts.simulate_dns_tunneling --target 192.168.1.1 --interface <ip>

Important notes:
    Use only an authorized DNS destination or isolated lab. The selected
    interface must match the interface monitored by NetSentry.

Optional commands:
    (--count #)
    (--interval seconds)
    (--scenario random)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "encoded_labels"    : send long Base32-like query labels
  - "unique_subdomains" : send many unique subdomains under one base domain
  - "txt_burst"         : send a burst of TXT queries
  - "mixed"             : alternate encoded and ordinary-looking labels
  - "random"            : randomly select one of the above scenarios

"""
from __future__ import annotations

import argparse
import base64
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

PROFILES = {
    "easy": {"count": 25, "interval": .03, "scenario": "encoded_labels"},
    "medium": {"count": 18, "interval": .08, "scenario": "unique_subdomains"},
    "hard": {"count": 13, "interval": .15, "scenario": "mixed"},
}
SCENARIOS = ("encoded_labels", "unique_subdomains", "txt_burst", "mixed", "random")


def difficulty_meter(level):
    n = {"easy": 1, "medium": 3, "hard": 5}[level]
    return f"[{'#' * n}{'-' * (5 - n)}] {level.upper()}"


def query_name(index, scenario):
    encoded = base64.b32encode(
        f"netsentry-lab-payload-{index:04d}".encode()
    ).decode().lower().rstrip("=")

    if scenario == "encoded_labels":
        return f"{encoded}{encoded}.tunnel.test"
    if scenario == "unique_subdomains":
        return f"session-{index:04d}-{random.randrange(1_000_000):06d}.tunnel.test"
    if scenario == "txt_burst":
        return f"txt-{index:04d}.tunnel.test"

    return f"{encoded if index % 2 else f'chunk-{index:04d}'}.tunnel.test"


def run(target, interface, count, interval, scenario, difficulty):
    from scapy.all import DNS, DNSQR, Ether, IP, UDP, sendp

    if scenario == "random":
        scenario = random.choice(SCENARIOS[:-1])

    print(
        f"interface: {interface}\n"
        f"detector test difficulty: {difficulty_meter(difficulty)}\n"
        f"scenario: {scenario}"
    )

    for index in range(count):
        qtype = "TXT" if scenario == "txt_burst" else "A"
        name = query_name(index, scenario)

        packet = (
            Ether() /
            IP(dst=target) /
            UDP(sport=random.randint(20000, 65000), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))
        )

        sendp(packet, iface=interface, verbose=False)
        print(f"  DNS {qtype} -> {name} ({index + 1}/{count})")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Simulate DNS tunneling indicators in an authorized lab"
    )
    parser.add_argument("--target", help="authorized DNS server/test destination IP")
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

    profile = PROFILES[args.difficulty]
    run(
        args.target,
        info.pcap_name,
        args.count or profile["count"],
        args.interval if args.interval is not None else profile["interval"],
        args.scenario or profile["scenario"],
        args.difficulty
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
