"""
scripts/simulate_icmp_flood.py

Sends a bounded burst of ICMP echo requests for flood-detector testing.

Usage:
    python -m scripts.simulate_icmp_flood --target 192.168.1.50 --interface <ip>

Important notes:
    Use only a host you own or are authorized to test. The selected interface
    must match the interface monitored by NetSentry.

Optional commands:
    (--count #)
    (--interval seconds)
    (--scenario random)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "single_source"       : reuse one synthetic source address
  - "varying_ids"         : vary ICMP identifiers across the burst
  - "distributed_sources" : rotate through multiple synthetic source IPs
  - "mixed"               : vary both source addresses and ICMP identifiers
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
    "easy": (140, .005, "single_source"),
    "medium": (120, .015, "varying_ids"),
    "hard": (105, .025, "distributed_sources")
}
SCENARIOS = ("single_source", "varying_ids", "distributed_sources", "mixed", "random")


def meter(x):
    n = {"easy": 1, "medium": 3, "hard": 5}[x]
    return f"[{'#' * n}{'-' * (5 - n)}] {x.upper()}"


def run(target, iface, count, interval, scenario, difficulty):
    from scapy.all import Ether, ICMP, IP, sendp

    if scenario == "random":
        scenario = random.choice(SCENARIOS[:-1])

    print(f"detector test difficulty: {meter(difficulty)}\nscenario: {scenario}")

    for i in range(count):
        src = f"192.0.2.{10 + i % 20}" if scenario in {"distributed_sources", "mixed"} else "192.0.2.10"
        ident = i if scenario in {"varying_ids", "mixed"} else 1

        sendp(
            Ether() / IP(src=src, dst=target) / ICMP(type=8, id=ident, seq=i),
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
