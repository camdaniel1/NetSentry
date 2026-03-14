"""
scripts/simulate_rogue_dhcp.py

Sends synthetic DHCP server claims for rogue-DHCP detector testing.

Usage:
    python -m scripts.simulate_rogue_dhcp --server-ip 192.168.1.1 --interface <ip>

Important notes:
    Run only on an authorized lab network. Synthetic transaction IDs and an
    unassigned offered address are used so normal clients should ignore claims.

Optional commands:
    (--count #)
    (--interval seconds)
    (--scenario random)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "competing_offer"  : introduce a DHCP OFFER from a competing server
  - "rogue_ack"        : send unauthorized DHCP ACK claims
  - "multiple_servers" : rotate through several synthetic server identities
  - "offer_burst"      : repeat offers from one competing server
  - "random"           : randomly select one of the above scenarios

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
    "easy": {"count": 3, "interval": .2, "scenario": "competing_offer"},
    "medium": {"count": 5, "interval": .4, "scenario": "rogue_ack"},
    "hard": {"count": 7, "interval": .6, "scenario": "multiple_servers"},
}
SCENARIOS = ("competing_offer", "rogue_ack", "multiple_servers", "offer_burst", "random")

BASELINE_MAC = "02:00:00:00:00:01"
ROGUE_MAC = "02:de:ad:be:ef:01"


def difficulty_meter(level):
    n = {"easy": 1, "medium": 3, "hard": 5}[level]
    return f"[{'#' * n}{'-' * (5 - n)}] {level.upper()}"


def packet(server_ip, server_mac, message_type, xid):
    from scapy.all import BOOTP, DHCP, Ether, IP, UDP

    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, xid=xid, yiaddr="0.0.0.0", siaddr=server_ip) /
        DHCP(options=[
            ("message-type", message_type),
            ("server_id", server_ip),
            "end"
        ])
    )


def run(server_ip, interface, count, interval, scenario, difficulty):
    from scapy.all import sendp

    if scenario == "random":
        scenario = random.choice(SCENARIOS[:-1])

    xid = random.randrange(1, 2**32 - 1)

    print(
        f"interface: {interface}\n"
        f"detector test difficulty: {difficulty_meter(difficulty)}\n"
        f"scenario: {scenario}"
    )

    sendp(
        packet(server_ip, BASELINE_MAC, "offer", xid),
        iface=interface,
        verbose=False
    )
    time.sleep(.5)

    for index in range(count):
        mac = ROGUE_MAC
        ip = server_ip.rsplit(".", 1)[0] + f".{200 + index % 20}"
        kind = "ack" if scenario == "rogue_ack" else "offer"

        if scenario == "multiple_servers":
            mac = f"02:de:ad:be:ef:{index % 5 + 1:02x}"
        if scenario == "offer_burst":
            ip = server_ip.rsplit(".", 1)[0] + ".200"

        sendp(
            packet(ip, mac, kind, xid),
            iface=interface,
            verbose=False
        )
        print(f"  DHCP {kind.upper()} from {ip} ({mac}) ({index + 1}/{count})")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Simulate rogue DHCP claims in an authorized lab"
    )
    parser.add_argument("--server-ip", help="baseline DHCP server IP")
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
    if not info:
        parser.error("a valid --interface is required")

    server_ip = args.server_ip or info.ip_addr
    if not server_ip or ":" in server_ip:
        parser.error("--server-ip must be an IPv4 address")

    p = PROFILES[args.difficulty]
    run(
        server_ip,
        info.pcap_name,
        args.count or p["count"],
        args.interval if args.interval is not None else p["interval"],
        args.scenario or p["scenario"],
        args.difficulty
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
