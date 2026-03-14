"""
scripts/simulate_arp_spoof.py

Sends real spoofed ARP replies on the local network.

Usage:
    python -m scripts.simulate_arp_spoof --target 192.168.1.1 --interface <ip>

Important notes:
    Leave --target pointing at your own router/gateway on an authorized LAN.
    The selected interface must match the interface monitored by NetSentry.

Optional commands:
    (--count #)
    (--interval seconds)
    (--scenario random)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "single"       : one baseline MAC, then one attacker MAC (classic case)
  - "multi_target"  : spoof several target IPs in sequence
  - "gratuitous"    : send unsolicited (gratuitous) ARP announcements
                       instead of unicast replies
  - "flicker"       : alternate between baseline and spoofed MAC a few
                       times, to test detectors that need to handle a
                       MAC "flapping" back and forth
  - "rotating_claimants": rotate several synthetic MAC claimants for one IP
  - "random"        : randomly pick one of the above for each run, and
                       randomize timing jitter between packets, purely
                       to broaden test coverage across runs

"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

# a MAC address that will never legitimately belong to the target IP
FAKE_MAC = "de:ad:be:ef:00:01"

# a plausible-looking "real" MAC used to establish a baseline before spoofing
BASELINE_MAC = "00:1a:2b:3c:4d:5e"

SCENARIO_CONFIG = {
    "scenarios": ["single", "multi_target", "gratuitous", "flicker", "rotating_claimants"],
    "flicker_cycles": 3,
    "jitter_range": (0.2, 1.5),
}

ROTATING_MACS = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02", "de:ad:be:ef:00:03"]

DIFFICULTY_PROFILES = {
    "easy": {"count": 4, "interval": 0.15, "scenario": "single", "jitter": False},
    "medium": {"count": 5, "interval": 0.4, "scenario": "gratuitous", "jitter": True},
    "hard": {"count": 7, "interval": 0.6, "scenario": "rotating_claimants", "jitter": True},
}


def difficulty_meter(level: str) -> str:
    filled = {"easy": 1, "medium": 3, "hard": 5}[level]
    return f"[{'#' * filled}{'-' * (5 - filled)}] {level.upper()}"


def nearby_targets(target_ip: str, count: int = 3) -> list[str]:
    """Derive deterministic lab targets from the supplied IPv4 subnet."""
    address = ipaddress.ip_address(target_ip)
    if address.version != 4:
        return [target_ip]
    network = ipaddress.ip_network(f"{target_ip}/24", strict=False)
    candidates = [str(host) for host in network.hosts() if host != address]
    return [target_ip] + candidates[:max(0, count - 1)]


def build_reply_packet(target_ip: str, mac: str):
    """Builds one ARP 'is-at' reply claiming target_ip -> mac (unicast-style)."""
    from scapy.all import ARP, Ether

    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,        # is-at (reply) — a claim, not a question
        psrc=target_ip,
        hwsrc=mac,
    )


def build_gratuitous_packet(target_ip: str, mac: str):
    """Builds a gratuitous ARP announcement claiming target_ip -> mac.
    """
    from scapy.all import ARP, Ether

    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=target_ip,
        pdst=target_ip,
        hwsrc=mac,
    )


def build_spoof_packet(target_ip: str, fake_mac: str):
    """Kept for backward compatibility — same as build_reply_packet."""
    return build_reply_packet(target_ip, fake_mac)


def resolve_interface(value: str) -> str:
    """Resolve --interface (sys_name | human_name | pcap_name | ip) to a pcap name."""
    info = find_interface(value)
    if info is None:
        print(f"{RED}could not resolve interface '{value}'.{RESET}")
        print_interface_err(list_interfaces())
        raise SystemExit(1)
    return info.pcap_name


def sleep_interval(interval: float, jitter: bool) -> None:
    if jitter:
        lo, hi = SCENARIO_CONFIG["jitter_range"]
        time.sleep(interval + random.uniform(lo, hi))
    else:
        time.sleep(interval)


def send(packet, interface: str) -> None:
    from scapy.all import sendp
    sendp(packet, iface=interface, verbose=False)


def run_single(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    print(f"{YELLOW}[single] baseline: {target_ip} is at {BASELINE_MAC}{RESET}")
    send(build_reply_packet(target_ip, BASELINE_MAC), interface)
    time.sleep(1)

    print(f"{YELLOW}[single] spoofing: claiming {target_ip} is at {FAKE_MAC} ({count} replies){RESET}")
    spoof_packet = build_reply_packet(target_ip, FAKE_MAC)
    for i in range(count):
        send(spoof_packet, interface)
        print(f"  sent spoofed reply {i + 1}/{count}")
        sleep_interval(interval, jitter)


def run_multi_target(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    targets = nearby_targets(target_ip)
    print(f"{YELLOW}[multi_target] targets: {targets}{RESET}")

    for ip in targets:
        send(build_reply_packet(ip, BASELINE_MAC), interface)
        print(f"  baseline set for {ip} -> {BASELINE_MAC}")
    time.sleep(1)

    for i in range(count):
        for ip in targets:
            send(build_reply_packet(ip, FAKE_MAC), interface)
            print(f"  spoofed {ip} -> {FAKE_MAC} ({i + 1}/{count})")
        sleep_interval(interval, jitter)


def run_gratuitous(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    print(f"{YELLOW}[gratuitous] baseline: {target_ip} is at {BASELINE_MAC}{RESET}")
    send(build_gratuitous_packet(target_ip, BASELINE_MAC), interface)
    time.sleep(1)

    print(f"{YELLOW}[gratuitous] announcing: {target_ip} is at {FAKE_MAC} ({count} announcements){RESET}")
    spoof_packet = build_gratuitous_packet(target_ip, FAKE_MAC)
    for i in range(count):
        send(spoof_packet, interface)
        print(f"  sent gratuitous announcement {i + 1}/{count}")
        sleep_interval(interval, jitter)


def run_flicker(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    cycles = max(2, count)
    print(f"{YELLOW}[flicker] baseline: {target_ip} is at {BASELINE_MAC}{RESET}")
    send(build_reply_packet(target_ip, BASELINE_MAC), interface)
    time.sleep(1)

    print(f"{YELLOW}[flicker] flapping {BASELINE_MAC} <-> {FAKE_MAC} for {cycles} cycles{RESET}")
    for c in range(cycles):
        send(build_reply_packet(target_ip, FAKE_MAC), interface)
        print(f"  cycle {c + 1}/{cycles}: -> {FAKE_MAC}")
        sleep_interval(interval, jitter)
        send(build_reply_packet(target_ip, BASELINE_MAC), interface)
        print(f"  cycle {c + 1}/{cycles}: -> {BASELINE_MAC}")
        sleep_interval(interval, jitter)


def run_rotating_claimants(target_ip: str, interface: str, count: int,
                           interval: float, jitter: bool) -> None:
    print(f"{YELLOW}[rotating_claimants] baseline: {target_ip} is at {BASELINE_MAC}{RESET}")
    send(build_reply_packet(target_ip, BASELINE_MAC), interface)
    time.sleep(1)
    for index in range(count):
        mac = ROTATING_MACS[index % len(ROTATING_MACS)]
        send(build_reply_packet(target_ip, mac), interface)
        print(f"  claimant {index + 1}/{count}: {target_ip} -> {mac}")
        sleep_interval(interval, jitter)


SCENARIO_RUNNERS = {
    "single": run_single,
    "multi_target": run_multi_target,
    "gratuitous": run_gratuitous,
    "flicker": run_flicker,
    "rotating_claimants": run_rotating_claimants,
}


def run_simulation(target_ip: str, interface: str, count: int, interval: float,
                   scenario: str, jitter: bool, difficulty: str = "medium") -> None:
    if scenario == "random":
        scenario = random.choice(SCENARIO_CONFIG["scenarios"])
        print(f"{YELLOW}[random] chose scenario: {scenario}{RESET}")

    runner = SCENARIO_RUNNERS.get(scenario)
    if runner is None:
        print(f"{RED}unknown scenario '{scenario}'. available: "
              f"{SCENARIO_CONFIG['scenarios']} (or 'random'){RESET}")
        raise SystemExit(1)

    print(f"interface: {interface}")
    print(f"detector test difficulty: {difficulty_meter(difficulty)}")
    print("watch your detector's output in another terminal now.\n")

    runner(target_ip, interface, count, interval, jitter)

    print(f"\n{YELLOW}done. the detector should have fired on the first "
          f"MAC change for each spoofed target. if it didn't, check that "
          f"it's watching the same interface ({interface}) and that the "
          f"pipeline/detector was already running before this script sent "
          f"anything.{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send real spoofed ARP traffic to test detectors/arp_spoof.py"
    )
    parser.add_argument("--target",
                         help="IP address to spoof (e.g. your own gateway)")
    parser.add_argument("--interface",
                         help="interface — sys_name, human_name, pcap_name, or ip; "
                              "run with --list-interfaces to see options")
    parser.add_argument("--difficulty", choices=DIFFICULTY_PROFILES, default="medium",
                         help="defensive detector test profile (default: medium)")
    parser.add_argument("--count", type=int,
                         help="override the profile's number of claims")
    parser.add_argument("--interval", type=float,
                         help="override the profile's seconds between claims")
    parser.add_argument("--interval-jitter", action="store_true",
                         help="add random jitter to --interval, for timing coverage variety")
    parser.add_argument("--scenario",
                         choices=list(SCENARIO_RUNNERS.keys()) + ["random"],
                         help="test scenario to run (default: single)")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="list available interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        print_interface_err(list_interfaces())
        return 0

    if not args.target or not args.interface:
        print(f"{RED}--target and --interface are required (unless using --list-interfaces).{RESET}")
        return 1

    iface = resolve_interface(args.interface)
    profile = DIFFICULTY_PROFILES[args.difficulty]

    run_simulation(
        target_ip=args.target,
        interface=iface,
        count=args.count if args.count is not None else profile["count"],
        interval=args.interval if args.interval is not None else profile["interval"],
        scenario=args.scenario or profile["scenario"],
        jitter=args.interval_jitter or profile["jitter"],
        difficulty=args.difficulty,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
