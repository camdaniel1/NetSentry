"""
scripts/simulate_port_scan.py

Sends TCP SYN patterns that exercise port-scan detection.

Usage:
    python -m scripts.simulate_port_scan --target 192.168.1.50 --interface <ip>

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

  - "sequential"   : scan a contiguous range of ports in order
  - "reverse_sequential": scan a contiguous range in descending order
  - "random_ports" : scan a random sample of ports out of order
  - "well_known"   : scan a curated list of commonly-targeted ports
                      (SSH, RDP, SMB, DB ports, etc.)
  - "slow_burst"    : spread the same number of ports out over a longer
                      time, to test whether the detector's time window
                      is wide enough to still catch a slower sweep
  - "horizontal_sweep": probe one service across multiple lab addresses
  - "random"       : randomly pick one of the above for each run, and
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


SCENARIO_CONFIG = {
    "scenarios": ["sequential", "reverse_sequential", "random_ports", "well_known",
                  "horizontal_sweep", "slow_burst"],
    "sequential_start_port": 1,
    "well_known_ports": [22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                          445, 993, 995, 1433, 1521, 3306, 3389, 5432,
                          5900, 8080],
    "slow_burst_spacing": 2.0,  # seconds between packets in slow_burst
    "jitter_range": (0.05, 0.4),  # seconds, used when --interval-jitter is set
}

# Defensive test profiles. Higher difficulty means the detector receives a
# less uniform but still bounded test pattern; these are not evasion modes.
DIFFICULTY_PROFILES = {
    "easy": {"count": 24, "interval": 0.05, "scenario": "sequential", "jitter": False},
    "medium": {"count": 20, "interval": 0.15, "scenario": "random_ports", "jitter": True},
    "hard": {"count": 16, "interval": 0.25, "scenario": "random_ports", "jitter": True},
}


def difficulty_meter(level: str) -> str:
    filled = {"easy": 1, "medium": 3, "hard": 5}[level]
    return f"[{'#' * filled}{'-' * (5 - filled)}] {level.upper()}"


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


def build_syn_packet(target_ip: str, port: int, src_port: int):
    """Builds one TCP SYN packet aimed at target_ip:port."""
    from scapy.all import IP, TCP

    return IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")


def send(packet, interface: str) -> None:
    from scapy.all import sendp
    from scapy.all import Ether

    # Wrap in an Ethernet frame so we can pin the send to a specific
    # interface the same way the ARP simulator does.
    eth_packet = Ether() / packet
    sendp(eth_packet, iface=interface, verbose=False)


def run_sequential(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    start = SCENARIO_CONFIG["sequential_start_port"]
    ports = list(range(start, start + count))
    print(f"{YELLOW}[sequential] scanning ports {ports[0]}-{ports[-1]} on {target_ip}{RESET}")
    src_port = random.randint(1024, 65000)
    for i, port in enumerate(ports):
        send(build_syn_packet(target_ip, port, src_port), interface)
        print(f"  SYN -> {target_ip}:{port} ({i + 1}/{count})")
        sleep_interval(interval, jitter)


def run_reverse_sequential(target_ip: str, interface: str, count: int,
                           interval: float, jitter: bool) -> None:
    ports = list(range(SCENARIO_CONFIG["sequential_start_port"],
                       SCENARIO_CONFIG["sequential_start_port"] + count))[::-1]
    print(f"{YELLOW}[reverse_sequential] scanning ports {ports[0]} down to {ports[-1]} on {target_ip}{RESET}")
    src_port = random.randint(1024, 65000)
    for index, port in enumerate(ports, start=1):
        send(build_syn_packet(target_ip, port, src_port), interface)
        print(f"  SYN -> {target_ip}:{port} ({index}/{count})")
        sleep_interval(interval, jitter)


def run_random_ports(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    ports = random.sample(range(1, 65536), count)
    print(f"{YELLOW}[random_ports] scanning {count} random ports on {target_ip}{RESET}")
    src_port = random.randint(1024, 65000)
    for i, port in enumerate(ports):
        send(build_syn_packet(target_ip, port, src_port), interface)
        print(f"  SYN -> {target_ip}:{port} ({i + 1}/{count})")
        sleep_interval(interval, jitter)


def run_well_known(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    base_ports = SCENARIO_CONFIG["well_known_ports"]
    # repeat/extend the well-known list if count > len(base_ports)
    ports = (base_ports * ((count // len(base_ports)) + 1))[:count]
    print(f"{YELLOW}[well_known] scanning {len(ports)} commonly-targeted ports on {target_ip}{RESET}")
    src_port = random.randint(1024, 65000)
    for i, port in enumerate(ports):
        send(build_syn_packet(target_ip, port, src_port), interface)
        print(f"  SYN -> {target_ip}:{port} ({i + 1}/{len(ports)})")
        sleep_interval(interval, jitter)


def run_slow_burst(target_ip: str, interface: str, count: int, interval: float, jitter: bool) -> None:
    spacing = SCENARIO_CONFIG["slow_burst_spacing"]
    start = SCENARIO_CONFIG["sequential_start_port"]
    ports = list(range(start, start + count))
    print(f"{YELLOW}[slow_burst] scanning {count} ports on {target_ip}, "
          f"spaced {spacing}s apart{RESET}")
    src_port = random.randint(1024, 65000)
    for i, port in enumerate(ports):
        send(build_syn_packet(target_ip, port, src_port), interface)
        print(f"  SYN -> {target_ip}:{port} ({i + 1}/{count})")
        sleep_interval(spacing, jitter)


def run_horizontal_sweep(target_ip: str, interface: str, count: int,
                         interval: float, jitter: bool) -> None:
    address = ipaddress.ip_address(target_ip)
    if address.version != 4:
        print(f"{RED}horizontal_sweep currently requires an IPv4 target{RESET}")
        raise SystemExit(1)
    network = ipaddress.ip_network(f"{target_ip}/24", strict=False)
    targets = [str(host) for host in network.hosts() if host != address][:count]
    destination_port = 22
    src_port = random.randint(1024, 65000)
    print(f"{YELLOW}[horizontal_sweep] probing TCP/{destination_port} across {len(targets)} hosts{RESET}")
    for index, host in enumerate(targets, start=1):
        send(build_syn_packet(host, destination_port, src_port), interface)
        print(f"  SYN -> {host}:{destination_port} ({index}/{len(targets)})")
        sleep_interval(interval, jitter)


SCENARIO_RUNNERS = {
    "sequential": run_sequential,
    "reverse_sequential": run_reverse_sequential,
    "random_ports": run_random_ports,
    "well_known": run_well_known,
    "slow_burst": run_slow_burst,
    "horizontal_sweep": run_horizontal_sweep,
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

    print(f"\n{YELLOW}done. the detector should have fired once enough "
          f"distinct ports were seen within its time window. if it "
          f"didn't, check that it's watching the same interface "
          f"({interface}), that the pipeline/detector was already "
          f"running before this script sent anything, and that --count "
          f"is at or above the detector's port threshold.{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send real TCP SYN traffic to test detectors/port_scan.py"
    )
    parser.add_argument("--target",
                         help="IP address to scan (a host you own or have permission to test)")
    parser.add_argument("--interface",
                         help="interface — sys_name, human_name, pcap_name, or ip; "
                              "run with --list-interfaces to see options")
    parser.add_argument("--difficulty", choices=DIFFICULTY_PROFILES, default="medium",
                         help="defensive detector test profile (default: medium)")
    parser.add_argument("--count", type=int,
                         help="override the profile's number of ports")
    parser.add_argument("--interval", type=float,
                         help="override the profile's seconds between packets")
    parser.add_argument("--interval-jitter", action="store_true",
                         help="add random jitter to --interval, for timing coverage variety")
    parser.add_argument("--scenario",
                         choices=list(SCENARIO_RUNNERS.keys()) + ["random"],
                         help="test scenario to run (default: sequential)")
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
