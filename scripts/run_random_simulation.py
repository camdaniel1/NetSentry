"""
scripts/run_random_simulations.py

Runs randomly selected NetSentry detector simulations sequentially.

Usage:
    python -m scripts.run_random_simulation --target 192.168.1.87 --interface <ip> --count 5

Important notes:
    Use only targets and networks you own or are authorized to test. Selection
    is with replacement, so one simulation may run more than once. Evil-twin
    runs require monitor mode and frame injection on the selected interface.

Optional commands:
    (--ssid LabWifi)
    (--count #)
    (--seed #)
    (--dry-run)
    (--stop-on-error)

SIMULATION POOL
---------------

  - ARP spoofing
  - DNS tunneling
  - port scan
  - rogue DHCP
  - SYN flood

"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
from dataclasses import dataclass


DIFFICULTIES = ("easy", "medium", "hard")


@dataclass(frozen=True)
class Simulation:
    name: str
    module: str
    target_flag: str | None = "--target"
    needs_ssid: bool = False


SIMULATIONS = (
    Simulation("ARP spoofing", "scripts.simulate_arp_spoof"),
    Simulation("DNS tunneling", "scripts.simulate_dns_tunneling"),
    Simulation("port scan", "scripts.simulate_port_scan"),
    Simulation("rogue DHCP", "scripts.simulate_rogue_dhcp", target_flag="--server-ip"),
    Simulation("SYN flood", "scripts.simulate_syn_flood"),
)


def build_command(simulation: Simulation, difficulty: str, *, target: str,
                  interface: str, ssid: str) -> list[str]:
    command = [
        sys.executable, "-m", simulation.module,
        "--interface", interface,
        "--difficulty", difficulty,
    ]
    if simulation.target_flag:
        command.extend([simulation.target_flag, target])
    if simulation.needs_ssid:
        command.extend(["--ssid", ssid])
    return command


def run_random_simulations(*, target: str, interface: str, ssid: str,
                           count: int, rng: random.Random, dry_run: bool = False,
                           stop_on_error: bool = False) -> int:
    failures = 0
    for index in range(1, count + 1):
        simulation = rng.choice(SIMULATIONS)
        difficulty = rng.choice(DIFFICULTIES)
        command = build_command(
            simulation, difficulty, target=target, interface=interface, ssid=ssid,
        )
        print(f"\n[{index}/{count}] {simulation.name} - {difficulty.upper()}", flush=True)
        print("  " + subprocess.list2cmdline(command), flush=True)
        if dry_run:
            continue
        result = subprocess.run(command, check=False)
        if result.returncode:
            failures += 1
            print(f"  simulation exited with code {result.returncode}", file=sys.stderr)
            if stop_on_error:
                break
    print(f"\nCompleted {count if not stop_on_error else index} selection(s); {failures} failed.")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run random NetSentry simulations sequentially.",
    )
    parser.add_argument("--target", required=True, help="authorized IPv4 test target")
    parser.add_argument("--interface", required=True, help="interface name, IP, or PCAP name")
    parser.add_argument("--ssid", default="NetSentry-Lab", help="SSID used if evil twin is selected")
    parser.add_argument("--count", type=int, default=1, help="number of random simulations (1-100)")
    parser.add_argument("--seed", type=int, help="repeatable random selection seed")
    parser.add_argument("--dry-run", action="store_true", help="print selections without running them")
    parser.add_argument("--stop-on-error", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.count <= 100:
        parser.error("--count must be between 1 and 100")
    return run_random_simulations(
        target=args.target,
        interface=args.interface,
        ssid=args.ssid,
        count=args.count,
        rng=random.Random(args.seed),
        dry_run=args.dry_run,
        stop_on_error=args.stop_on_error,
    )


if __name__ == "__main__":
    raise SystemExit(main())
