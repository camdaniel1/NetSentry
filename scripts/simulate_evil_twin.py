"""
scripts/simulate_evil_twin.py

Sends synthetic 802.11 beacon frames for evil-twin detector testing.

Usage:
    python -m scripts.simulate_evil_twin --ssid LabWifi --interface <ip>

Important notes:
    The interface must support 802.11 monitor mode and frame injection. Run
    only in an authorized wireless lab; managed-mode Wi-Fi is insufficient.

Optional commands:
    (--scenario duplicate_bssid)
    (--difficulty easy | medium | hard)
    (--list-interfaces)

SCENARIO VARIETY
----------------

  - "duplicate_bssid" : advertise one SSID from a second BSSID
  - "rotating_bssid"  : rotate several synthetic BSSIDs for one SSID
  - "interleaved"     : alternate the baseline and synthetic BSSIDs

"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.interfaces import find_interface, list_interfaces, print_interface_err

PROFILES = {
    "easy": (8, .05, "duplicate_bssid"),
    "medium": (6, .2, "rotating_bssid"),
    "hard": (4, .5, "interleaved")
}
SCENARIOS = ("duplicate_bssid", "rotating_bssid", "interleaved")


def meter(x):
    n = {"easy": 1, "medium": 3, "hard": 5}[x]
    return f"[{'#' * n}{'-' * (5 - n)}] {x.upper()}"


def beacon(ssid, bssid):
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

    return (
        RadioTap() /
        Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid
        ) /
        Dot11Beacon() /
        Dot11Elt(ID="SSID", info=ssid)
    )


def run(ssid, iface, count, interval, scenario, difficulty):
    from scapy.all import sendp

    print(
        f"detector test difficulty: {meter(difficulty)}\n"
        f"scenario: {scenario}\n"
        f"monitor mode required"
    )

    sendp(beacon(ssid, "02:00:00:00:00:01"), iface=iface, verbose=False)
    time.sleep(.2)

    for i in range(count):
        bssid = "02:de:ad:be:ef:01" if scenario == "duplicate_bssid" else f"02:de:ad:be:ef:{i % 4 + 1:02x}"

        if scenario == "interleaved" and i % 2 == 0:
            bssid = "02:00:00:00:00:01"

        sendp(beacon(ssid, bssid), iface=iface, verbose=False)
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ssid", required=True)
    p.add_argument("--interface")
    p.add_argument("--difficulty", choices=PROFILES, default="medium")
    p.add_argument("--scenario", choices=SCENARIOS)
    p.add_argument("--list-interfaces", action="store_true")
    a = p.parse_args()

    if a.list_interfaces:
        print_interface_err(list_interfaces())
        return 0

    i = find_interface(a.interface or "")
    if not i:
        p.error("valid monitor-mode --interface required")

    c, t, s = PROFILES[a.difficulty]
    run(a.ssid, i.pcap_name, c, t, a.scenario or s, a.difficulty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
