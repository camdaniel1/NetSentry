"""
response/containment.py

Optional automated response actions — e.g. blocking a host that
triggered a critical finding.

This module is DRY-RUN BY DEFAULT. Nothing it does will actually touch
the firewall or network unless you explicitly pass live=True.

Scope note: this only targets Linux (iptables) for the live path, since
that's the most common target for a project like this. Extending to
Windows (netsh) or macOS (pf) would follow the same pattern but isn't
implemented here.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity
from detectors.base import Finding


@dataclass
class ContainmentAction:
    timestamp: float
    ip: str
    action: str          # "block_ip"
    executed: bool          # False if this was a dry run
    command: str              # the command that was (or would have been) run
    reason: str


CONTAINMENT_THRESHOLD = Severity.critical

_SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def _block_command(ip: str) -> List[str]:
    """
    The actual iptables command that would drop all traffic from 'ip'.
    """
    return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]


def block_ip(ip: str, reason: str, live: bool = False) -> ContainmentAction:
    """
    Blocks (or simulates blocking) an IP address.

    live=False (the default): builds the command, logs it, does NOT
    execute it. Safe to call anywhere, anytime.

    live=True: actually executes the iptables command. Requires root
    and Linux. This will really block traffic from 'ip' on this
    machine.
    """
    command = _block_command(ip)
    command_str = " ".join(command)

    if not live:
        print(f"[containment] DRY RUN — would execute: {command_str}")
        return ContainmentAction(
            timestamp=time.time(), ip=ip, action="block_ip",
            executed=False, command=command_str, reason=reason,
        )

    if platform.system() != "Linux":
        raise NotImplementedError(
            f"live containment is only implemented for Linux (iptables), "
            f"not {platform.system()}"
        )
    if os.geteuid() != 0:
        raise PermissionError("live containment requires root privileges")

    subprocess.run(command, check=True)
    print(f"[containment] EXECUTED: {command_str}")
    
    return ContainmentAction(timestamp=time.time(), ip=ip, action="block_ip", executed=True, command=command_str, reason=reason)


def maybe_contain(finding: Finding, severity: Severity, live: bool = False) -> ContainmentAction | None:
    """
    Decides whether a finding warrants containment at all, based on
    CONTAINMENT_THRESHOLD, and if so calls block_ip(). Returns None if
    the finding didn't meet the threshold.
    """
    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[CONTAINMENT_THRESHOLD]:
        return None

    if not finding.src_ip:
        return None  # nothing to block without a source IP

    return block_ip(finding.src_ip, reason=f"{finding.detector_name}: {finding.summary}", live=live)