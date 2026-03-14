"""
correlation/severity.py

Assigns a severity level to a Finding.

Each detector gets its own scoring function, dispatched by
Finding.detector_name. Unknown detector names fall back to "medium"
rather than crashing, so a new detector always produces a usable
severity even before its scoring rule is written.
"""

from __future__ import annotations

import os
import sys
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.base import Finding

# Commonly targeted for lateral movement / exploitation.
_HIGH_VALUE_PORTS = {22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432}


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _score_arp_spoof(finding: Finding) -> Severity:
    """
    Any confirmed mismatch is treated as high severity by default.
    Escalate to critical if the spoofed IP looks like a gateway
    (heuristic: ends in .1 or .254 — common default gateway addresses),
    since that's the highest-impact target to spoof.
    """
    ip = finding.src_ip or ""
    if ip.endswith(".1") or ip.endswith(".254"):
        return Severity.critical
    return Severity.high


def _score_port_scan(finding: Finding) -> Severity:
    """
      - critical: scan touched a high-value port (SSH/RDP/SMB/DB/etc)
        *and* covered a large number of distinct ports — looks like a
        broad sweep specifically probing for exploitable services
      - high: scan touched a high-value port, or covered an unusually
        large number of ports, but not both
      - medium: a plain scan that only just crossed the detector's
        threshold
    """
    details = finding.details or {}
    port_count = details.get("port_count", 0)
    sample_ports = set(details.get("sample_ports", []))

    hits_high_value = bool(sample_ports & _HIGH_VALUE_PORTS)
    large_sweep = port_count >= 100

    if hits_high_value and large_sweep:
        return Severity.critical
    if hits_high_value or large_sweep:
        return Severity.high
    return Severity.medium


def _score_dns_tunneling(finding: Finding) -> Severity:
    details = finding.details or {}
    if details.get("label_entropy", 0) >= 4.2 and details.get("unique_queries", 0) >= 25:
        return Severity.critical
    if details.get("tunnel_pattern") == "encoded_label" or details.get("unique_queries", 0) >= 20:
        return Severity.high
    return Severity.medium


def _score_syn_flood(finding: Finding) -> Severity:
    details = finding.details or {}
    if details.get("syn_rate", 0) >= 500 or details.get("syn_count", 0) >= 1000:
        return Severity.critical
    if details.get("syn_rate", 0) >= 100 or details.get("source_count", 0) >= 5:
        return Severity.high
    return Severity.medium


def _score_rogue_dhcp(finding: Finding) -> Severity:
    details = finding.details or {}
    if details.get("message_type") in {"5", "ack"}:
        return Severity.critical
    return Severity.high

def _score_rate_flood(finding: Finding) -> Severity:
    details=finding.details or {}; rate=details.get("packet_rate",0); count=details.get("packet_count",0)
    if rate>=1000 or count>=2000:return Severity.critical
    if rate>=200 or details.get("source_count",0)>=5:return Severity.high
    return Severity.medium

def _score_ip_spoofing(finding: Finding) -> Severity:
    return Severity.critical if (finding.details or {}).get("spoof_pattern")=="martian_source" else Severity.high

def _score_packet_sniffing(finding: Finding) -> Severity: return Severity.high
def _score_evil_twin(finding: Finding) -> Severity: return Severity.critical

# List of scorers ----------------------

_SCORERS = {
    "arp_spoof": _score_arp_spoof,
    "port_scan": _score_port_scan,
    "dns_tunneling": _score_dns_tunneling,
    "syn_flood": _score_syn_flood,
    "rogue_dhcp": _score_rogue_dhcp,
    "icmp_flood": _score_rate_flood,
    "udp_flood": _score_rate_flood,
    "ip_spoofing": _score_ip_spoofing,
    "packet_sniffing": _score_packet_sniffing,
    "evil_twin": _score_evil_twin,
}


# Public API ---------------------------


_DEFAULT_SEVERITY = Severity.medium


def score(finding: Finding) -> Severity:
    """
    Returns the Severity for a given Finding. Unknown detector names
    fall back to medium rather than raising, so a newly added detector
    without a scoring rule yet still produces something usable.
    """
    scorer = _SCORERS.get(finding.detector_name)
    if scorer is None:
        return _DEFAULT_SEVERITY
    return scorer(finding)
