"""
response/alerting.py

Dispatches notifications when a Finding comes in.

Channels are pluggable via a simple callable interface, so adding a
new one (email, Slack, PagerDuty) means writing one function.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.severity import Severity, score
from detectors.base import Finding

AlertChannel = Callable[[Finding, Severity], None]

_SEVERITY_COLOR = {
    Severity.low: "\033[37m",       # gray
    Severity.medium: "\033[33m",     # yellow
    Severity.high: "\033[91m",        # bright red
    Severity.critical: "\033[41m\033[97m",  # white on red background
}
_RESET = "\033[0m"


def console_channel(finding: Finding, severity: Severity) -> None:
    """Prints the alert to stdout."""
    color = _SEVERITY_COLOR.get(severity, "")
    print(f"{color}[ALERT] [{severity.value.upper()}] {finding.detector_name}: {finding.summary}{_RESET}")


def webhook_channel(url: str) -> AlertChannel:
    """
    Returns a channel function that POSTs the alert as JSON to the given
    URL. Not wired to anything by default.
    """
    import json
    import urllib.request

    def _send(finding: Finding, severity: Severity) -> None:
        payload = {
            "detector": finding.detector_name,
            "severity": severity.value,
            "summary": finding.summary,
            "src_ip": finding.src_ip,
            "timestamp": finding.timestamp,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            print(f"[alerting] webhook delivery failed: {exc}")

    return _send


# minimum severity that triggers an alert at all
DEFAULT_ALERT_THRESHOLD = Severity.high

_SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def dispatch_alert(finding: Finding, channels: Optional[List[AlertChannel]] = None, threshold: Severity = DEFAULT_ALERT_THRESHOLD) -> Optional[Severity]:
    """
    Scores the finding, and if it meets or exceeds `threshold`, sends it
    to every channel in 'channels'. Returns the computed severity if an
    alert was sent, or None if it was below threshold and suppressed.

    Defaults to just the console channel if none are given.
    """
    if channels is None:
        channels = [console_channel]

    severity = score(finding)

    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[threshold]:
        return None  # below threshold, suppressed — no channels notified

    for channel in channels:
        channel(finding, severity)

    return severity