"""
evidence/custody.py

Chain-of-custody tracking for pcap evidence files. Two things live here:

  1. Hashing — computes a SHA-256 of a file's contents at a point in
     time, so tampering can be detected later.

  2. An append-only audit log — every custody event (file created,
     rotated/closed, integrity checked) gets one line in a JSONL file.

This does NOT prevent tampering — nothing running on the same machine
as an attacker can truly prevent that. What it provides is *detection*:
if a pcap file's hash no longer matches what was logged when it was
last touched.

"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CUSTODY_LOG_PATH = Path(__file__).parent.parent / "data" / "custody_log.jsonl"

CHUNK_SIZE = 1024 * 1024  # read files in 1 MB chunks when hashing


@dataclass
class CustodyEvent:
    timestamp: float
    action: str        # "created", "rotated", "integrity_check"
    file: str
    sha256: str
    size_bytes: int
    note: Optional[str] = None


def compute_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def _append_event(event: CustodyEvent) -> None:
    CUSTODY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CUSTODY_LOG_PATH, "a") as f:
        f.write(json.dumps(asdict(event)) + "\n")


def record_custody_event(path: Path, action: str, note: Optional[str] = None) -> CustodyEvent:
    """
    Hashes the given file right now and appends one line to the custody
    log recording that hash. Call this at meaningful moments — e.g.
    when a pcap file is rotated/closed.
    """
    path = Path(path)
    event = CustodyEvent(
        timestamp=time.time(),
        action=action,
        file=str(path),
        sha256=compute_file_hash(path),
        size_bytes=path.stat().st_size,
        note=note,
    )
    _append_event(event)
    return event


def get_custody_log(file: Optional[str] = None) -> List[CustodyEvent]:
    if not CUSTODY_LOG_PATH.exists():
        return []

    events = []
    with open(CUSTODY_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            if file is not None and data["file"] != file:
                continue
            events.append(CustodyEvent(**data))
    return events


def verify_file_integrity(path: Path) -> bool:
    """
    Recomputes the hash of the given file right now and compares it
    against the most recent logged hash for that file.
    """
    path = Path(path)
    if not path.exists():
        return False

    history = get_custody_log(file=str(path))
    if not history:
        return False  # nothing on record for this file — can't vouch for it

    last_known_hash = history[-1].sha256
    current_hash = compute_file_hash(path)
    return current_hash == last_known_hash