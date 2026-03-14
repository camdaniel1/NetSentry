"""
evidence/vault.py

Owns the on-disk storage of raw packet capture files. This is the
"write-once pcap storage, retention/pruning" piece architecture.

"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

VAULT_DIR = Path(__file__).parent.parent / "data" / "pcaps"

# rotate to a new file once the active one reaches this size
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB

# files older than this get pruned by prune_expired()
DEFAULT_RETENTION_DAYS = 14

FILE_PREFIX = "capture_"
FILE_SUFFIX = ".pcap"


@dataclass
class VaultFile:
    path: Path
    size_bytes: int
    created_at: float  # unix timestamp, from the filename itself


def _filename_for(timestamp: float) -> str:
    """
    Encodes the creation time directly into the filename, so file age
    can be determined without touching the filesystem's mtime (which
    can be altered by copying/backing up files) — the timestamp is
    part of the evidence itself.
    """
    return f"{FILE_PREFIX}{int(timestamp * 1000)}{FILE_SUFFIX}"


def _parse_timestamp(path: Path) -> Optional[float]:
    """Extracts the creation timestamp back out of a vault filename, or None if unparseable."""
    name = path.stem  # strips .pcap
    if not name.startswith(FILE_PREFIX):
        return None
    try:
        return float(name[len(FILE_PREFIX):]) / 1000
    except ValueError:
        return None


class EvidenceVault:
    """
    Manages the pool of rotating pcap files under VAULT_DIR. A writer
    (pcap_writer.py, eventually) asks this for the current file to
    write into via get_active_file(), and calls notify_written() after
    each write so the vault knows when to rotate.
    """

    def __init__(self, vault_dir: "Path | str" = VAULT_DIR, max_file_size_bytes: int = MAX_FILE_SIZE_BYTES) -> None:
        self.vault_dir = Path(vault_dir)
        self.max_file_size_bytes = max_file_size_bytes
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self._active_path: Optional[Path] = None

    # -- writing interface (used by capture/pcap_writer.py) ------------

    def get_active_file(self) -> Path:
        if self._active_path is None or self._should_rotate():
            self._active_path = self.vault_dir / _filename_for(time.time())
        return self._active_path

    def _should_rotate(self) -> bool:
        if self._active_path is None or not self._active_path.exists():
            return False
        return self._active_path.stat().st_size >= self.max_file_size_bytes

    # -- inventory -------------------------------------------------------

    def list_files(self) -> List[VaultFile]:
        """All pcap files currently in the vault, oldest first."""
        files = []
        for path in self.vault_dir.glob(f"{FILE_PREFIX}*{FILE_SUFFIX}"):
            created_at = _parse_timestamp(path)
            if created_at is None:
                continue  # skip anything that doesn't match our naming scheme
            files.append(VaultFile(
                path=path,
                size_bytes=path.stat().st_size,
                created_at=created_at,
            ))
        return sorted(files, key=lambda f: f.created_at)

    def total_size_bytes(self) -> int:
        return sum(f.size_bytes for f in self.list_files())

    # -- retention -----------------------------------------------------

    def prune_expired(
        self,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        before_delete: Optional[Callable[[Path], None]] = None,
    ) -> List[Path]:
        """
        Deletes files older than retention_days. Never deletes the
        currently active file, even if it happens to be old.

        Returns the list of paths that were deleted, so a caller can
        log what was removed.
        """
        cutoff = time.time() - (retention_days * 86400)
        deleted = []

        for vault_file in self.list_files():
            if vault_file.path == self._active_path:
                continue
            if vault_file.created_at < cutoff:
                if before_delete is not None:
                    before_delete(vault_file.path)
                vault_file.path.unlink()
                deleted.append(vault_file.path)

        return deleted
