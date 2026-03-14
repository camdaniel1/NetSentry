"""Retention behavior for the evidence vault."""

import time

from evidence.vault import EvidenceVault, _filename_for


def test_prune_calls_hook_before_removing_expired_file(tmp_path):
    vault = EvidenceVault(tmp_path)
    expired = tmp_path / _filename_for(time.time() - (3 * 86400))
    expired.write_bytes(b"pcap")
    observed = []

    deleted = vault.prune_expired(retention_days=1, before_delete=lambda path: observed.append((path, path.exists())))

    assert deleted == [expired]
    assert observed == [(expired, True)]
    assert not expired.exists()
