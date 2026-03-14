"""Persistence and audit operations for incident case management."""

from __future__ import annotations

import time
from typing import Any

from storage.db import get_connection


VALID_STATUSES = {"open", "investigating", "resolved"}


def list_cases(limit: int = 100) -> list[dict[str, Any]]:
    """Return grouped incidents enriched with their case workflow state."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT f.incident_id,
                   COALESCE(c.title, 'Incident ' || substr(f.incident_id, 1, 8)) AS title,
                   COALESCE(c.status, 'open') AS status,
                   c.assignee, COALESCE(c.notes, '') AS notes,
                   MIN(f.timestamp) AS first_seen, MAX(f.timestamp) AS last_seen,
                   COUNT(*) AS finding_count,
                   GROUP_CONCAT(DISTINCT f.detector_name) AS detectors,
                   MAX(f.src_ip) AS src_ip,
                   c.updated_at
            FROM findings f
            LEFT JOIN cases c ON c.incident_id = f.incident_id
            WHERE f.incident_id IS NOT NULL
              AND COALESCE(c.status, 'open') != 'resolved'
            GROUP BY f.incident_id
            ORDER BY last_seen DESC LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    return [dict(row) for row in rows]


def update_case(
    incident_id: str,
    updates: dict[str, Any],
) -> dict[str, Any]:
    """Create case state on first edit and apply validated workflow updates."""
    allowed = {"title", "status", "assignee", "notes"}
    changes = {key: value for key, value in updates.items() if key in allowed and value is not None}
    if "status" in changes and changes["status"] not in VALID_STATUSES:
        raise ValueError(f"invalid case status: {changes['status']}")

    now = time.time()
    with get_connection() as conn:
        exists = conn.execute(
            "SELECT 1 FROM findings WHERE incident_id = ? LIMIT 1", (incident_id,)
        ).fetchone()
        if exists is None:
            raise LookupError("incident not found")

        conn.execute(
            """INSERT OR IGNORE INTO cases
               (incident_id, title, status, assignee, notes, created_at, updated_at)
               VALUES (?, ?, 'open', NULL, '', ?, ?)""",
            (incident_id, f"Incident {incident_id[:8]}", now, now),
        )
        if changes:
            assignments = ", ".join(f"{key} = ?" for key in changes)
            conn.execute(
                f"UPDATE cases SET {assignments}, updated_at = ? WHERE incident_id = ?",
                (*changes.values(), now, incident_id),
            )
        row = conn.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,)).fetchone()
    return dict(row)
