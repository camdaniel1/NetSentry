"""
forensics/report.py

Exports a reconstructed incident timeline as a case report file. Two
formats: JSON (machine-readable, for re-ingestion or archival) and
Markdown (human-readable, for handing to someone who isn't going to
query the API themselves).

"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensics.timeline import IncidentTimeline, build_timeline
from settings import project_path, setting

REPORTS_DIR = project_path(str(setting("evidence.report_directory")))


def _format_ts(unix_ts: float) -> str:
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def timeline_to_dict(timeline: IncidentTimeline) -> dict:
    """Structured representation of a timeline, suitable for json.dumps()."""
    return {
        "incident_id": timeline.incident_id,
        "event_count": timeline.event_count,
        "first_seen": timeline.first_seen,
        "last_seen": timeline.last_seen,
        "highest_severity": timeline.highest_severity.value if timeline.highest_severity else None,
        "involved_detectors": timeline.involved_detectors,
        "entries": [
            {
                "timestamp": e.timestamp,
                "detector_name": e.detector_name,
                "summary": e.summary,
                "severity": e.severity.value,
                "src_ip": e.src_ip,
            }
            for e in timeline.entries
        ],
    }


def timeline_to_markdown(timeline: IncidentTimeline) -> str:
    """Human-readable case report as a markdown string."""
    lines = [
        f"# Incident Report — {timeline.incident_id}",
        "",
        f"- **Events:** {timeline.event_count}",
        f"- **First seen:** {_format_ts(timeline.first_seen) if timeline.first_seen else 'N/A'}",
        f"- **Last seen:** {_format_ts(timeline.last_seen) if timeline.last_seen else 'N/A'}",
        f"- **Highest severity:** {timeline.highest_severity.value if timeline.highest_severity else 'N/A'}",
        f"- **Detectors involved:** {', '.join(timeline.involved_detectors) or 'N/A'}",
        "",
        "## Timeline",
        "",
    ]

    for e in timeline.entries:
        lines.append(f"- **{_format_ts(e.timestamp)}** [{e.severity.value.upper()}] "
                      f"`{e.detector_name}` — {e.summary} (src: {e.src_ip or 'unknown'})")

    lines.append("")
    lines.append(f"_Generated {_format_ts(time.time())}_")
    return "\n".join(lines)


def export_report(incident_id: str, fmt: str = "json", output_dir: Optional[Path] = None) -> Path:
    """
    Builds the timeline for incident_id and writes it to disk as either
    'json' or 'markdown'. Returns the path written to.
    """
    if fmt not in ("json", "markdown"):
        raise ValueError(f"fmt must be 'json' or 'markdown', got '{fmt}'")

    timeline = build_timeline(incident_id)
    out_dir = output_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path = out_dir / f"incident_{incident_id}.json"
        path.write_text(json.dumps(timeline_to_dict(timeline), indent=2))
    else:
        path = out_dir / f"incident_{incident_id}.md"
        path.write_text(timeline_to_markdown(timeline))

    return path
