"""
api/main.py

Run with:
    uvicorn api.main:app --reload

The launcher exposes API documentation at ``/docs`` and serves the dashboard
using the host and ports defined in config.yaml.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from correlation.grouper import run_grouping
from correlation.severity import score
from correlation.traffic_export import EXPORT_DIR, export_source_traffic
from detectors.base import Finding
from evidence.custody import get_custody_log, record_custody_event, verify_file_integrity
from evidence.vault import DEFAULT_RETENTION_DAYS, VAULT_DIR, EvidenceVault
from forensics.report import export_report
from storage.case_store import list_cases, update_case
from settings import setting

from storage.event_store import (
    count_findings_by_detector,
    get_findings_by_detector,
    get_recent_findings,
    get_trend_summary,
    get_timeline_findings,
    init_db,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # runs once on startup
    yield


app = FastAPI(title="NetSentry", lifespan=lifespan)

FINDINGS_LIMIT = int(setting("dashboard.findings_limit"))
CASES_LIMIT = int(setting("dashboard.cases_limit"))
TIMELINE_LIMIT = int(setting("dashboard.timeline_limit"))
EVIDENCE_FILES_LIMIT = int(setting("dashboard.evidence_files_limit"))
TREND_HOURS = int(setting("dashboard.trend_hours"))
TREND_TOP_SOURCES = int(setting("dashboard.trend_top_sources"))

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


class PruneRequest(BaseModel):
    retention_days: int = DEFAULT_RETENTION_DAYS


class CustodyRequest(BaseModel):
    file: str
    action: str = "reviewed"
    note: Optional[str] = None


class FileRequest(BaseModel):
    file: str


class TrafficExportRequest(BaseModel):
    source: str


def _resolve_vault_file(value: str) -> Path:
    roots = (VAULT_DIR.resolve(), EXPORT_DIR.resolve())
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    resolved = candidate.resolve()
    if resolved.parent not in roots or resolved.suffix.lower() != ".pcap":
        raise HTTPException(status_code=400, detail="file must be a managed evidence PCAP")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="evidence file not found")
    return resolved

# allow the separately served dashboard to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/findings")
def list_findings(limit: int = FINDINGS_LIMIT, interface: Optional[str] = None):
    """The dashboard's live feed."""
    findings = get_recent_findings(limit=limit, interface_name=interface)
    return [
        {**asdict(finding), "severity": score(finding).value}
        for finding in findings
    ]


@app.get("/findings/{detector_name}")
def list_findings_by_detector(detector_name: str, limit: int = FINDINGS_LIMIT):
    """Findings from one detector type only."""
    return get_findings_by_detector(detector_name, limit=limit)


@app.get("/stats")
def stats(interface: Optional[str] = None):
    """{'arp_spoof': 12, ...} — counts per detector."""
    return count_findings_by_detector(interface_name=interface)


@app.get("/trends")
def trends(hours: int = TREND_HOURS, top_limit: int = TREND_TOP_SOURCES):
    """Aggregated detector activity and top source offenders."""
    return get_trend_summary(hours=hours, top_limit=top_limit)


@app.get("/cases")
def cases(limit: int = CASES_LIMIT):
    return list_cases(limit=limit)


@app.patch("/cases/{incident_id}")
def edit_case(incident_id: str, payload: CaseUpdate):
    try:
        return update_case(
            incident_id,
            payload.model_dump(exclude_none=True),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/cases/group")
def group_cases():
    created = run_grouping()
    return {"incidents_created": created}


@app.get("/timeline")
def timeline(limit: int = TIMELINE_LIMIT, incident_id: str | None = None, src_ip: str | None = None):
    records = get_timeline_findings(limit=limit, incident_id=incident_id, src_ip=src_ip)
    result = []
    for record in records:
        finding = Finding(
            detector_name=record.detector_name,
            timestamp=record.timestamp,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            summary=record.summary,
            details=record.details,
        )
        item = asdict(record)
        item["severity"] = score(finding).value
        item["has_evidence"] = bool(record.pcap_file)
        result.append(item)
    return result


@app.get("/timeline/{incident_id}/report")
def timeline_report(incident_id: str, fmt: str = "json"):
    try:
        path = export_report(incident_id, fmt=fmt)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    media_type = "application/json" if fmt == "json" else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get("/evidence/files")
def evidence_files(limit: int = EVIDENCE_FILES_LIMIT):
    files = []
    for vault_file in EvidenceVault().list_files():
        history = get_custody_log(file=str(vault_file.path))
        files.append({
            "file": str(vault_file.path),
            "name": vault_file.path.name,
            "size_bytes": vault_file.size_bytes,
            "created_at": vault_file.created_at,
            "custody_events": len(history),
            "last_custody_action": history[-1].action if history else None,
            "kind": "Capture",
        })
    if EXPORT_DIR.exists():
        for path in EXPORT_DIR.glob("*.pcap"):
            history = get_custody_log(file=str(path))
            stat = path.stat()
            files.append({
                "file": str(path),
                "name": path.name,
                "size_bytes": stat.st_size,
                "created_at": stat.st_mtime,
                "custody_events": len(history),
                "last_custody_action": history[-1].action if history else None,
                "kind": "Export",
            })
    return sorted(files, key=lambda item: item["created_at"], reverse=True)[:max(1, min(limit, 100))]


@app.post("/evidence/open-folder")
def open_evidence_folder():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="opening the evidence folder is only supported on Windows")
    os.startfile(str(VAULT_DIR))
    return {"opened": str(VAULT_DIR)}


@app.post("/evidence/prune")
def prune_evidence(payload: PruneRequest):
    if payload.retention_days < 1:
        raise HTTPException(status_code=400, detail="retention_days must be at least 1")
    deleted = EvidenceVault().prune_expired(
        retention_days=payload.retention_days,
        before_delete=lambda path: record_custody_event(
            path,
            "pruned",
            note=f"expired after {payload.retention_days} retention days",
        ),
    )
    return {"deleted": [str(path) for path in deleted], "count": len(deleted)}


@app.post("/evidence/custody")
def record_custody(payload: CustodyRequest):
    path = _resolve_vault_file(payload.file)
    event = record_custody_event(path, payload.action[:50], note=payload.note)
    return asdict(event)


@app.get("/evidence/custody")
def custody_log(file: str | None = None):
    resolved = str(_resolve_vault_file(file)) if file else None
    return [asdict(event) for event in get_custody_log(file=resolved)]


@app.post("/evidence/verify")
def verify_evidence(payload: FileRequest):
    path = _resolve_vault_file(payload.file)
    valid = verify_file_integrity(path)
    return {"file": str(path), "valid": valid}


@app.post("/evidence/export-source")
def export_source(payload: TrafficExportRequest):
    try:
        exported = export_source_traffic(payload.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(
        exported.path,
        media_type="application/vnd.tcpdump.pcap",
        filename=exported.path.name,
        headers={"X-NetSentry-Packet-Count": str(exported.packet_count)},
    )
