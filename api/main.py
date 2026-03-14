"""
api/main.py

Run with:
    uvicorn api.main:app --reload

Then visit http://127.0.0.1:8000/docs for the auto-generated API docs.
Serve the project directory (for example, ``python -m http.server 8080``)
and open http://127.0.0.1:8080/dashboard/ for the modular dashboard.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
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
from response.containment import block_ip
from storage.case_store import list_audit_log, list_cases, record_audit, update_case

from storage.event_store import (
    count_findings_by_detector,
    get_findings_by_detector,
    get_finding_by_id,
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

ROLE_PERMISSIONS = {
    "viewer": ["dashboard:view"],
    "analyst": [
        "dashboard:view", "cases:update", "cases:annotate", "cases:group",
        "evidence:custody", "evidence:export", "reports:export",
    ],
    "admin": [
        "dashboard:view", "cases:update", "cases:annotate", "cases:group",
        "evidence:custody", "evidence:export", "reports:export",
        "evidence:prune", "response:contain", "access:manage",
    ],
}


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


class ContainRequest(BaseModel):
    finding_id: int


def _identity(request: Request) -> tuple[str, str]:
    role = request.headers.get("X-NetSentry-Role", "analyst").lower()
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=403, detail="unknown role")
    actor = request.headers.get("X-NetSentry-Actor", "local-operator")[:100]
    return actor, role


def _require(request: Request, permission: str) -> tuple[str, str]:
    actor, role = _identity(request)
    if permission not in ROLE_PERMISSIONS[role]:
        raise HTTPException(status_code=403, detail=f"{role} cannot {permission}")
    return actor, role


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
def list_findings(limit: int = 50, interface: Optional[str] = None):
    """The dashboard's live feed."""
    findings = get_recent_findings(limit=limit, interface_name=interface)
    return [
        {**asdict(finding), "severity": score(finding).value}
        for finding in findings
    ]


@app.get("/findings/{detector_name}")
def list_findings_by_detector(detector_name: str, limit: int = 50):
    """Findings from one detector type only."""
    return get_findings_by_detector(detector_name, limit=limit)


@app.get("/stats")
def stats(interface: Optional[str] = None):
    """{'arp_spoof': 12, ...} — counts per detector."""
    return count_findings_by_detector(interface_name=interface)


@app.get("/trends")
def trends(hours: int = 24, top_limit: int = 8):
    """Aggregated detector activity and top source offenders."""
    return get_trend_summary(hours=hours, top_limit=top_limit)


@app.get("/cases")
def cases(limit: int = 15):
    return list_cases(limit=limit)


@app.patch("/cases/{incident_id}")
def edit_case(incident_id: str, payload: CaseUpdate, request: Request):
    actor, role = _require(request, "cases:update")
    try:
        return update_case(
            incident_id,
            payload.model_dump(exclude_none=True),
            actor=actor,
            role=role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/cases/group")
def group_cases(request: Request):
    actor, role = _require(request, "cases:group")
    created = run_grouping()
    record_audit(actor=actor, role=role, action="cases.grouped", details={"created": created})
    return {"incidents_created": created}


@app.get("/timeline")
def timeline(limit: int = 75, incident_id: str | None = None, src_ip: str | None = None):
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
def timeline_report(incident_id: str, request: Request, fmt: str = "json"):
    actor, role = _require(request, "reports:export")
    try:
        path = export_report(incident_id, fmt=fmt)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        actor=actor,
        role=role,
        action="report.exported",
        target=incident_id,
        details={"format": fmt, "file": str(path)},
    )
    media_type = "application/json" if fmt == "json" else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get("/evidence/files")
def evidence_files(limit: int = 15):
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
def open_evidence_folder(request: Request):
    _require(request, "dashboard:view")
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="opening the evidence folder is only supported on Windows")
    os.startfile(str(VAULT_DIR))
    return {"opened": str(VAULT_DIR)}


@app.post("/evidence/prune")
def prune_evidence(payload: PruneRequest, request: Request):
    actor, role = _require(request, "evidence:prune")
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
    record_audit(
        actor=actor,
        role=role,
        action="evidence.pruned",
        details={"retention_days": payload.retention_days, "deleted": [str(path) for path in deleted]},
    )
    return {"deleted": [str(path) for path in deleted], "count": len(deleted)}


@app.post("/evidence/custody")
def record_custody(payload: CustodyRequest, request: Request):
    actor, role = _require(request, "evidence:custody")
    path = _resolve_vault_file(payload.file)
    event = record_custody_event(path, payload.action[:50], note=payload.note)
    record_audit(actor=actor, role=role, action="custody.recorded", target=str(path), details={"custody_action": event.action})
    return asdict(event)


@app.get("/evidence/custody")
def custody_log(file: str | None = None):
    resolved = str(_resolve_vault_file(file)) if file else None
    return [asdict(event) for event in get_custody_log(file=resolved)]


@app.post("/evidence/verify")
def verify_evidence(payload: FileRequest, request: Request):
    actor, role = _require(request, "evidence:custody")
    path = _resolve_vault_file(payload.file)
    valid = verify_file_integrity(path)
    record_audit(actor=actor, role=role, action="evidence.verified", target=str(path), details={"valid": valid})
    return {"file": str(path), "valid": valid}


@app.post("/evidence/export-source")
def export_source(payload: TrafficExportRequest, request: Request):
    actor, role = _require(request, "evidence:export")
    try:
        exported = export_source_traffic(payload.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    record_audit(
        actor=actor,
        role=role,
        action="evidence.source_exported",
        target=payload.source,
        details={"packets": exported.packet_count, "files_scanned": exported.files_scanned, "file": str(exported.path)},
    )
    return FileResponse(
        exported.path,
        media_type="application/vnd.tcpdump.pcap",
        filename=exported.path.name,
        headers={"X-NetSentry-Packet-Count": str(exported.packet_count)},
    )


@app.post("/contain")
def contain(payload: ContainRequest, request: Request):
    actor, role = _require(request, "response:contain")
    record = get_finding_by_id(payload.finding_id)
    if record is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if not record.src_ip:
        raise HTTPException(status_code=400, detail="finding has no source IP to contain")
    action = block_ip(record.src_ip, reason=f"{record.detector_name}: {record.summary}", live=False)
    record_audit(actor=actor, role=role, action="response.containment_dry_run", target=record.src_ip, details=asdict(action))
    return asdict(action)


@app.get("/access")
def access(request: Request):
    actor, role = _identity(request)
    return {
        "actor": actor,
        "role": role,
        "permissions": ROLE_PERMISSIONS[role],
        "roles": ROLE_PERMISSIONS,
        "audit_log": list_audit_log(limit=15),
    }
