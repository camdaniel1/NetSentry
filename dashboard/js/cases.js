import { API_BASE, DASHBOARD_CONFIG } from "./api.js?v=9";
import { badgeClass, downloadResponse, escapeHtml, formatTime } from "./utils.js?v=2";

const state = { cases: [], selectedId: null };

function operationMessage(message, isError = false) {
  const element = document.getElementById("case-operation-state");
  element.textContent = message;
  element.style.color = isError ? "#ff7777" : "";
}

function formatBytes(bytes) {
  if (!Number.isFinite(Number(bytes)) || Number(bytes) <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(Number(bytes)) / Math.log(1024)), units.length - 1);
  const value = Number(bytes) / (1024 ** index);
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function detectorBadges(value) {
  return String(value || "").split(",").filter(Boolean)
    .map(name => `<span class="badge ${badgeClass(name)}">${escapeHtml(name)}</span>`)
    .join(" ") || "—";
}

async function loadIncidentEvents(incidentId) {
  const list = document.getElementById("case-timeline-list");
  list.innerHTML = `<div class="trend-empty">Loading events…</div>`;
  const params = new URLSearchParams({ limit: String(DASHBOARD_CONFIG.timelineLimit), incident_id: incidentId });
  const response = await fetch(`${API_BASE}/timeline?${params}`);
  if (!response.ok) {
    list.innerHTML = `<div class="trend-empty">Could not load incident events</div>`;
    return;
  }
  const events = await response.json();
  list.innerHTML = events.length
    ? events.map(event => `<article class="timeline-event severity-${escapeHtml(event.severity)}"><span class="timeline-dot"></span><div class="timeline-meta">${formatTime(event.timestamp)} · ${escapeHtml(event.detector_name)} · ${escapeHtml(event.src_ip || "unknown source")}</div><div class="timeline-summary">${escapeHtml(event.summary)}</div>${event.has_evidence ? `<div class="timeline-meta">Evidence: ${escapeHtml(event.pcap_file)}</div>` : ""}</article>`).join("")
    : `<div class="trend-empty">No events are linked to this incident</div>`;
}

function selectCase(incidentId) {
  state.selectedId = incidentId;
  const item = state.cases.find(entry => entry.incident_id === incidentId);
  if (!item) return;
  document.getElementById("case-title").value = item.title || "";
  document.getElementById("case-assignee").value = item.assignee || "";
  document.getElementById("case-status").value = item.status || "open";
  document.getElementById("case-notes").value = item.notes || "";
  document.getElementById("case-editor-help").textContent = `${item.finding_count} finding(s) · ${item.src_ip || "unknown source"}`;
  ["case-title", "case-assignee", "case-status", "case-notes", "case-save", "case-export-report"].forEach(id => {
    document.getElementById(id).disabled = false;
  });
  document.getElementById("case-save-state").textContent = "";
  document.querySelectorAll("#cases-body tr").forEach(row => row.classList.toggle("selected", row.dataset.incidentId === incidentId));
  loadIncidentEvents(incidentId).catch(console.error);
}

export async function loadCases() {
  const response = await fetch(`${API_BASE}/cases?limit=${DASHBOARD_CONFIG.casesLimit}`);
  if (!response.ok) throw new Error(`case request failed: ${response.status}`);
  state.cases = await response.json();
  const body = document.getElementById("cases-body");
  body.innerHTML = state.cases.length
    ? state.cases.map(item => `<tr class="clickable-row" data-incident-id="${escapeHtml(item.incident_id)}"><td class="mono">${escapeHtml(item.title)}</td><td>${detectorBadges(item.detectors)}</td><td class="mono">${escapeHtml(item.src_ip || "—")}</td><td>${Number(item.finding_count)}</td><td>${formatTime(item.last_seen)}</td><td><span class="status-pill status-${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.assignee || "Unassigned")}</td></tr>`).join("")
    : `<tr><td colspan="7" class="empty">No incidents yet. Use “Find related incidents” after findings arrive.</td></tr>`;
  body.querySelectorAll("[data-incident-id]").forEach(row => row.addEventListener("click", () => selectCase(row.dataset.incidentId)));
  if (state.selectedId && state.cases.some(item => item.incident_id === state.selectedId)) selectCase(state.selectedId);
  return state.cases;
}

export async function loadVaultFiles() {
  const response = await fetch(`${API_BASE}/evidence/files?limit=${DASHBOARD_CONFIG.evidenceFilesLimit}`);
  if (!response.ok) throw new Error("could not list evidence files");
  const files = await response.json();
  document.getElementById("vault-body").innerHTML = files.length
    ? files.map(item => `<tr><td class="mono" title="${escapeHtml(item.file)}">${escapeHtml(item.name)}</td><td><span class="status-pill">${escapeHtml(item.kind)}</span></td><td>${formatBytes(item.size_bytes)}</td><td>${formatTime(item.created_at)}</td></tr>`).join("")
    : `<tr><td colspan="4" class="empty">No capture or export files yet</td></tr>`;
}

async function runGrouping() {
  operationMessage("Finding related incidents…");
  const response = await fetch(`${API_BASE}/cases/group`, { method: "POST" });
  if (!response.ok) return operationMessage("Could not group findings", true);
  const result = await response.json();
  operationMessage(`${result.incidents_created} incident group(s) processed.`);
  await loadCases();
}

async function saveSelectedCase() {
  if (!state.selectedId) return;
  const status = document.getElementById("case-save-state");
  status.textContent = "Saving…";
  const payload = {
    title: document.getElementById("case-title").value,
    assignee: document.getElementById("case-assignee").value,
    status: document.getElementById("case-status").value,
    notes: document.getElementById("case-notes").value,
  };
  const response = await fetch(`${API_BASE}/cases/${encodeURIComponent(state.selectedId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) return void (status.textContent = "Save failed");
  status.textContent = "Saved";
  await loadCases();
}

async function exportSelectedReport() {
  if (!state.selectedId) return;
  const format = document.getElementById("report-format").value;
  operationMessage("Preparing report…");
  try {
    const response = await fetch(`${API_BASE}/timeline/${encodeURIComponent(state.selectedId)}/report?fmt=${encodeURIComponent(format)}`);
    const filename = await downloadResponse(response);
    operationMessage(`Downloaded ${filename}.`);
  } catch (error) {
    operationMessage(error.message, true);
  }
}

async function pruneExpired() {
  if (!window.confirm("Delete evidence files older than the configured retention period?")) return;
  const response = await fetch(`${API_BASE}/evidence/prune`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) return operationMessage("Prune failed", true);
  const result = await response.json();
  operationMessage(`Pruned ${result.count} expired file(s).`);
  await loadVaultFiles();
}

async function exportSourceTraffic() {
  const source = document.getElementById("traffic-source").value.trim();
  if (!source) return operationMessage("Enter an IP or MAC source address.", true);
  operationMessage(`Building traffic export for ${source}…`);
  try {
    const response = await fetch(`${API_BASE}/evidence/export-source`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source }),
    });
    const filename = await downloadResponse(response);
    operationMessage(`Downloaded ${filename}.`);
    await loadVaultFiles();
  } catch (error) {
    operationMessage(error.message, true);
  }
}

export function initCases() {
  document.getElementById("cases-refresh").addEventListener("click", () => Promise.all([loadCases(), loadVaultFiles()]));
  document.getElementById("cases-group").addEventListener("click", runGrouping);
  document.getElementById("case-save").addEventListener("click", saveSelectedCase);
  document.getElementById("case-export-report").addEventListener("click", exportSelectedReport);
  document.getElementById("vault-refresh").addEventListener("click", async () => {
    const response = await fetch(`${API_BASE}/evidence/open-folder`, { method: "POST" });
    if (!response.ok) operationMessage("Could not open the evidence folder.", true);
  });
  document.getElementById("vault-prune").addEventListener("click", pruneExpired);
  document.getElementById("traffic-export").addEventListener("click", exportSourceTraffic);
}
