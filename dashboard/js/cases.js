import { API_BASE, apiHeaders, hasPermission } from "./api.js";
import { badgeClass, downloadResponse, escapeHtml, formatTime } from "./utils.js?v=2";

const state = { cases: [], selectedId: null, onCasesLoaded: () => {} };

function detectorBadges(value) {
  return String(value || "").split(",").filter(Boolean)
    .map(name => `<span class="badge ${badgeClass(name)}">${escapeHtml(name)}</span>`)
    .join(" ") || "—";
}

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

function selectCase(incidentId) {
  state.selectedId = incidentId;
  const item = state.cases.find(entry => entry.incident_id === incidentId);
  if (!item) return;
  document.getElementById("case-title").value = item.title || "";
  document.getElementById("case-assignee").value = item.assignee || "";
  document.getElementById("case-status").value = item.status || "open";
  document.getElementById("case-notes").value = item.notes || "";
  document.getElementById("case-editor-help").textContent = `Incident ${incidentId} · ${item.finding_count} finding(s)`;
  const allowed = hasPermission("cases:update");
  ["case-title", "case-assignee", "case-status", "case-notes", "case-save"].forEach(id => {
    document.getElementById(id).disabled = !allowed;
  });
  document.getElementById("case-save-state").textContent = allowed ? "" : "Viewer role is read-only";
}

export async function loadCases() {
  const response = await fetch(`${API_BASE}/cases?limit=15`, { headers: apiHeaders() });
  if (!response.ok) throw new Error(`case request failed: ${response.status}`);
  state.cases = await response.json();
  const body = document.getElementById("cases-body");
  body.innerHTML = state.cases.length
    ? state.cases.map((item, index) => `<tr class="clickable-row" data-case-index="${index}"><td class="mono">${escapeHtml(item.title)}</td><td>${detectorBadges(item.detectors)}</td><td class="mono">${escapeHtml(item.src_ip || "—")}</td><td>${Number(item.finding_count)}</td><td>${formatTime(item.last_seen)}</td><td><span class="status-pill status-${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.assignee || "Unassigned")}</td></tr>`).join("")
    : `<tr><td colspan="7" class="empty">No grouped incidents yet</td></tr>`;
  body.querySelectorAll("[data-case-index]").forEach(row => {
    row.addEventListener("click", () => selectCase(state.cases[Number(row.dataset.caseIndex)].incident_id));
  });
  state.onCasesLoaded(state.cases);
  if (state.selectedId) selectCase(state.selectedId);
  return state.cases;
}

async function runGrouping() {
  operationMessage("Grouping unassigned findings…");
  const response = await fetch(`${API_BASE}/cases/group`, { method: "POST", headers: apiHeaders() });
  if (!response.ok) {
    operationMessage(response.status === 403 ? "Your role cannot run grouping" : "Grouping failed", true);
    return;
  }
  const result = await response.json();
  operationMessage(`Grouping complete: ${result.incidents_created} incident group(s) processed.`);
  await loadCases();
  document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
}

async function loadCustodyLog(file) {
  const response = await fetch(`${API_BASE}/evidence/custody?file=${encodeURIComponent(file)}`, { headers: apiHeaders() });
  if (!response.ok) throw new Error("could not load custody log");
  const events = await response.json();
  document.getElementById("custody-title").textContent = file;
  document.getElementById("custody-body").innerHTML = events.length
    ? events.slice(-50).reverse().map(event => `<tr><td>${formatTime(event.timestamp)}</td><td>${escapeHtml(event.action)}</td><td class="mono" title="${escapeHtml(event.sha256)}">${escapeHtml(event.sha256.slice(0, 16))}…</td><td>${formatBytes(event.size_bytes)}</td><td>${escapeHtml(event.note || "—")}</td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">No custody events recorded for this file</td></tr>`;
}

async function recordCustody(file) {
  const action = window.prompt("Custody action", "reviewed");
  if (action === null || !action.trim()) return;
  const note = window.prompt("Optional custody note", "") ?? "";
  const response = await fetch(`${API_BASE}/evidence/custody`, {
    method: "POST",
    headers: apiHeaders(true),
    body: JSON.stringify({ file, action: action.trim(), note }),
  });
  if (!response.ok) {
    operationMessage(response.status === 403 ? "Your role cannot record custody events" : "Custody recording failed", true);
    return;
  }
  operationMessage("Custody event recorded.");
  await Promise.all([loadVaultFiles(), loadCustodyLog(file)]);
  document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
}

async function verifyEvidence(file, resultElement) {
  resultElement.textContent = "Checking…";
  const response = await fetch(`${API_BASE}/evidence/verify`, {
    method: "POST",
    headers: apiHeaders(true),
    body: JSON.stringify({ file }),
  });
  if (!response.ok) {
    resultElement.textContent = response.status === 403 ? "Denied" : "Error";
    return;
  }
  const result = await response.json();
  resultElement.textContent = result.valid ? "Valid" : "Invalid / no baseline";
  resultElement.className = result.valid ? "integrity-valid" : "integrity-invalid";
  document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
}

export async function loadVaultFiles() {
  const response = await fetch(`${API_BASE}/evidence/files?limit=15`, { headers: apiHeaders() });
  if (!response.ok) throw new Error("could not list evidence files");
  const files = await response.json();
  const body = document.getElementById("vault-body");
  body.innerHTML = files.length ? files.map((item, index) => `<tr><td class="mono" title="${escapeHtml(item.file)}">${escapeHtml(item.name)}</td><td><span class="status-pill">${escapeHtml(item.kind)}</span></td><td>${formatBytes(item.size_bytes)}</td><td>${formatTime(item.created_at)}</td><td>${Number(item.custody_events)} · ${escapeHtml(item.last_custody_action || "unrecorded")} <span data-integrity="${index}"></span></td><td><button class="table-action" data-log="${index}">Log</button><button class="table-action" data-record="${index}" ${hasPermission("evidence:custody") ? "" : "disabled"}>Record</button><button class="table-action" data-verify="${index}" ${hasPermission("evidence:custody") ? "" : "disabled"}>Verify</button></td></tr>`).join("") : `<tr><td colspan="6" class="empty">No capture or export PCAP files</td></tr>`;
  body.querySelectorAll("[data-log]").forEach(button => button.addEventListener("click", () => loadCustodyLog(files[Number(button.dataset.log)].file)));
  body.querySelectorAll("[data-record]").forEach(button => button.addEventListener("click", () => recordCustody(files[Number(button.dataset.record)].file)));
  body.querySelectorAll("[data-verify]").forEach(button => button.addEventListener("click", () => {
    const index = Number(button.dataset.verify);
    verifyEvidence(files[index].file, body.querySelector(`[data-integrity="${index}"]`));
  }));
  document.getElementById("cases-group").disabled = !hasPermission("cases:group");
  document.getElementById("vault-prune").disabled = !hasPermission("evidence:prune");
  document.getElementById("traffic-export").disabled = !hasPermission("evidence:export");
}

async function pruneExpired() {
  if (!window.confirm("Delete vault PCAP files older than the configured retention period? This cannot be undone.")) return;
  const response = await fetch(`${API_BASE}/evidence/prune`, {
    method: "POST",
    headers: apiHeaders(true),
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    operationMessage(response.status === 403 ? "Administrator role required to prune evidence" : "Prune failed", true);
    return;
  }
  const result = await response.json();
  operationMessage(`Pruned ${result.count} expired file(s).`);
  await loadVaultFiles();
  document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
}

async function exportSourceTraffic() {
  const source = document.getElementById("traffic-source").value.trim();
  if (!source) {
    operationMessage("Enter an IP or MAC source address.", true);
    return;
  }
  operationMessage(`Building all-traffic PCAP for ${source}…`);
  try {
    const response = await fetch(`${API_BASE}/evidence/export-source`, {
      method: "POST",
      headers: apiHeaders(true),
      body: JSON.stringify({ source }),
    });
    const filename = await downloadResponse(response);
    operationMessage(`Downloaded ${filename}.`);
    await loadVaultFiles();
    document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
  } catch (error) {
    operationMessage(error.message, true);
  }
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
    headers: apiHeaders(true),
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    status.textContent = response.status === 403 ? "Your role cannot update cases" : "Save failed";
    return;
  }
  status.textContent = "Saved";
  await loadCases();
  document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
}

export function refreshCasePermissions() {
  if (state.selectedId) selectCase(state.selectedId);
}

export function initCases(onCasesLoaded) {
  state.onCasesLoaded = onCasesLoaded || (() => {});
  document.getElementById("cases-refresh").addEventListener("click", () => Promise.all([loadCases(), loadVaultFiles()]));
  document.getElementById("cases-group").addEventListener("click", runGrouping);
  document.getElementById("case-save").addEventListener("click", saveSelectedCase);
  document.getElementById("vault-refresh").addEventListener("click", async () => {
    const response = await fetch(`${API_BASE}/evidence/open-folder`, { method: "POST", headers: apiHeaders() });
    if (!response.ok) operationMessage("Could not open the evidence folder.", true);
  });
  document.getElementById("vault-prune").addEventListener("click", pruneExpired);
  document.getElementById("traffic-export").addEventListener("click", exportSourceTraffic);
}
