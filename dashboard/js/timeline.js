import { API_BASE, apiHeaders, hasPermission } from "./api.js";
import { downloadResponse, escapeHtml, formatTime } from "./utils.js?v=2";

export function refreshTimelinePermissions() {
  document.getElementById("timeline-export").disabled = !hasPermission("reports:export");
}

async function exportTimelineReport() {
  const state = document.getElementById("timeline-export-state");
  const incidentId = document.getElementById("timeline-case").value;
  if (!incidentId) {
    state.textContent = "Select a case before exporting a report.";
    return;
  }
  const format = document.getElementById("report-format").value;
  state.textContent = "Preparing report…";
  try {
    const response = await fetch(`${API_BASE}/timeline/${encodeURIComponent(incidentId)}/report?fmt=${encodeURIComponent(format)}`, { headers: apiHeaders() });
    const filename = await downloadResponse(response);
    state.textContent = `Downloaded ${filename}.`;
    document.dispatchEvent(new CustomEvent("netsentry:audit-changed"));
  } catch (error) {
    state.textContent = error.message;
  }
}

export function setTimelineCases(cases) {
  const select = document.getElementById("timeline-case");
  const selected = select.value;
  select.innerHTML = `<option value="">All cases</option>` + cases.map(item => `<option value="${escapeHtml(item.incident_id)}">${escapeHtml(item.title)}</option>`).join("");
  select.value = selected;
}

export async function loadTimeline() {
  const incidentId = document.getElementById("timeline-case").value;
  const params = new URLSearchParams({ limit: incidentId ? "75" : "25" });
  const srcIp = document.getElementById("timeline-source").value.trim();
  if (incidentId) params.set("incident_id", incidentId);
  if (srcIp) params.set("src_ip", srcIp);
  const response = await fetch(`${API_BASE}/timeline?${params}`, { headers: apiHeaders() });
  if (!response.ok) throw new Error(`timeline request failed: ${response.status}`);
  const events = await response.json();
  document.getElementById("timeline-list").innerHTML = events.length
    ? events.map(event => `<article class="timeline-event severity-${escapeHtml(event.severity)}"><span class="timeline-dot"></span><div class="timeline-meta">${formatTime(event.timestamp)} · ${escapeHtml(event.detector_name)} · ${escapeHtml(event.src_ip || "unknown source")} · ${escapeHtml(event.incident_id ? `case ${event.incident_id.slice(0, 8)}` : "ungrouped")}</div><div class="timeline-summary">${escapeHtml(event.summary)}</div><div class="timeline-meta">${event.has_evidence ? `Evidence: ${escapeHtml(event.pcap_file)} @ ${event.pcap_packet_number == null ? "packet row unavailable" : `No. ${Number(event.pcap_packet_number).toLocaleString()}`}` : "No PCAP evidence attached"}</div></article>`).join("")
    : `<div class="trend-empty">No events match these filters</div>`;
}

export function initTimeline() {
  document.getElementById("timeline-refresh").addEventListener("click", loadTimeline);
  document.getElementById("timeline-apply").addEventListener("click", loadTimeline);
  document.getElementById("timeline-case").addEventListener("change", loadTimeline);
  document.getElementById("timeline-export").addEventListener("click", exportTimelineReport);
  refreshTimelinePermissions();
}
