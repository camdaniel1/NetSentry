import { API_BASE, DASHBOARD_CONFIG, LIVE_CONTROL_BASE } from "./api.js?v=9";
import { badgeClass, escapeHtml, formatTime } from "./utils.js?v=2";

let activeInterfaceName = null;
let selectedDetector = "all";

async function loadStats(interfaceName) {
  const response = await fetch(`${API_BASE}/stats?interface=${encodeURIComponent(interfaceName)}`);
  const stats = await response.json();
  const total = Object.values(stats).reduce((sum, count) => sum + count, 0);
  const container = document.getElementById("stats");
  container.innerHTML = `<div class="stat-card"><div class="count">${total}</div><div class="label">total findings</div></div>`;
  for (const [name, count] of Object.entries(stats)) {
    container.innerHTML += `<div class="stat-card"><div class="count">${count}</div><div class="label">${escapeHtml(name)}</div></div>`;
  }
  const filter = document.getElementById("incident-detector-filter");
  const previous = filter.value;
  filter.innerHTML = `<option value="all">All detectors</option>` + Object.keys(stats)
    .sort()
    .map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`)
    .join("");
  filter.value = [...filter.options].some(option => option.value === previous) ? previous : "all";
  selectedDetector = filter.value;
}

async function loadFindings(interfaceName) {
  const response = await fetch(`${API_BASE}/findings?limit=${DASHBOARD_CONFIG.findingsLimit}&interface=${encodeURIComponent(interfaceName)}`);
  const findings = await response.json();
  const visibleFindings = selectedDetector === "all"
    ? findings
    : findings.filter(finding => finding.detector_name === selectedDetector);
  const body = document.getElementById("findings-body");
  if (!visibleFindings.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty">no ${escapeHtml(selectedDetector === "all" ? "" : `${selectedDetector} `)}findings to display</td></tr>`;
    return;
  }
  body.innerHTML = visibleFindings.map(finding => `<tr><td>${formatTime(finding.timestamp)}</td><td><span class="badge ${badgeClass(finding.detector_name)}">${escapeHtml(finding.detector_name)}</span></td><td><span class="severity-pill severity-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td><td>${escapeHtml(finding.src_ip || "—")}</td><td>${escapeHtml(finding.summary)}</td></tr>`).join("");
}

export async function refreshIncidents() {
  try {
    const interfaceResponse = await fetch(`${LIVE_CONTROL_BASE}/interfaces`, { cache: "no-store" });
    if (!interfaceResponse.ok) throw new Error("active interface unavailable");
    const interfaceData = await interfaceResponse.json();
    if (!interfaceData.active?.pcap_name) throw new Error("no active interface");
    activeInterfaceName = interfaceData.active.pcap_name;
    await Promise.all([
      loadStats(interfaceData.active.pcap_name),
      loadFindings(interfaceData.active.pcap_name),
    ]);
  } catch (error) {
    document.getElementById("findings-body").innerHTML = `<tr><td colspan="5" class="empty">could not reach API at ${API_BASE} — is it running?</td></tr>`;
  }
}

export function initIncidents() {
  document.getElementById("incident-detector-filter").addEventListener("change", event => {
    selectedDetector = event.target.value;
    if (activeInterfaceName) loadFindings(activeInterfaceName).catch(console.error);
  });
}
