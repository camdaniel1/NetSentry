import { API_BASE, apiHeaders, setIdentity, setPermissions } from "./api.js";
import { escapeHtml, formatTime } from "./utils.js?v=2";

let onRoleChanged = async () => {};

export async function loadAccess() {
  const actor = document.getElementById("access-actor").value.trim() || "local-operator";
  const role = document.getElementById("access-role").value;
  setIdentity(actor, role);
  const response = await fetch(`${API_BASE}/access`, { headers: apiHeaders() });
  if (!response.ok) throw new Error(`access request failed: ${response.status}`);
  const data = await response.json();
  setPermissions(data.permissions);
  document.getElementById("active-permissions").innerHTML = data.permissions.map(permission => `<span class="permission-chip">${escapeHtml(permission)}</span>`).join("");
  document.getElementById("role-definitions").innerHTML = Object.entries(data.roles).map(([name, permissions]) => `<div class="role-card ${name === data.role ? "active" : ""}"><strong>${escapeHtml(name)}</strong><div class="muted" style="font-size:10px;margin-top:4px">${permissions.map(escapeHtml).join(" · ")}</div></div>`).join("");
  document.getElementById("audit-body").innerHTML = data.audit_log.length
    ? data.audit_log.map(entry => `<tr><td>${formatTime(entry.timestamp)}</td><td>${escapeHtml(entry.actor)}</td><td>${escapeHtml(entry.role)}</td><td>${escapeHtml(entry.action)}</td><td class="mono">${escapeHtml(entry.target ? entry.target.slice(0, 12) : "—")}</td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">No audited actions yet</td></tr>`;
  return data;
}

export function initAccess(callback) {
  onRoleChanged = callback || (async () => {});
  document.getElementById("access-role").addEventListener("change", async () => {
    await loadAccess();
    await onRoleChanged();
  });
  document.getElementById("access-actor").addEventListener("change", loadAccess);
  document.addEventListener("netsentry:audit-changed", loadAccess);
}
