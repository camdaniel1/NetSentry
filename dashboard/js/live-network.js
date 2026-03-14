import { DASHBOARD_CONFIG, LIVE_STREAM_URL } from "./api.js?v=9";
import { recordHealthPacket } from "./network-health.js?v=15";
import { escapeHtml, formatTime } from "./utils.js?v=2";

const MAX_DISPLAYED_ROWS = DASHBOARD_CONFIG.liveDisplayedRows;
const MAX_PENDING = DASHBOARD_CONFIG.livePendingPackets;
const RENDER_INTERVAL_MS = DASHBOARD_CONFIG.liveRenderIntervalMs;

const state = {
  receivedPackets: 0,
  rows: [],
  rowsByProtocol: new Map(),
  pending: [],
  rowsDirty: false,
  paused: false,
  protocolFilter: "all",
  protocols: new Set(),
  seenPackets: new Set(),
};

function rowHtml(packet) {
  return `<tr>
    <td class="mono">${packet.no}</td>
    <td class="mono">${formatTime(Number(packet.timestamp))}</td>
    <td class="mono">${escapeHtml(packet.src || "—")}</td>
    <td class="mono">${escapeHtml(packet.dst || "—")}</td>
    <td>${escapeHtml(packet.protocol || "—")}</td>
    <td class="mono">${Number(packet.caplen || 0).toLocaleString()}</td>
    <td>${escapeHtml(packet.info || "—")}</td>
  </tr>`;
}

function addPacket(packet) {
  const packetKey = `${packet.pcap_file || "live"}:${packet.no}`;
  if (state.seenPackets.has(packetKey)) return;
  state.seenPackets.add(packetKey);
  if (state.seenPackets.size > 5000) state.seenPackets.delete(state.seenPackets.values().next().value);

  state.receivedPackets += 1;
  packet.no = Number(packet.no) || state.receivedPackets;
  packet.protocol = String(packet.protocol || "unknown").toLowerCase();
  recordHealthPacket(packet);

  if (!state.protocols.has(packet.protocol)) {
    state.protocols.add(packet.protocol);
    const option = document.createElement("option");
    option.value = packet.protocol;
    option.textContent = packet.protocol.toUpperCase();
    document.getElementById("protocol-filter").appendChild(option);
  }

  state.pending.push(packet);
  if (state.pending.length > MAX_PENDING) state.pending.splice(0, state.pending.length - MAX_PENDING);
  state.rowsDirty = true;
}

function renderRows() {
  const visibleRows = state.protocolFilter === "all"
    ? state.rows
    : (state.rowsByProtocol.get(state.protocolFilter) || []);
  document.getElementById("live-body").innerHTML = visibleRows.length
    ? visibleRows.map(rowHtml).join("")
    : `<tr><td colspan="7" class="empty">no ${escapeHtml(state.protocolFilter === "all" ? "" : `${state.protocolFilter.toUpperCase()} `)}packets to display</td></tr>`;
}

function flush() {
  if (document.hidden || state.paused || !state.rowsDirty) return;
  if (state.pending.length) {
    const newestPackets = state.pending.reverse();
    state.rows = newestPackets.concat(state.rows).slice(0, MAX_DISPLAYED_ROWS);
    for (let index = newestPackets.length - 1; index >= 0; index -= 1) {
      const packet = newestPackets[index];
      const protocolRows = state.rowsByProtocol.get(packet.protocol) || [];
      protocolRows.unshift(packet);
      protocolRows.length = Math.min(protocolRows.length, MAX_DISPLAYED_ROWS);
      state.rowsByProtocol.set(packet.protocol, protocolRows);
    }
    state.pending = [];
  }
  renderRows();
  state.rowsDirty = false;
}

function setStreamStatus(status, text) {
  const element = document.getElementById("stream-status");
  element.className = `stream-status ${status}`;
  element.querySelector("span:last-child").textContent = text;
}

function connect() {
  const events = new EventSource(LIVE_STREAM_URL);
  events.onopen = () => setStreamStatus("connected", "live");
  events.onmessage = event => {
    try {
      const payload = JSON.parse(event.data);
      if (!payload.type || payload.type === "packet") addPacket(payload);
    } catch (error) {
      console.error("invalid live packet event", error);
    }
  };
  events.onerror = () => setStreamStatus("error", "reconnecting");
}

export function initLiveNetwork() {
  document.getElementById("live-pause").addEventListener("click", event => {
    state.paused = !state.paused;
    event.currentTarget.textContent = state.paused ? "Resume" : "Pause";
    event.currentTarget.classList.toggle("paused", state.paused);
    event.currentTarget.setAttribute("aria-pressed", String(state.paused));
    if (!state.paused) {
      state.rowsDirty = true;
      flush();
    }
  });
  document.getElementById("protocol-filter").addEventListener("change", event => {
    state.protocolFilter = event.target.value;
    renderRows();
  });
  connect();
  setInterval(flush, RENDER_INTERVAL_MS);
}
