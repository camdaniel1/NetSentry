import { LIVE_CONTROL_BASE } from "./api.js?v=3";
import { escapeHtml } from "./utils.js?v=3";

const MAX_RECENT = 2000;
const STORAGE_KEY = "netsentry.networkHealth.v1";
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

const state = {
  packets: 0,
  bytes: 0,
  recent: [],
  protocolCounts: new Map(),
  lastPacketNumbers: new Map(),
  sequenceGaps: 0,
  healthSamples: [],
  baselineRate: 0,
  seenPackets: new Set(),
  initialized: false,
  sessionId: null,
};

function resetState(sessionId = null) {
  state.packets = 0;
  state.bytes = 0;
  state.recent = [];
  state.protocolCounts = new Map();
  state.lastPacketNumbers = new Map();
  state.sequenceGaps = 0;
  state.healthSamples = [];
  state.baselineRate = 0;
  state.seenPackets = new Set();
  state.sessionId = sessionId;
}

function restore(expectedSessionId) {
  try {
    if (!expectedSessionId) {
      localStorage.removeItem(STORAGE_KEY);
      resetState();
      return;
    }
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (!saved || saved.sessionId !== expectedSessionId || Date.now() - Number(saved.savedAt) > MAX_AGE_MS) {
      localStorage.removeItem(STORAGE_KEY);
      resetState(expectedSessionId);
      return;
    }
    state.sessionId = expectedSessionId;
    state.packets = Number(saved.packets) || 0;
    state.bytes = Number(saved.bytes) || 0;
    state.baselineRate = Number(saved.baselineRate) || 0;
    state.sequenceGaps = Number(saved.sequenceGaps) || 0;
    state.healthSamples = Array.isArray(saved.healthSamples) ? saved.healthSamples.slice(-60) : [];
    state.recent = Array.isArray(saved.recent)
      ? saved.recent.filter(sample => Number(sample.time) >= Date.now() - 5000).slice(-MAX_RECENT)
      : [];
    state.protocolCounts = new Map(Array.isArray(saved.protocolCounts) ? saved.protocolCounts : []);
    state.lastPacketNumbers = new Map(Array.isArray(saved.lastPacketNumbers) ? saved.lastPacketNumbers : []);
    state.seenPackets = new Set(Array.isArray(saved.seenPackets) ? saved.seenPackets.slice(-5000) : []);
  } catch (error) {
    console.warn("could not restore network health state", error);
  }
}

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      savedAt: Date.now(),
      sessionId: state.sessionId,
      packets: state.packets,
      bytes: state.bytes,
      baselineRate: state.baselineRate,
      sequenceGaps: state.sequenceGaps,
      healthSamples: state.healthSamples,
      recent: state.recent,
      protocolCounts: [...state.protocolCounts.entries()],
      lastPacketNumbers: [...state.lastPacketNumbers.entries()],
      seenPackets: [...state.seenPackets].slice(-5000),
    }));
  } catch (error) {
    console.warn("could not persist network health state", error);
  }
}

export function recordHealthPacket(packet) {
  if (packet.session_id && packet.session_id !== state.sessionId) {
    resetState(packet.session_id);
    localStorage.removeItem(STORAGE_KEY);
  }
  const packetKey = `${packet.pcap_file || "live"}:${packet.no}`;
  if (state.seenPackets.has(packetKey)) return false;
  state.seenPackets.add(packetKey);
  if (state.seenPackets.size > 5000) {
    state.seenPackets.delete(state.seenPackets.values().next().value);
  }

  const caplen = Number(packet.caplen) || 0;
  const sampleTime = Number(packet.timestamp) * 1000 || Date.now();
  const protocol = String(packet.protocol || "unknown").toLowerCase();
  const packetNumber = Number(packet.no);
  const previousNumber = state.lastPacketNumbers.get(packet.pcap_file);

  state.packets += 1;
  state.bytes += caplen;
  state.protocolCounts.set(protocol, (state.protocolCounts.get(protocol) || 0) + 1);
  if (previousNumber && packetNumber > previousNumber + 1) {
    state.sequenceGaps += packetNumber - previousNumber - 1;
  }
  if (!previousNumber || packetNumber > previousNumber) {
    state.lastPacketNumbers.set(packet.pcap_file, packetNumber);
  }
  state.recent.push({ time: sampleTime, bytes: caplen });
  if (state.recent.length > MAX_RECENT) state.recent.splice(0, state.recent.length - MAX_RECENT);
  return true;
}

function renderHealthChart() {
  const container = document.getElementById("health-chart");
  if (state.healthSamples.length < 2) {
    container.innerHTML = `<div class="trend-empty">Collecting live traffic baseline…</div>`;
    return;
  }
  const width = 620, height = 190, padding = 14;
  const maxValue = Math.max(...state.healthSamples.flatMap(sample => [sample.rate, sample.baseline]), 1);
  const pointsFor = key => state.healthSamples.map((sample, index) => {
    const x = padding + index / 59 * (width - padding * 2);
    const y = height - padding - sample[key] / maxValue * (height - padding * 2);
    return `${x},${y}`;
  }).join(" ");
  container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Live traffic rate and baseline">
    <line class="chart-grid-line" x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}"/>
    <polyline class="chart-line" points="${pointsFor("rate")}"/>
    <polyline points="${pointsFor("baseline")}" fill="none" stroke="#ffc464" stroke-width="1.5" stroke-dasharray="5 4"/>
    <text class="chart-label" x="${padding}" y="12">Live</text><text class="chart-label" x="48" y="12" fill="#ffc464">Baseline</text>
  </svg>`;
}

function renderProtocols() {
  const values = [...state.protocolCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const container = document.getElementById("health-protocols");
  if (!values.length) {
    container.innerHTML = `<div class="trend-empty">Waiting for live packets…</div>`;
    return;
  }
  const max = values[0][1];
  container.innerHTML = values.map(([protocol, count]) => `<div class="bar-row"><div class="bar-label">${escapeHtml(protocol.toUpperCase())}</div><div class="bar-track"><div class="bar-fill" style="width:${count / max * 100}%"></div></div><div class="bar-value">${count.toLocaleString()}</div></div>`).join("");
}

function update() {
  const currentRate = state.recent.filter(sample => sample.time >= Date.now() - 5000).length / 5;
  state.baselineRate = state.baselineRate === 0 ? currentRate : state.baselineRate * .92 + currentRate * .08;
  const deviation = state.baselineRate > .1
    ? Math.abs(currentRate - state.baselineRate) / state.baselineRate * 100
    : 0;
  const health = deviation > 100 ? "Degraded" : deviation > 50 ? "Watch" : "Normal";
  const stateElement = document.getElementById("health-state");
  stateElement.textContent = state.packets < 10 ? "Learning" : health;
  stateElement.className = `health-state health-${health.toLowerCase()}`;
  document.getElementById("health-rate").textContent = currentRate.toFixed(1);
  document.getElementById("health-baseline").textContent = state.baselineRate.toFixed(1);
  document.getElementById("health-deviation").textContent = `${deviation.toFixed(0)}%`;
  document.getElementById("health-gaps").textContent = state.sequenceGaps.toLocaleString();
  state.healthSamples.push({ rate: currentRate, baseline: state.baselineRate });
  if (state.healthSamples.length > 60) state.healthSamples.shift();
  renderHealthChart();
  renderProtocols();
  persist();
}

export function initNetworkHealth() {
  if (state.initialized) return;
  state.initialized = true;
  fetch(`${LIVE_CONTROL_BASE}/interfaces`, { cache: "no-store" })
    .then(response => response.ok ? response.json() : Promise.reject(new Error("unavailable")))
    .then(data => {
      restore(data.session_id);
      document.getElementById("health-interface").textContent = data.active?.human_name || "No active interface";
      update();
      setInterval(update, 1000);
    })
    .catch(() => {
      resetState();
      document.getElementById("health-interface").textContent = "Interface unavailable";
      update();
      setInterval(update, 1000);
    });
}
