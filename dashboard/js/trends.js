import { API_BASE, DASHBOARD_CONFIG } from "./api.js?v=9";
import { escapeHtml, formatTime } from "./utils.js?v=2";

function renderActivityChart(activity) {
  const container = document.getElementById("activity-chart");
  if (!activity.length || !activity.some(point => point.count > 0)) {
    container.innerHTML = `<div class="trend-empty">No findings in this period</div>`;
    return;
  }
  const width = 720, height = 190;
  const padding = { top: 12, right: 12, bottom: 25, left: 34 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const maxCount = Math.max(...activity.map(point => Number(point.count)), 1);
  const points = activity.map((point, index) => ({
    x: padding.left + index / Math.max(activity.length - 1, 1) * chartWidth,
    y: padding.top + chartHeight - Number(point.count) / maxCount * chartHeight,
  }));
  const line = points.map(point => `${point.x},${point.y}`).join(" ");
  const area = `${padding.left},${padding.top + chartHeight} ${line} ${padding.left + chartWidth},${padding.top + chartHeight}`;
  const grid = [0, .5, 1].map(ratio => {
    const y = padding.top + chartHeight - ratio * chartHeight;
    return `<line class="chart-grid-line" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"/><text class="chart-label" x="${padding.left - 8}" y="${y + 3}" text-anchor="end">${Math.round(maxCount * ratio)}</text>`;
  }).join("");
  const first = new Date(activity[0].timestamp * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric" });
  const last = new Date(activity.at(-1).timestamp * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric" });
  container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Findings over time">${grid}<polygon class="chart-area" points="${area}"/><polyline class="chart-line" points="${line}"/><text class="chart-label" x="${padding.left}" y="${height - 4}">${escapeHtml(first)}</text><text class="chart-label" x="${width - padding.right}" y="${height - 4}" text-anchor="end">${escapeHtml(last)}</text></svg>`;
}

function renderDetectorChart(detectors) {
  const container = document.getElementById("detector-chart");
  if (!detectors.length) {
    container.innerHTML = `<div class="trend-empty">No detector activity</div>`;
    return;
  }
  const maxCount = Math.max(...detectors.map(item => Number(item.count)), 1);
  container.innerHTML = detectors.map(item => `<div class="bar-row"><div class="bar-label" title="${escapeHtml(item.detector_name)}">${escapeHtml(item.detector_name)}</div><div class="bar-track"><div class="bar-fill" style="width:${Number(item.count) / maxCount * 100}%"></div></div><div class="bar-value">${Number(item.count).toLocaleString()}</div></div>`).join("");
}

function renderTopOffenders(offenders) {
  document.getElementById("offender-body").innerHTML = offenders.length
    ? offenders.map((item, index) => `<tr><td class="mono">${index + 1}. ${escapeHtml(item.src_ip)}</td><td>${Number(item.count).toLocaleString()}</td><td>${Number(item.detectors).toLocaleString()}</td><td>${formatTime(Number(item.last_seen))}</td></tr>`).join("")
    : `<tr><td colspan="4" class="empty">No source ips in this period</td></tr>`;
}

export async function loadTrends() {
  const hours = document.getElementById("trend-range").value;
  const response = await fetch(`${API_BASE}/trends?hours=${encodeURIComponent(hours)}&top_limit=${DASHBOARD_CONFIG.trendTopSources}`);
  if (!response.ok) throw new Error(`trend request failed: ${response.status}`);
  const trends = await response.json();
  const summary = trends.summary;
  document.getElementById("trends-stats").innerHTML = `<div class="stat-card"><div class="count">${Number(summary.total).toLocaleString()}</div><div class="label">findings in period</div></div><div class="stat-card"><div class="count">${Number(summary.last_hour).toLocaleString()}</div><div class="label">findings last hour</div></div><div class="stat-card"><div class="count">${Number(summary.offenders).toLocaleString()}</div><div class="label">unique ips</div></div><div class="stat-card"><div class="count">${Number(summary.detectors).toLocaleString()}</div><div class="label">active detectors</div></div>`;
  renderActivityChart(trends.activity);
  renderDetectorChart(trends.detectors);
  renderTopOffenders(trends.top_offenders);
}

export function initTrends() {
  const range = document.getElementById("trend-range");
  if ([...range.options].some(option => Number(option.value) === DASHBOARD_CONFIG.trendHours)) {
    range.value = String(DASHBOARD_CONFIG.trendHours);
  }
  range.addEventListener("change", () => {
    loadTrends().catch(() => {
      document.getElementById("activity-chart").innerHTML = `<div class="trend-empty">Could not load trend data</div>`;
    });
  });
}
