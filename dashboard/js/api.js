const fallbackConfig = {
  host: "127.0.0.1",
  apiPort: 8000,
  livePort: 8765,
  findingsLimit: 50,
  casesLimit: 15,
  timelineLimit: 100,
  evidenceFilesLimit: 15,
  trendHours: 24,
  trendTopSources: 8,
  refreshIntervalMs: 5000,
  liveRenderIntervalMs: 250,
  liveDisplayedRows: 150,
  livePendingPackets: 500,
  healthRecentSamples: 2000,
  healthSavedStateMaxAgeHours: 24,
};

let config = fallbackConfig;
try {
  const runtimeModule = await import("../runtime-config.js");
  config = { ...fallbackConfig, ...runtimeModule.default };
} catch (error) {
  console.warn("Using built-in dashboard defaults; runtime configuration is unavailable.", error);
}

export const DASHBOARD_CONFIG = config;
export const API_BASE = `http://${config.host}:${config.apiPort}`;
export const LIVE_CONTROL_BASE = `http://${config.host}:${config.livePort}`;
export const LIVE_STREAM_URL = `${LIVE_CONTROL_BASE}/events`;
