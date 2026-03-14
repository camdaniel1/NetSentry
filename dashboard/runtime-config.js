// Compatibility defaults for generic static servers. The NetSentry dashboard
// server overrides this URL with values generated from config.yaml.
export default {
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
