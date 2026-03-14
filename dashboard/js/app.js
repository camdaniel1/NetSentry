import { initAccess, loadAccess } from "./access-control.js?v=3";
import { initCases, loadCases, loadVaultFiles, refreshCasePermissions } from "./cases.js?v=13";
import { initDetectorControl } from "./detector-control.js?v=12";
import { initIncidents, refreshIncidents } from "./incidents.js?v=12";
import { initInterfaceControls } from "./interface-control.js?v=5";
import { initLiveNetwork } from "./live-network.js?v=15";
import { initNetworkHealth } from "./network-health.js?v=15";
import { initTimeline, loadTimeline, refreshTimelinePermissions, setTimelineCases } from "./timeline.js?v=14";
import { initTrends, loadTrends } from "./trends.js?v=3";

function initNavigation() {
  const activatePanel = panelName => {
    const navItem = document.querySelector(`.nav-item[data-panel="${panelName}"]`);
    const panel = document.getElementById(`panel-${panelName}`);
    if (!navItem || !panel) return;
    document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(item => item.classList.remove("active"));
    navItem.classList.add("active");
    panel.classList.add("active");
  };

  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      sessionStorage.setItem("netsentry.activePanel", item.dataset.panel);
      activatePanel(item.dataset.panel);
    });
  });
  activatePanel(sessionStorage.getItem("netsentry.activePanel") || "incidents");
}

initNavigation();
initIncidents();
initDetectorControl();
initInterfaceControls();
initTrends();
initCases(setTimelineCases);
initTimeline();
initAccess(async () => {
  refreshCasePermissions();
  refreshTimelinePermissions();
  await Promise.all([loadCases(), loadVaultFiles(), refreshIncidents()]);
});
initNetworkHealth();
initLiveNetwork();

async function initializeData() {
  try {
    await loadAccess();
    refreshCasePermissions();
    refreshTimelinePermissions();
    await Promise.all([loadCases(), loadVaultFiles()]);
    await Promise.all([refreshIncidents(), loadTrends(), loadTimeline()]);
  } catch (error) {
    console.error("dashboard initialization failed", error);
  }
}

initializeData();
setInterval(refreshIncidents, 5000);
setInterval(() => loadTrends().catch(console.error), 5000);
