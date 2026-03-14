import { LIVE_CONTROL_BASE } from "./api.js?v=3";

async function switchInterface(selected, statusElement, dialog) {
  try {
    dialog.close();
    statusElement.textContent = "Switching interface…";
    const switchResponse = await fetch(`${LIVE_CONTROL_BASE}/interface`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: selected.trim() }),
    });
    const result = await switchResponse.json();
    if (!switchResponse.ok) throw new Error(result.detail || `switch failed (${switchResponse.status})`);

    // Session health and packet rows describe one interface only. Discard them
    // before reloading so no data from the previous capture remains visible.
    localStorage.removeItem("netsentry.networkHealth.v1");
    const activePanel = statusElement.closest(".panel")?.id.replace(/^panel-/, "");
    if (activePanel) sessionStorage.setItem("netsentry.activePanel", activePanel);
    window.location.reload();
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

function showInterfacePicker(data, statusElement) {
  const dialog = document.createElement("dialog");
  dialog.className = "interface-dialog";
  const heading = document.createElement("h2");
  heading.textContent = "Choose capture interface";
  const help = document.createElement("div");
  help.className = "subtitle";
  help.textContent = "Click the network interface you want NetSentry to probe.";
  const choices = document.createElement("div");
  choices.className = "interface-choices";

  data.interfaces.forEach(item => {
    const choice = document.createElement("button");
    choice.type = "button";
    choice.className = "interface-choice";
    const name = document.createElement("strong");
    name.textContent = item.human_name;
    const detail = document.createElement("span");
    detail.textContent = item.ip_addr || "No IP address";
    choice.append(name, detail);
    if (item.pcap_name === data.active?.pcap_name) {
      choice.classList.add("active");
      choice.disabled = true;
      detail.textContent += " · Active";
    } else {
      choice.addEventListener("click", () => switchInterface(item.pcap_name, statusElement, dialog));
    }
    choices.appendChild(choice);
  });

  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "live-control interface-cancel";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => dialog.close());
  dialog.append(heading, help, choices, cancel);
  dialog.addEventListener("close", () => dialog.remove());
  document.body.appendChild(dialog);
  dialog.showModal();
}

async function chooseInterface(statusElement) {
  statusElement.textContent = "Loading interfaces…";
  try {
    const response = await fetch(`${LIVE_CONTROL_BASE}/interfaces`, { cache: "no-store" });
    if (!response.ok) throw new Error(`interface list failed (${response.status})`);
    const data = await response.json();
    if (!data.interfaces.length) throw new Error("no capture interfaces found");
    statusElement.textContent = "";
    showInterfacePicker(data, statusElement);
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

export function initInterfaceControls() {
  fetch(`${LIVE_CONTROL_BASE}/interfaces`, { cache: "no-store" })
    .then(response => response.ok ? response.json() : Promise.reject(new Error("unavailable")))
    .then(data => {
      document.querySelectorAll("[data-active-interface]").forEach(element => {
        element.textContent = data.active?.human_name || "No active interface";
      });
    })
    .catch(() => {
      document.querySelectorAll("[data-active-interface]").forEach(element => {
        element.textContent = "Interface unavailable";
      });
    });

  document.querySelectorAll("[data-change-interface]").forEach(button => {
    button.addEventListener("click", () => {
      const statusElement = document.getElementById(button.dataset.statusTarget);
      chooseInterface(statusElement);
    });
  });
}
