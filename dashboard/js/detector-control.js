import { LIVE_CONTROL_BASE } from "./api.js?v=9";

async function openDetectorPicker(statusElement) {
  statusElement.textContent = "Loading detectors…";
  try {
    const response = await fetch(`${LIVE_CONTROL_BASE}/detectors`, { cache: "no-store" });
    if (!response.ok) throw new Error(`detector list failed (${response.status})`);
    const data = await response.json();
    statusElement.textContent = "";

    const dialog = document.createElement("dialog");
    dialog.className = "interface-dialog";
    dialog.innerHTML = `<h2>Active detectors</h2><div class="subtitle">Checked detectors inspect new packets immediately.</div>`;
    const choices = document.createElement("div");
    choices.className = "detector-choices";
    data.detectors.forEach(detector => {
      const label = document.createElement("label");
      label.className = "detector-choice";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = detector.name;
      checkbox.checked = detector.enabled;
      const name = document.createElement("span");
      name.textContent = detector.name;
      label.append(checkbox, name);
      choices.appendChild(label);
    });
    const actions = document.createElement("div");
    actions.className = "detector-actions";
    const cancel = document.createElement("button");
    cancel.className = "live-control";
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => dialog.close());
    const apply = document.createElement("button");
    apply.className = "action-button";
    apply.textContent = "Apply";
    apply.addEventListener("click", async () => {
      apply.disabled = true;
      const enabled = [...choices.querySelectorAll("input:checked")].map(input => input.value);
      const save = await fetch(`${LIVE_CONTROL_BASE}/detectors`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      const result = await save.json();
      if (!save.ok) {
        apply.disabled = false;
        statusElement.textContent = result.detail || "could not update detectors";
        return;
      }
      statusElement.textContent = `${result.enabled.length} detector(s) active`;
      dialog.close();
    });
    actions.append(cancel, apply);
    dialog.append(choices, actions);
    dialog.addEventListener("close", () => dialog.remove());
    document.body.appendChild(dialog);
    dialog.showModal();
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

export function initDetectorControl() {
  document.getElementById("incident-detector-toggle").addEventListener("click", () => {
    openDetectorPicker(document.getElementById("incident-detector-state"));
  });
}
