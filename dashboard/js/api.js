export const API_BASE = "http://127.0.0.1:8000";
export const LIVE_STREAM_URL = "http://127.0.0.1:8765/events";
export const LIVE_CONTROL_BASE = "http://127.0.0.1:8765";

const identity = {
  actor: "local-operator",
  role: "analyst",
  permissions: new Set(),
};

export function setIdentity(actor, role) {
  identity.actor = actor || "local-operator";
  identity.role = role || "analyst";
}

export function setPermissions(permissions) {
  identity.permissions = new Set(permissions);
}

export function hasPermission(permission) {
  return identity.permissions.has(permission);
}

export function apiHeaders(json = false) {
  const headers = {
    "X-NetSentry-Actor": identity.actor,
    "X-NetSentry-Role": identity.role,
  };
  if (json) headers["Content-Type"] = "application/json";
  return headers;
}
