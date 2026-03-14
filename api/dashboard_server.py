"""Serve only the NetSentry dashboard under /dashboard/."""

from __future__ import annotations

import argparse
import json
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from settings import setting

DASHBOARD_DIR = PROJECT_ROOT / "dashboard"


class DashboardHandler(SimpleHTTPRequestHandler):
    """Reject repository paths and expose only dashboard static assets."""

    def _prepare_dashboard_path(self) -> bool:
        parsed = urlsplit(self.path)
        if parsed.path == "/dashboard":
            self.send_response(308)
            self.send_header("Location", "/dashboard/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        if not parsed.path.startswith("/dashboard/"):
            self.send_error(404)
            return False
        relative_path = parsed.path[len("/dashboard"):]
        self.path = relative_path + (f"?{parsed.query}" if parsed.query else "")
        return True

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/dashboard/runtime-config.js":
            payload = {
                "host": str(setting("server.host")),
                "apiPort": int(setting("server.api_port")),
                "livePort": int(setting("server.live_port")),
                "findingsLimit": int(setting("dashboard.findings_limit")),
                "casesLimit": int(setting("dashboard.cases_limit")),
                "timelineLimit": int(setting("dashboard.timeline_limit")),
                "evidenceFilesLimit": int(setting("dashboard.evidence_files_limit")),
                "trendHours": int(setting("dashboard.trend_hours")),
                "trendTopSources": int(setting("dashboard.trend_top_sources")),
                "refreshIntervalMs": int(setting("dashboard.refresh_interval_ms")),
                "liveRenderIntervalMs": int(setting("dashboard.live_render_interval_ms")),
                "liveDisplayedRows": int(setting("dashboard.live_displayed_rows")),
                "livePendingPackets": int(setting("dashboard.live_pending_packets")),
                "healthRecentSamples": int(setting("dashboard.health_recent_samples")),
                "healthSavedStateMaxAgeHours": float(setting("dashboard.health_saved_state_max_age_hours")),
            }
            body = f"export default {json.dumps(payload)};\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self._prepare_dashboard_path():
            super().do_GET()

    def do_HEAD(self) -> None:
        if self._prepare_dashboard_path():
            super().do_HEAD()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the NetSentry dashboard only.")
    parser.add_argument("--host", default=str(setting("server.host")))
    parser.add_argument("--port", type=int, default=int(setting("server.dashboard_port")))
    args = parser.parse_args()
    handler = partial(DashboardHandler, directory=str(DASHBOARD_DIR))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"dashboard: http://{args.host}:{args.port}/dashboard/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
