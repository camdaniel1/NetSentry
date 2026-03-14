"""Serve only the NetSentry dashboard under /dashboard/."""

from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


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
        if self._prepare_dashboard_path():
            super().do_GET()

    def do_HEAD(self) -> None:
        if self._prepare_dashboard_path():
            super().do_HEAD()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the NetSentry dashboard only.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    handler = partial(DashboardHandler, directory=str(DASHBOARD_DIR))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"dashboard: http://{args.host}:{args.port}/dashboard/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
