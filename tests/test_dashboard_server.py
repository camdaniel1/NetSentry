"""Tests for the dashboard-only static file server."""

from functools import partial
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

from api.dashboard_server import DASHBOARD_DIR, DashboardHandler


def _request(path: str) -> tuple[int, str | None]:
    handler = partial(DashboardHandler, directory=str(DASHBOARD_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("GET", path)
        response = connection.getresponse()
        response.read()
        return response.status, response.getheader("Location")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_serves_dashboard_route():
    status, _ = _request("/dashboard/")
    assert status == 200


def test_redirects_dashboard_without_trailing_slash():
    status, location = _request("/dashboard")
    assert status == 308
    assert location == "/dashboard/"


def test_rejects_repository_files_and_root_listing():
    assert _request("/")[0] == 404
    assert _request("/run.py")[0] == 404
