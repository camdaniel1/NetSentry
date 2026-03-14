"""Tests for the combined NetSentry launcher."""

import run as launcher


class FakeProcess:
    def __init__(self, return_code=None):
        self.return_code = return_code
        self.terminated = False

    def poll(self):
        return self.return_code

    def wait(self, timeout=None):
        if self.return_code is None and timeout is None:
            self.return_code = 0
        return self.return_code

    def terminate(self):
        self.terminated = True
        self.return_code = 0

    def kill(self):
        self.return_code = -9


def test_run_starts_services_in_order_and_cleans_them_up(monkeypatch):
    events = []
    api = FakeProcess()
    dashboard = FakeProcess()
    pipeline = FakeProcess()

    def start_service(name, command, port):
        events.append((name, port))
        return api if name == "API" else dashboard

    def start_pipeline(command, cwd):
        events.append(("pipeline", command[-1]))
        return pipeline

    monkeypatch.setattr(launcher, "_start_service", start_service)
    monkeypatch.setattr(launcher.subprocess, "Popen", start_pipeline)

    assert launcher.run("Wi-Fi") == 0
    assert events == [("API", 8000), ("dashboard", 8080), ("pipeline", "Wi-Fi")]
    assert api.terminated is True
    assert dashboard.terminated is True


def test_main_joins_multiword_interface(monkeypatch):
    captured = []
    monkeypatch.setattr(launcher.sys, "argv", ["run.py", "Npcap", "Loopback", "Adapter"])
    monkeypatch.setattr(launcher, "run", lambda interface: captured.append(interface) or 0)

    assert launcher.main() == 0
    assert captured == ["Npcap Loopback Adapter"]
