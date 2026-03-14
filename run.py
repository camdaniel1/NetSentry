"""Start the NetSentry API, dashboard server, and capture pipeline together."""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

from capture.interfaces import list_interfaces, print_interface_err
from settings import setting


PROJECT_ROOT = Path(__file__).resolve().parent
API_HOST = str(setting("server.host"))
API_PORT = int(setting("server.api_port"))
DASHBOARD_PORT = int(setting("server.dashboard_port"))
STARTUP_TIMEOUT_SECONDS = float(setting("server.startup_timeout_seconds"))
SHUTDOWN_TIMEOUT_SECONDS = float(setting("server.shutdown_timeout_seconds"))
PORT_PROBE_TIMEOUT_SECONDS = float(setting("server.port_probe_timeout_seconds"))


def _port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=PORT_PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def _start_service(name: str, command: list[str], port: int) -> subprocess.Popen:
    if _port_is_open(API_HOST, port):
        raise RuntimeError(f"{name} cannot start: port {port} is already in use")

    print(f"[launcher] starting {name}...", flush=True)
    process = subprocess.Popen(command, cwd=PROJECT_ROOT)
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"{name} exited during startup with code {return_code}")
        if _port_is_open(API_HOST, port):
            print(f"[launcher] {name} ready on {API_HOST}:{port}", flush=True)
            return process
        time.sleep(0.1)

    process.terminate()
    raise RuntimeError(f"{name} did not become ready within {STARTUP_TIMEOUT_SECONDS} seconds")


def _stop_process(name: str, process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    print(f"[launcher] stopping {name}...", flush=True)
    process.terminate()
    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)


def run(interface: str) -> int:
    api_process = None
    dashboard_process = None
    pipeline_process = None

    try:
        api_process = _start_service(
            "API",
            [
                sys.executable,
                "-m",
                "uvicorn",
                "api.main:app",
                "--host",
                API_HOST,
                "--port",
                str(API_PORT),
            ],
            API_PORT,
        )
        dashboard_process = _start_service(
            "dashboard",
            [
                sys.executable,
                "api/dashboard_server.py",
                "--port",
                str(DASHBOARD_PORT),
                "--host",
                API_HOST,
            ],
            DASHBOARD_PORT,
        )

        print(
            f"[launcher] dashboard: http://{API_HOST}:{DASHBOARD_PORT}/dashboard/",
            flush=True,
        )
        print(f"[launcher] starting capture pipeline on {interface!r}...", flush=True)
        pipeline_process = subprocess.Popen(
            [sys.executable, "core/pipeline.py", interface],
            cwd=PROJECT_ROOT,
        )
        return pipeline_process.wait()
    except KeyboardInterrupt:
        print("\n[launcher] shutdown requested", flush=True)
        return 130
    except RuntimeError as error:
        print(f"[launcher] {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        _stop_process("capture pipeline", pipeline_process)
        _stop_process("dashboard", dashboard_process)
        _stop_process("API", api_process)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the NetSentry API, dashboard, and capture pipeline.",
    )
    parser.add_argument(
        "interface",
        nargs="*",
        help="interface IP, PCAP name, system name, or human-readable name",
    )
    parser.add_argument(
        "-i",
        "--interfaces",
        action="store_true",
        help="print available capture interfaces and exit",
    )
    args = parser.parse_args()
    if args.interfaces:
        print_interface_err(list_interfaces())
        return 0
    if not args.interface:
        parser.error("an interface is required (use -i to list interfaces)")
    return run(" ".join(args.interface))


if __name__ == "__main__":
    raise SystemExit(main())
