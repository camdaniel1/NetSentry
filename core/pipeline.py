"""
core/pipeline.py

Minimal NetSentry pipeline:
    Sniffer -> PcapWriter -> Detectors -> Correlation and Severity ->
    Send response -> Capture evidence -> Forensic report -> Dashboard

Usage:
    python core/pipeline.py <name | pcap_name | ip>

Example:
    python core/pipeline.py 192.168.1.25
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Allow this file to be run directly with:
#     python core/pipeline.py <interface>
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from capture.pcap_writer import PcapWriter
from capture.sniffer import Sniffer
from capture.interfaces import (
    InterfaceInfo,
    find_interface,
    interface_payload,
    list_interfaces,
    print_interface_err,
)
from capture.packet_normalizer import normalize_packet
from correlation.grouper import run_grouping
from core.event import Event
from detectors.arp_spoof import ArpSpoofDetector
from detectors.base import Detector
from detectors.dns_tunneling import DnsTunnelingDetector
from detectors.port_scan import PortScanDetector
from detectors.rogue_dhcp import RogueDhcpDetector
from detectors.syn_flood import SynFloodDetector
from evidence.custody import record_custody_event
from response.alerting import dispatch_alert
from storage.event_store import init_db, save_finding
from settings import setting

# how often (in seconds) to run grouping and log evidence custody —
# these don't need to happen on every single packet
MAINTENANCE_INTERVAL_SECONDS = float(setting("capture.maintenance_interval_seconds"))

# registered detectors — adding a new one is one line here, nothing
# else in the pipeline needs to change (this is the pluggability
# detectors/base.py's interface was built for)
DETECTORS: list[Detector] = [
    ArpSpoofDetector(),
    PortScanDetector(),
    DnsTunnelingDetector(),
    SynFloodDetector(),
    RogueDhcpDetector(),
]
DETECTOR_LOCK = threading.Lock()
ENABLED_DETECTORS = {detector.name for detector in DETECTORS}


RED = "\033[31m"
RESET = "\033[0m"


LIVE_HOST = str(setting("server.host"))
LIVE_PORT = int(setting("server.live_port"))
LIVE_REPLAY_SIZE = int(setting("capture.live_replay_packets"))
SUBSCRIBER_QUEUE_BUFFER = int(setting("capture.subscriber_queue_buffer"))
STREAM_HEARTBEAT_SECONDS = float(setting("capture.stream_heartbeat_seconds"))
INTERFACE_SWITCH_TIMEOUT_SECONDS = float(setting("capture.interface_switch_timeout_seconds"))
CAPTURE_SESSION_ID = str(uuid.uuid4())


class LivePacketStream:
    """Small in-process SSE broadcaster for the dashboard live-data panel."""

    def __init__(self) -> None:
        self._subscribers: set[queue.Queue[str]] = set()
        self._packet_history: deque[str] = deque(maxlen=LIVE_REPLAY_SIZE)
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue[str]:
        subscriber: queue.Queue[str] = queue.Queue(maxsize=LIVE_REPLAY_SIZE + SUBSCRIBER_QUEUE_BUFFER)
        with self._lock:
            for message in self._packet_history:
                subscriber.put_nowait(message)
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, payload: dict[str, object]) -> None:
        message = json.dumps(payload, separators=(",", ":"))
        with self._lock:
            if payload.get("type") == "packet":
                self._packet_history.append(message)
            subscribers = tuple(self._subscribers)

        for subscriber in subscribers:
            try:
                subscriber.put_nowait(message)
            except queue.Full:
                # Keep the stream live rather than letting a slow browser stall capture.
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(message)
                except (queue.Empty, queue.Full):
                    pass

    def reset(self) -> None:
        """Discard packets captured on the previously selected interface."""
        with self._lock:
            self._packet_history.clear()


LIVE_STREAM = LivePacketStream()
INTERFACE_SWITCHES: queue.Queue[tuple[str, queue.Queue[dict[str, object]]]] = queue.Queue()
ACTIVE_INTERFACE: InterfaceInfo | None = None


class LivePacketHandler(BaseHTTPRequestHandler):
    """Expose captured packet metadata as Server-Sent Events on /events."""

    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if self.path == "/interfaces":
            self._send_json(200, {
                "session_id": CAPTURE_SESSION_ID,
                "active": interface_payload(ACTIVE_INTERFACE) if ACTIVE_INTERFACE else None,
                "interfaces": [interface_payload(info) for info in list_interfaces()],
            })
            return

        if self.path == "/detectors":
            with DETECTOR_LOCK:
                enabled = set(ENABLED_DETECTORS)
            self._send_json(200, {
                "detectors": [
                    {"name": detector.name, "enabled": detector.name in enabled}
                    for detector in DETECTORS
                ]
            })
            return

        if self.path != "/events":
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        subscriber = LIVE_STREAM.subscribe()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    message = subscriber.get(timeout=STREAM_HEARTBEAT_SECONDS)
                    chunk = f"data: {message}\n\n".encode("utf-8")
                except queue.Empty:
                    chunk = b": keepalive\n\n"
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            LIVE_STREAM.unsubscribe(subscriber)

    def do_POST(self) -> None:
        if self.path == "/detectors":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                requested = {str(name) for name in payload.get("enabled", [])}
            except (ValueError, TypeError, json.JSONDecodeError):
                self._send_json(400, {"detail": "invalid detector selection"})
                return
            known = {detector.name for detector in DETECTORS}
            unknown = requested - known
            if unknown:
                self._send_json(400, {"detail": f"unknown detector(s): {', '.join(sorted(unknown))}"})
                return
            with DETECTOR_LOCK:
                ENABLED_DETECTORS.clear()
                ENABLED_DETECTORS.update(requested)
            self._send_json(200, {"enabled": sorted(requested)})
            return

        if self.path != "/interface":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            value = str(payload.get("interface", "")).strip()
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"detail": "invalid JSON request"})
            return
        if not value:
            self._send_json(400, {"detail": "interface is required"})
            return

        response: queue.Queue[dict[str, object]] = queue.Queue(maxsize=1)
        INTERFACE_SWITCHES.put((value, response))
        try:
            result = response.get(timeout=INTERFACE_SWITCH_TIMEOUT_SECONDS)
        except queue.Empty:
            self._send_json(504, {"detail": "interface switch timed out"})
            return
        self._send_json(int(result.pop("status", 200)), result)

    def log_message(self, format: str, *args: object) -> None:
        return


def start_live_server() -> ThreadingHTTPServer | None:
    """Start the dashboard SSE endpoint without adding another dependency."""
    try:
        server = ThreadingHTTPServer((LIVE_HOST, LIVE_PORT), LivePacketHandler)
    except OSError as exc:
        print(f"live dashboard stream unavailable on {LIVE_HOST}:{LIVE_PORT}: {exc}")
        return None

    thread = threading.Thread(target=server.serve_forever, name="netsentry-live", daemon=True)
    thread.start()
    print(f"live dashboard stream: http://{LIVE_HOST}:{LIVE_PORT}/events")
    return server


def run(interface: InterfaceInfo) -> None:
    """
    Capture packets, write each one to rotating PCAP storage, and run
    every registered detector over it. A detector firing turns into an
    Event (Finding + computed severity + evidence location), which gets
    stored and alerted on (if severe enough)
    (dry-run only, if critical enough) — the pipeline described at the
    top of this file, now actually connected end to end.
    """
    global ACTIVE_INTERFACE
    ACTIVE_INTERFACE = interface
    print(
        f"listening on {interface.human_name} "
        f"({interface.ip_addr or 'no IP'})... (ctrl+c to stop)"
    )

    init_db()

    sniffer = Sniffer(interface.pcap_name)
    live_server = start_live_server()
    last_maintenance = time.time()

    try:
        with PcapWriter() as writer:
            sniffer.start()

            while True:
                try:
                    requested_value, response = INTERFACE_SWITCHES.get_nowait()
                except queue.Empty:
                    pass
                else:
                    requested = find_interface(requested_value)
                    if requested is None:
                        response.put({"status": 404, "detail": "interface not found"})
                    else:
                        try:
                            sniffer.stop()
                            replacement = Sniffer(requested.pcap_name)
                            replacement.start()
                        except Exception as exc:
                            try:
                                sniffer.start()
                            except Exception:
                                pass
                            response.put({"status": 500, "detail": f"could not switch interface: {exc}"})
                        else:
                            sniffer = replacement
                            ACTIVE_INTERFACE = requested
                            interface = requested
                            LIVE_STREAM.reset()
                            LIVE_STREAM.publish({"type": "reset", "interface": requested.human_name})
                            print(f"switched capture to {requested.human_name} ({requested.ip_addr or 'no IP'})")
                            response.put({"interface": interface_payload(requested)})

                try:
                    packet = sniffer.packet_queue.get(timeout=1)
                except queue.Empty:
                    last_maintenance = _maybe_run_maintenance(last_maintenance)
                    continue

                location = writer.write(packet)
                normalized_packet = normalize_packet(packet)

                LIVE_STREAM.publish(
                    {
                        "type": "packet",
                        "no": location.packet_number,
                        "pcap_file": location.file,
                        "timestamp": packet.timestamp,
                        "caplen": packet.caplen,
                        "src": normalized_packet.src,
                        "dst": normalized_packet.dst,
                        "protocol": normalized_packet.protocol,
                        "info": normalized_packet.info,
                        "stored_len": location.len,
                        "offset": location.offset,
                        "interface": interface.human_name,
                        "session_id": CAPTURE_SESSION_ID,
                    }
                )

                # run every registered detector over this packet
                with DETECTOR_LOCK:
                    enabled_detectors = set(ENABLED_DETECTORS)
                for detector in DETECTORS:
                    if detector.name not in enabled_detectors:
                        continue
                    try:
                        finding = detector.process_packet(normalized_packet)
                        if finding is None:
                            continue

                        event = Event.from_finding(finding)
                        event.attach_evidence(
                            location.file, location.offset, location.len, location.packet_number
                        )

                        save_finding(
                            finding,
                            interface_name=interface.pcap_name,
                            interface_human_name=interface.human_name,
                            pcap_file=event.pcap_file,
                            pcap_packet_number=event.pcap_packet_number,
                            pcap_offset=event.pcap_offset,
                            pcap_length=event.pcap_length,
                        )

                        dispatch_alert(finding)
                        LIVE_STREAM.publish({
                            "type": "finding",
                            "detector": finding.detector_name,
                            "severity": event.severity.value,
                            "summary": finding.summary,
                        })
                    except Exception:
                        import traceback
                        print(f"{RED}[pipeline] {detector.name} raised an exception "
                              f"processing a packet — skipping this packet, "
                              f"pipeline continues:{RESET}")
                        traceback.print_exc()

                if time.time() - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
                    _run_maintenance()
                    last_maintenance = time.time()

    except KeyboardInterrupt:
        print("\nStopping...")

    finally:
        sniffer.stop()
        if live_server is not None:
            live_server.shutdown()
            live_server.server_close()


def _maybe_run_maintenance(last_maintenance: float) -> float:
    if time.time() - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
        _run_maintenance()
        return time.time()
    return last_maintenance


def _run_maintenance() -> None:
    """
    Periodic housekeeping: group any ungrouped findings into incidents.
    Evidence custody logging happens at rotation time inside PcapWriter's
    caller, not here — this is purely the correlation pass.
    """
    created = run_grouping()
    if created:
        print(f"[maintenance] grouped findings into {created} incident(s)")


def main() -> int:
    available = list_interfaces()

    if len(sys.argv) < 2:
        print(f"{RED}no interface given{RESET} — available interfaces:")
        print_interface_err(available)
        return 1

    value = sys.argv[1]

    interface = next(
        (
            info
            for info in available
            if value
            in {
                info.ip_addr,
                info.pcap_name,
                info.sys_name,
                info.human_name,
            }
        ),
        None,
    )

    if interface is None:
        print(f"{RED}'{value}' is not a valid interface.{RESET}")
        print("available interfaces:")
        print_interface_err(available)
        return 1

    run(interface)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
