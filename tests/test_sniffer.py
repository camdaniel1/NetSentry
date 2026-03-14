"""Unit tests for capture.sniffer without opening a capture interface."""

import queue
from types import SimpleNamespace

import pytest
from scapy.all import Ether, IP, UDP, raw

import capture.sniffer as sniffer_module
from capture.sniffer import Sniffer


def test_start_configures_and_starts_async_sniffer(monkeypatch):
    created = []

    class FakeAsyncSniffer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.started = False
            created.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(sniffer_module, "AsyncSniffer", FakeAsyncSniffer)
    sniffer = Sniffer("eth0", "tcp")

    sniffer.start()

    instance = created[0]
    assert instance.started is True
    assert instance.kwargs == {"iface": "eth0", "filter": "tcp", "prn": sniffer._on_captured, "store": False}


def test_empty_filter_is_passed_as_none(monkeypatch):
    captured = {}

    class FakeAsyncSniffer:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def start(self):
            pass

    monkeypatch.setattr(sniffer_module, "AsyncSniffer", FakeAsyncSniffer)
    Sniffer("eth0").start()

    assert captured["filter"] is None


def test_stop_stops_active_sniffer_and_clears_it():
    fake = SimpleNamespace(stopped=False)
    fake.stop = lambda: setattr(fake, "stopped", True)
    sniffer = Sniffer("eth0")
    sniffer._sniffer = fake

    sniffer.stop()

    assert fake.stopped is True
    assert sniffer._sniffer is None


def test_context_manager_starts_and_stops(monkeypatch):
    events = []
    monkeypatch.setattr(Sniffer, "start", lambda self: events.append("start"))
    monkeypatch.setattr(Sniffer, "stop", lambda self: events.append("stop"))

    with Sniffer("eth0") as value:
        assert isinstance(value, Sniffer)

    assert events == ["start", "stop"]


def test_on_captured_queues_raw_packet():
    scapy_packet = Ether() / IP() / UDP()
    scapy_packet.time = 456.25
    sniffer = Sniffer("eth0", queue_maxsize=1)

    sniffer._on_captured(scapy_packet)
    packet = sniffer.packet_queue.get_nowait()

    assert packet.timestamp == 456.25
    assert packet.data == raw(scapy_packet)
    assert packet.caplen == packet.length == len(packet.data)
    assert packet.scapy_packet is scapy_packet


def test_on_captured_drops_packet_when_queue_is_full():
    sniffer = Sniffer("eth0", queue_maxsize=1)
    sniffer.packet_queue.put_nowait("existing")

    sniffer._on_captured(Ether())

    assert sniffer.packet_queue.qsize() == 1
    assert sniffer.packet_queue.get_nowait() == "existing"
    with pytest.raises(queue.Empty):
        sniffer.packet_queue.get_nowait()