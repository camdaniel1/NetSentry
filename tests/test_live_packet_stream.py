"""Tests for dashboard packet replay in the live pipeline stream."""

import json
import queue

from core.pipeline import LivePacketStream


def test_late_subscriber_receives_packet_history_but_not_findings():
    stream = LivePacketStream()
    stream.publish({"type": "packet", "no": 1})
    stream.publish({"type": "finding", "detector": "test"})
    stream.publish({"type": "packet", "no": 2})

    subscriber = stream.subscribe()

    assert json.loads(subscriber.get_nowait())["no"] == 1
    assert json.loads(subscriber.get_nowait())["no"] == 2
    try:
        subscriber.get_nowait()
    except queue.Empty:
        pass
    else:
        raise AssertionError("only packet events should be replayed")


def test_reset_discards_packets_from_previous_interface():
    stream = LivePacketStream()
    stream.publish({"type": "packet", "no": 1, "interface": "old"})

    stream.reset()
    subscriber = stream.subscribe()

    try:
        subscriber.get_nowait()
    except queue.Empty:
        pass
    else:
        raise AssertionError("reset should clear replay history")
