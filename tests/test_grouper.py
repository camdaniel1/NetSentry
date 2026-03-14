from types import SimpleNamespace

import correlation.grouper as grouper
import core.pipeline as pipeline


def finding(id, timestamp, src="192.0.2.10", dst="192.0.2.20",
            detector="port_scan", interface="iface-a"):
    return SimpleNamespace(
        id=id, timestamp=timestamp, src_ip=src, dst_ip=dst,
        detector_name=detector, interface_name=interface, incident_id=None,
    )


def test_clusters_related_findings_across_ten_minutes():
    clusters = grouper._cluster_by_ip_and_time([
        finding(1, 0), finding(2, 10 * 60),
    ])
    assert [[item.id for item in cluster] for cluster in clusters] == [[1, 2]]


def test_keeps_interfaces_separate():
    clusters = grouper._cluster_by_ip_and_time([
        finding(1, 0, interface="iface-a"),
        finding(2, 1, interface="iface-b"),
    ])
    assert len(clusters) == 2


def test_syn_floods_group_by_target_despite_changing_source():
    clusters = grouper._cluster_by_ip_and_time([
        finding(1, 0, src="192.0.2.10", detector="syn_flood"),
        finding(2, 1, src="192.0.2.11", detector="syn_flood"),
    ])
    assert len(clusters) == 1


def test_run_grouping_reuses_recent_incident_and_reports_processed_cluster(monkeypatch):
    items = [finding(1, 100), finding(2, 101)]
    assignments = []
    monkeypatch.setattr(grouper, "get_ungrouped_findings", lambda limit=500: items)
    monkeypatch.setattr(grouper, "find_related_incident", lambda item, since: "existing-case")
    monkeypatch.setattr(grouper, "assign_incident_id", lambda id, incident: assignments.append((id, incident)))
    assert grouper.run_grouping() == 1
    assert assignments == [(1, "existing-case"), (2, "existing-case")]


def test_idle_maintenance_advances_timestamp(monkeypatch):
    calls = []
    monkeypatch.setattr(pipeline.time, "time", lambda: 100.0)
    monkeypatch.setattr(pipeline, "_run_maintenance", lambda: calls.append(True))
    assert pipeline._maybe_run_maintenance(0.0) == 100.0
    assert calls == [True]
    assert pipeline._maybe_run_maintenance(90.0) == 90.0
