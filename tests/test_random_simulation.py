import random

import scripts.run_random_simulation as runner


def test_pool_contains_the_ten_detector_simulations():
    assert len(runner.SIMULATIONS) == 10
    assert len({simulation.module for simulation in runner.SIMULATIONS}) == 10


def test_build_command_handles_special_arguments(monkeypatch):
    monkeypatch.setattr(runner.sys, "executable", "python")
    evil_twin = next(item for item in runner.SIMULATIONS if item.name == "evil twin")
    dhcp = next(item for item in runner.SIMULATIONS if item.name == "rogue DHCP")
    evil_command = runner.build_command(
        evil_twin, "hard", target="192.0.2.10", interface="Wi-Fi", ssid="LabWifi",
    )
    dhcp_command = runner.build_command(
        dhcp, "easy", target="192.0.2.1", interface="Wi-Fi", ssid="LabWifi",
    )
    assert "--ssid" in evil_command and "--target" not in evil_command
    assert dhcp_command[-2:] == ["--server-ip", "192.0.2.1"]


def test_count_runs_sequential_random_selections_without_execution(capsys):
    result = runner.run_random_simulations(
        target="192.0.2.10", interface="Wi-Fi", ssid="LabWifi",
        count=3, rng=random.Random(7), dry_run=True,
    )
    output = capsys.readouterr().out
    assert result == 0
    assert "[1/3]" in output
    assert "[2/3]" in output
    assert "[3/3]" in output
