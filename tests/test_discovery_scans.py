"""Tests for discovery scan helpers."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import discovery_scans
from config import ScanConfig


def _make_config(tmp_path: Path) -> ScanConfig:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "nmap").mkdir()
    targets_file = tmp_path / "targets.ip"
    targets_file.write_text("192.0.2.1\n")
    exclude_file = tmp_path / "exclude.ip"
    exclude_file.write_text("198.51.100.1\n")
    return ScanConfig(
        output_dir=output_dir,
        targets_file=targets_file,
        exclude_file=exclude_file,
        tcp_port_range="1-1024",
        udp_port_range="1-1024",
        nmap_min_host=1,
        nmap_min_rate=10,
        masscan_max_rate=1000,
        masscan_interface=None,
    )


def test_nmap_fast_port_scan_prefers_alive_list(tmp_path, monkeypatch):
    config = _make_config(tmp_path)
    alive_file = config.output_dir / "nmap" / "alive.ip"
    alive_file.write_text("203.0.113.1\n")
    captured: dict[str, list[str]] = {}

    def fake_run_command(command):
        captured["command"] = command

    monkeypatch.setattr(discovery_scans, "run_command", fake_run_command)

    discovery_scans.nmap_fast_port_scan(config)

    assert str(alive_file) == captured["command"][3]


def test_nmap_all_hosts_port_scan_falls_back_without_alive(tmp_path, monkeypatch):
    config = _make_config(tmp_path)
    alive_file = config.output_dir / "nmap" / "alive.ip"
    if alive_file.exists():
        alive_file.unlink()
    captured: dict[str, list[str]] = {}

    def fake_run_command(command):
        captured["command"] = command

    monkeypatch.setattr(discovery_scans, "run_command", fake_run_command)

    discovery_scans.nmap_all_hosts_port_scan(config)

    assert str(config.targets_file) == captured["command"][3]
