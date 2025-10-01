"""Tests for parsers helpers."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import ScanConfig
from parsers import parse_nessus_report


def _make_config(tmp_path: Path, nessus_file: Path) -> ScanConfig:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "alive.ip").write_text("192.0.2.10\n")

    targets_file = tmp_path / "targets.ip"
    targets_file.write_text("192.0.2.10\n")
    exclude_file = tmp_path / "exclude.ip"
    exclude_file.write_text("")

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
        nessus_file=nessus_file,
    )


def test_parse_nessus_report_filters_informational(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "sample.nessus"
    config = _make_config(tmp_path, fixture)

    host_ports = {"192.0.2.10": {"22/tcp", "25/tcp", "3389/tcp", "443/tcp"}}

    parse_nessus_report(config, host_ports)

    output_dir = config.output_dir / "nessus"
    json_path = output_dir / "nessus-findings.json"
    csv_path = output_dir / "nessus-findings.csv"

    data = json.loads(json_path.read_text())
    assert {finding["plugin_id"] for finding in data} == {"101", "102", "103", "104"}

    severity_by_plugin = {finding["plugin_id"]: finding["severity"] for finding in data}
    assert severity_by_plugin == {"101": 1, "102": 2, "103": 3, "104": 4}

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert {row["plugin_id"] for row in rows} == {"101", "102", "103", "104"}
    for row in rows:
        assert row["severity"] == str(severity_by_plugin[row["plugin_id"]])
