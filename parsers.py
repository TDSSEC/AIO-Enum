#!/usr/bin/env python3
"""Parsers and reporting helpers for the Python rewrite of AIO-Enum."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from shutil import copy2
from typing import DefaultDict

from config import ScanConfig
from utils import COLOURS, colour_text, run_command


def _hosts_from_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _extract_hosts_from_gnmap(file_path: Path) -> set[str]:
    hosts: set[str] = set()
    if not file_path.exists():
        return hosts
    for line in file_path.read_text().splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            hosts.add(parts[1])
    return hosts


def combiner(config: ScanConfig) -> None:
    """Combine masscan and nmap results into unified directories."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Combining {colour_text('nmap', COLOURS.yellow)} and {colour_text('masscan', COLOURS.yellow)} scans"
    )
    (config.output_dir / "alive.ip").touch()
    masscan_alive = config.output_dir / "masscan" / "alive.ip"
    masscan_alive.touch()

    scans_dir = config.output_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    for source_dir in (config.output_dir / "masscan" / "scans", config.output_dir / "nmap" / "scans"):
        if source_dir.exists():
            for file in source_dir.iterdir():
                if file.is_file():
                    copy2(file, scans_dir / file.name)

    masscan_gnmap = config.output_dir / "masscan" / "scans" / "masscan.gnmap"
    masscan_hosts = _extract_hosts_from_gnmap(masscan_gnmap)
    masscan_alive.write_text("\n".join(sorted(masscan_hosts)))

    nmap_alive = config.output_dir / "nmap" / "alive.ip"
    nmap_hosts = set(_hosts_from_file(nmap_alive))
    combined = masscan_hosts.union(nmap_hosts)
    (config.output_dir / "alive.ip").write_text("\n".join(sorted(combined)))


def _parse_gnmap_files(scans_dir: Path) -> tuple[DefaultDict[int, dict[str, set[str]]], dict[str, set[str]]]:
    port_map: DefaultDict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    host_ports: dict[str, set[str]] = defaultdict(set)
    for gnmap in scans_dir.glob("*.gnmap"):
        for line in gnmap.read_text().splitlines():
            if not line.startswith("Host:"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            host = parts[1]
            if "Ports:" not in line:
                continue
            port_section = line.split("Ports:", 1)[1]
            for entry in port_section.split(","):
                entry = entry.strip()
                if not entry or "/open/" not in entry:
                    continue
                fields = entry.split("/")
                if len(fields) < 3:
                    continue
                try:
                    port = int(fields[0])
                except ValueError:
                    continue
                protocol = fields[2]
                port_map[port][protocol].add(host)
                host_ports.setdefault(host, set()).add(f"{port}/{protocol}")
    return port_map, host_ports


def port_parser(config: ScanConfig) -> tuple[DefaultDict[int, dict[str, set[str]]], dict[str, set[str]]]:
    """Create ``open-ports`` files per port based on gnmap output."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('parser', COLOURS.yellow)} for {colour_text('nse', COLOURS.yellow)} scans"
    )
    scans_dir = config.output_dir / "scans"
    port_map, host_ports = _parse_gnmap_files(scans_dir)

    open_ports_dir = config.output_dir / "open-ports"
    open_ports_dir.mkdir(parents=True, exist_ok=True)

    for file in open_ports_dir.glob("*.txt"):
        if file.is_file() and file.name[0].isdigit():
            file.unlink()

    for port, protocols in port_map.items():
        hosts: set[str] = set()
        for proto_hosts in protocols.values():
            hosts.update(proto_hosts)
        if hosts:
            (open_ports_dir / f"{port}.txt").write_text("\n".join(sorted(hosts)))
    return port_map, host_ports


def csv_parser(config: ScanConfig) -> None:
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('parser', COLOURS.yellow)} for {colour_text('NMAP XML to CSV', COLOURS.yellow)}"
    )
    scans_dir = config.output_dir / "scans"
    xml_files = sorted(scans_dir.glob("*.xml"))
    if not xml_files:
        return
    output_dir = config.output_dir / "csv_and_html_files"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "xsltproc",
            "-o",
            str(output_dir / "nmap-results.csv"),
            "xml-to-csv.xsl",
            str(xml_files[0]),
        ]
    )


def html_parser(config: ScanConfig) -> None:
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('parser', COLOURS.yellow)} for {colour_text('NMAP XML to HTML', COLOURS.yellow)}"
    )
    scans_dir = config.output_dir / "scans"
    xml_files = sorted(scans_dir.glob("*.xml"))
    if not xml_files:
        return
    output_dir = config.output_dir / "csv_and_html_files"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "xsltproc",
            "-o",
            str(output_dir / "nmap-results.html"),
            str(xml_files[0]),
        ]
    )


def summary(config: ScanConfig, host_ports: dict[str, set[str]]) -> None:
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Generating a summary of the scans..."
    )
    open_ports_dir = config.output_dir / "open-ports"
    open_ports_dir.mkdir(parents=True, exist_ok=True)
    for ip, ports in host_ports.items():
        with (open_ports_dir / f"{ip}.txt").open("w", encoding="utf-8") as handle:
            for port in sorted(ports):
                handle.write(f"{port}\n")

    alive_hosts = _hosts_from_file(config.output_dir / "alive.ip")
    total_ports = {port for ports in host_ports.values() for port in ports}
    summary_message = (
        f"\n[{colour_text('+', COLOURS.green)}] there are {len(alive_hosts)} {colour_text('alive hosts', COLOURS.yellow)} "
        f"and {len(total_ports)} {colour_text('unique ports/services', COLOURS.yellow)}"
    )
    print(summary_message)
    with (config.output_dir / "discovered_ports.txt").open("a", encoding="utf-8") as handle:
        handle.write(summary_message + "\n")


def summary_ping_sweep(config: ScanConfig) -> None:
    alive_file = config.output_dir / "nmap" / "alive.ip"
    alive_hosts = _hosts_from_file(alive_file)
    print(
        f"\n[{colour_text('+', COLOURS.green)}] {colour_text('There are', COLOURS.yellow)} {len(alive_hosts)}"
        f" {colour_text('alive hosts', COLOURS.yellow)}"
    )
