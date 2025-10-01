#!/usr/bin/env python3
"""Parsers and reporting helpers for the Python rewrite of AIO-Enum."""
from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from shutil import copy2
from typing import DefaultDict

from config import ScanConfig
from utils import COLOURS, colour_text, run_command


NESSUS_RISK_FACTOR_TO_SEVERITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
    "none": 0,
}


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


def parse_nessus_report(config: ScanConfig, host_ports: dict[str, set[str]]) -> None:
    """Parse a Nessus report and compare the findings with discovery data."""

    if not config.nessus_file:
        return

    nessus_path = config.nessus_file
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('parser', COLOURS.yellow)} for "
        f"{colour_text('Nessus report correlation', COLOURS.yellow)}"
    )

    if not nessus_path.exists():
        print(
            f"[{colour_text('!', COLOURS.red)}] Nessus file {colour_text(str(nessus_path), COLOURS.yellow)} "
            "was not found. Skipping Nessus parsing."
        )
        return

    try:
        tree = ET.parse(nessus_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        print(
            f"[{colour_text('!', COLOURS.red)}] Unable to parse Nessus report: {colour_text(str(exc), COLOURS.yellow)}"
        )
        return

    alive_hosts = set(_hosts_from_file(config.output_dir / "alive.ip"))
    normalised_host_ports = {
        host: {entry.lower() for entry in ports}
        for host, ports in host_ports.items()
    }

    findings: list[dict[str, object]] = []
    host_discovery_status: dict[str, bool] = {}
    hosts_in_report: set[str] = set()

    for report_host in root.findall(".//ReportHost"):
        host_name = (report_host.get("name") or "").strip()
        host_ip = host_name
        for tag in report_host.findall("./HostProperties/tag"):
            if tag.get("name") == "host-ip" and tag.text:
                host_ip = tag.text.strip()
                break

        identifiers: list[str] = []
        for candidate in (host_ip, host_name):
            if candidate and candidate not in identifiers:
                identifiers.append(candidate)

        canonical_host = identifiers[0] if identifiers else "unknown"
        hosts_in_report.add(canonical_host)

        host_alive = any(identifier in alive_hosts for identifier in identifiers)
        if canonical_host not in host_discovery_status:
            host_discovery_status[canonical_host] = host_alive
        else:
            host_discovery_status[canonical_host] = (
                host_discovery_status[canonical_host] or host_alive
            )
        for report_item in report_host.findall("./ReportItem"):
            port_raw = (report_item.get("port") or "").strip()
            protocol = (report_item.get("protocol") or "").strip().lower()
            service = (report_item.get("svc_name") or "").strip()
            plugin_id = (report_item.get("pluginID") or "").strip()
            plugin_name = (report_item.get("pluginName") or "").strip()
            severity_raw = (report_item.get("severity") or "").strip()
            risk_factor = (report_item.findtext("risk_factor") or "").strip()

            try:
                port_int = int(port_raw)
            except ValueError:
                port_int = None

            port_value = str(port_int) if port_int is not None else port_raw
            port_proto = f"{port_value}/{protocol}" if protocol else port_value
            port_proto_normalised = port_proto.lower()

            host_port_confirmed = False
            for identifier in identifiers:
                if (
                    identifier in normalised_host_ports
                    and port_proto_normalised in normalised_host_ports[identifier]
                ):
                    host_port_confirmed = True
                    break

            severity: int | None
            try:
                severity = int(severity_raw)
            except ValueError:
                severity = None

            if severity is None:
                risk_factor_normalised = risk_factor.lower()
                severity = NESSUS_RISK_FACTOR_TO_SEVERITY.get(risk_factor_normalised)

            if severity is None or severity not in {1, 2, 3, 4}:
                continue

            notes: list[str] = []
            if not host_alive:
                notes.append("Host not present in discovery data (alive.ip)")
            if not host_port_confirmed and protocol:
                notes.append("Port/protocol not found in discovery data (open-ports)")
            elif not host_port_confirmed:
                notes.append("Port not found in discovery data (open-ports)")

            finding = {
                "host": canonical_host,
                "host_aliases": identifiers,
                "port": port_int if port_int is not None else port_value,
                "protocol": protocol,
                "service": service,
                "severity": severity,
                "risk_factor": risk_factor,
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "in_alive": host_alive,
                "port_confirmed": host_port_confirmed,
                "notes": notes,
            }
            findings.append(finding)

    nessus_output_dir = config.output_dir / "nessus"
    nessus_output_dir.mkdir(parents=True, exist_ok=True)

    json_path = nessus_output_dir / "nessus-findings.json"
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)

    csv_path = nessus_output_dir / "nessus-findings.csv"
    csv_fields = [
        "host",
        "host_aliases",
        "port",
        "protocol",
        "service",
        "severity",
        "risk_factor",
        "plugin_id",
        "plugin_name",
        "in_alive",
        "port_confirmed",
        "notes",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "host": finding["host"],
                    "host_aliases": ", ".join(finding["host_aliases"]),
                    "port": finding["port"],
                    "protocol": finding["protocol"],
                    "service": finding["service"],
                    "severity": finding["severity"],
                    "risk_factor": finding["risk_factor"],
                    "plugin_id": finding["plugin_id"],
                    "plugin_name": finding["plugin_name"],
                    "in_alive": finding["in_alive"],
                    "port_confirmed": finding["port_confirmed"],
                    "notes": "; ".join(finding["notes"]),
                }
            )

    total_hosts = len(hosts_in_report)
    confirmed_hosts = sum(1 for alive in host_discovery_status.values() if alive)
    missing_hosts = [host for host, alive in host_discovery_status.items() if not alive]
    total_findings = len(findings)
    discrepancy_findings = sum(1 for finding in findings if finding["notes"])

    print(
        f"[{colour_text('+', COLOURS.green)}] Parsed {colour_text(str(total_findings), COLOURS.yellow)} findings "
        f"across {colour_text(str(total_hosts), COLOURS.yellow)} hosts."
    )
    print(
        f"[{colour_text('+', COLOURS.green)}] {colour_text(str(confirmed_hosts), COLOURS.yellow)} hosts confirmed by "
        f"discovery data; {colour_text(str(len(missing_hosts)), COLOURS.yellow)} hosts missing from alive.ip."
    )
    print(
        f"[{colour_text('+', COLOURS.green)}] {colour_text(str(discrepancy_findings), COLOURS.yellow)} findings "
        "flagged for review."
    )
    if missing_hosts:
        print(
            f"[{colour_text('!', COLOURS.red)}] Hosts missing from discovery data: "
            f"{colour_text(', '.join(sorted(missing_hosts)), COLOURS.yellow)}"
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
