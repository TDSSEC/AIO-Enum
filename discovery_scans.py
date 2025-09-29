#!/usr/bin/env python3
"""Discovery scans implemented in Python."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from config import ScanConfig
from utils import COLOURS, colour_text, run_command

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")


def nmap_settings(config: ScanConfig) -> None:
    """Echo the nmap and masscan settings to the terminal."""

    message = (
        f"\n[{colour_text('+', COLOURS.green)}] Using nmap settings:\n"
        f"    tcp port range: {colour_text(config.tcp_port_range, COLOURS.green)}\n"
        f"    udp port range: {colour_text(config.udp_port_range, COLOURS.green)}\n"
        f"    minimum host group: {colour_text(str(config.nmap_min_host), COLOURS.green)}\n"
        f"    minimum rate: {colour_text(str(config.nmap_min_rate), COLOURS.green)}"
    )
    print(message)


def _resolve_hostnames(targets: Iterable[str]) -> set[str]:
    resolved: set[str] = set()
    for target in targets:
        target = target.strip()
        if not target or target.startswith("#"):
            continue
        if IPV4_RE.match(target):
            resolved.add(target)
            continue
        try:
            result = run_command(["dig", "+short", target], capture_output=True, check=False)
        except Exception:
            continue
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and IPV4_RE.match(line):
                resolved.add(line)
    return resolved


def masscan_resolver(config: ScanConfig) -> Path:
    """Resolve hostnames in ``targets.ip`` for masscan consumption."""

    targets = config.targets_file.read_text().splitlines()
    resolved = _resolve_hostnames(targets)
    resolv_path = config.output_dir / "masscan" / "resolv.ip"
    resolv_path.write_text("\n".join(sorted(resolved)))
    return resolv_path


def massscan_port_scan(config: ScanConfig) -> None:
    """Execute masscan across the configured hosts."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Using masscan settings:\n"
        f"    tcp port range: {colour_text(config.tcp_port_range, COLOURS.green)}\n"
        f"    udp port range: {colour_text(config.udp_port_range, COLOURS.green)}\n"
        f"    max rate: {colour_text(str(config.masscan_max_rate), COLOURS.green)}"
    )
    print(f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('masscan', COLOURS.yellow)} scans")
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Resolving all "
        f"{colour_text('hostnames', COLOURS.yellow)} in targets.ip"
    )
    resolv_file = masscan_resolver(config)
    command = [
        "masscan",
        "--open",
        "-iL",
        str(resolv_file),
        "--excludefile",
        str(config.exclude_file),
        "-oG",
        str(config.output_dir / "masscan" / "scans" / "masscan.gnmap"),
        "-v",
        "-p",
        f"{config.tcp_port_range},U:{config.udp_port_range}",
        f"--max-rate={config.masscan_max_rate}",
    ]
    if config.masscan_interface:
        command.extend(["--interface", config.masscan_interface])
    run_command(command)


def ping_sweep(config: ScanConfig) -> None:
    """Run the standard nmap ping sweep."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('nmap', COLOURS.yellow)} scans"
    )
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running an {colour_text('nmap ping sweep', COLOURS.yellow)}"
        " for all ip in targets.ip"
    )
    command = [
        "nmap",
        "--open",
        "-sn",
        "-PE",
        "-iL",
        str(config.targets_file),
        "-oA",
        str(config.output_dir / "nmap" / "scans" / "PingSweep"),
        "--excludefile",
        str(config.exclude_file),
        "--min-hostgroup",
        str(config.nmap_min_host),
        f"--min-rate={config.nmap_min_rate}",
    ]
    run_command(command)
    ping_file = config.output_dir / "nmap" / "scans" / "PingSweep.gnmap"
    alive_file = config.output_dir / "nmap" / "alive.ip"
    hosts: set[str] = set()
    if ping_file.exists():
        for line in ping_file.read_text().splitlines():
            if "Up" in line:
                parts = line.split()
                if len(parts) >= 2:
                    hosts.add(parts[1])
    alive_file.write_text("\n".join(sorted(hosts)))


def ping_sweep_default(config: ScanConfig) -> None:
    """Ping sweep with default min-rate and min-hostgroup."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running {colour_text('nmap', COLOURS.yellow)} scans"
    )
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running an {colour_text('nmap ping sweep', COLOURS.yellow)}"
        " for all ip in targets.ip"
    )
    command = [
        "nmap",
        "--open",
        "-sn",
        "-PE",
        "-iL",
        str(config.targets_file),
        "-oA",
        str(config.output_dir / "nmap" / "scans" / "PingSweep"),
        "--excludefile",
        str(config.exclude_file),
        "--min-hostgroup",
        "50",
        "--min-rate=200",
    ]
    run_command(command)
    ping_file = config.output_dir / "nmap" / "scans" / "PingSweep.gnmap"
    alive_file = config.output_dir / "nmap" / "alive.ip"
    hosts: set[str] = set()
    if ping_file.exists():
        for line in ping_file.read_text().splitlines():
            if "Up" in line:
                parts = line.split()
                if len(parts) >= 2:
                    hosts.add(parts[1])
    alive_file.write_text("\n".join(sorted(hosts)))


def _nmap_port_command(
    config: ScanConfig,
    *,
    target_file: Path,
    enable_version: bool,
    enable_os: bool,
) -> list[str]:
    command = [
        "nmap",
        "--open",
        "-iL",
        str(target_file),
        "-sU",
        "-sS",
        "-Pn",
        "-n",
        "-oA",
        str(config.output_dir / "nmap" / "scans" / "portscan"),
        "-v",
        "-p",
        f"T:{config.tcp_port_range},U:{config.udp_port_range}",
        "--min-hostgroup",
        str(config.nmap_min_host),
        f"--min-rate={config.nmap_min_rate}",
    ]
    if enable_version:
        command.append("-sV")
    if enable_os:
        command.append("-O")
    return command


def nmap_fast_port_scan(config: ScanConfig) -> None:
    """Run an nmap TCP/UDP port scan, preferring alive hosts without service or OS detection."""

    alive_file = config.output_dir / "nmap" / "alive.ip"
    alive_exists = alive_file.exists()
    target = alive_file if alive_exists else config.targets_file
    target_desc = "nmap/alive.ip" if alive_exists else "targets.ip"
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running an {colour_text('nmap port scan', COLOURS.yellow)}"
        f" for all ip in {target_desc}. No version or OS detection"
    )
    command = _nmap_port_command(
        config,
        target_file=target,
        enable_version=False,
        enable_os=False,
    )
    run_command(command)


def nmap_all_hosts_port_scan(config: ScanConfig) -> None:
    """Run an nmap port scan (including service/OS detection) against alive targets when available."""

    alive_file = config.output_dir / "nmap" / "alive.ip"
    alive_exists = alive_file.exists()
    target = alive_file if alive_exists else config.targets_file
    target_desc = "nmap/alive.ip" if alive_exists else "targets.ip"
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running an {colour_text('nmap port scan', COLOURS.yellow)}"
        f" for all ip in {target_desc}"
    )
    command = _nmap_port_command(
        config,
        target_file=target,
        enable_version=True,
        enable_os=True,
    )
    run_command(command)


def nmap_port_scan(config: ScanConfig) -> None:
    """Run an nmap port scan against hosts that responded to the ping sweep."""

    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running an {colour_text('nmap port scan', COLOURS.yellow)}"
        " for all ip in nmap/alive.ip"
    )
    alive_file = config.output_dir / "nmap" / "alive.ip"
    target = alive_file if alive_file.exists() else config.targets_file
    command = _nmap_port_command(
        config,
        target_file=target,
        enable_version=True,
        enable_os=True,
    )
    run_command(command)
