#!/usr/bin/env python3
"""Shared configuration structures for the Python rewrite of AIO-Enum."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ScanConfig:
    """Container for command-line options shared across modules."""

    output_dir: Path
    targets_file: Path
    exclude_file: Path
    tcp_port_range: str
    udp_port_range: str
    nmap_min_host: int
    nmap_min_rate: int
    masscan_max_rate: int
    masscan_interface: str | None
    nessus_file: Path | None

