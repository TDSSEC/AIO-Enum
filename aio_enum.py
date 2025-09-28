#!/usr/bin/env python3
"""Python entrypoint for the AIO-Enum toolkit."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Tuple

from config import ScanConfig
from discovery_scans import (
    massscan_port_scan,
    nmap_all_hosts_port_scan,
    nmap_fast_port_scan,
    nmap_port_scan,
    nmap_settings,
    ping_sweep,
)
from nmap_nse_scans import discovery_scans, nse, other_scans
from parsers import combiner, csv_parser, html_parser, port_parser, summary, summary_ping_sweep
from top_ports_data import TOP_100, TOP_1000
from utils import COLOURS, abort, colour_text, ensure_tools_installed, run_command


TOOLS = [
    "masscan",
    "dig",
    "curl",
    "nmap",
    "ike-scan",
    "nbtscan",
    "dirb",
    "xsltproc",
]


def check_root() -> None:
    if os.geteuid() != 0:
        abort(
            f"\n[{colour_text('!', COLOURS.red)}] must be {colour_text('root', COLOURS.red)}"
        )


def check_dependencies() -> None:
    missing = ensure_tools_installed(TOOLS)
    if missing:
        abort(
            f"\n[{colour_text('!', COLOURS.red)}] Ensure the following tools are installed: "
            f"{', '.join(sorted(missing))}"
        )


def setup_environment(config: ScanConfig) -> None:
    targets_file = config.targets_file
    exclude_file = config.exclude_file

    if not targets_file.exists():
        targets_file.touch()
        abort(
            f"\n[{colour_text('+', COLOURS.green)}] Populate the {colour_text(str(targets_file), COLOURS.yellow)} file"
        )
    if targets_file.stat().st_size == 0:
        abort(
            f"\n[{colour_text('!', COLOURS.red)}] targets.ip file isn't populated with target IP addresses"
        )
    if not exclude_file.exists():
        exclude_file.touch()

    directories = [
        config.output_dir / "scans",
        config.output_dir / "open-ports",
        config.output_dir / "nse_scans",
        config.output_dir / "masscan" / "scans",
        config.output_dir / "nmap" / "scans",
        config.output_dir / "csv_and_html_files",
    ]
    for folder in directories:
        folder.mkdir(parents=True, exist_ok=True)


def ip_checker() -> None:
    print(
        f"\n {colour_text('[!]', COLOURS.red)} ENSURE YOU ARE SOURCING FROM AN INSCOPE IP {COLOURS.reset}"
    )
    try:
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as response:
            pub_ip = response.read().decode().strip()
    except (urllib.error.URLError, TimeoutError):
        pub_ip = "Unavailable"
    print(f"\nYour Public IP is: {colour_text(pub_ip or 'Unavailable', COLOURS.red)}")

    result = run_command(["ip", "-o", "-4", "addr", "list"], capture_output=True, check=False)
    internal = []
    for line in result.stdout.splitlines():
        if "127.0.0.1" in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            internal.append(parts[3].split("/")[0])
    print(f"\nYour Internal IP(s) are: {colour_text(', '.join(internal) or 'Unavailable', COLOURS.red)}")
    print(f"\n {colour_text('[!]', COLOURS.red)} Ctrl+C now if you do not want to proceed")
    for i in range(5, 0, -1):
        print(f"Continuing in {colour_text(str(i), COLOURS.red)}", end="\r", flush=True)
        time.sleep(1)
    print("".ljust(40), end="\r")


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python rewrite of AIO-Enum",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-1", "--default", dest="scantype", action="store_const", const="default",
                       help="Identify Alive IPs and Ports")
    group.add_argument("-2", "--quick", dest="scantype", action="store_const", const="quick",
                       help="Portscan hosts replying to ICMP")
    group.add_argument("-3", "--scans", dest="scantype", action="store_const", const="scans",
                       help="Masscan, Nmap and Nmap NSE scripts")
    group.add_argument("-4", "--all", dest="scantype", action="store_const", const="all",
                       help="Masscan, Nmap, Nmap NSE scripts and Web dir/page enum")
    group.add_argument("-5", "--nmap", dest="scantype", action="store_const", const="nmap",
                       help="Nmap and NSE scripts - No masscan")
    group.add_argument("-6", "--icmp", dest="scantype", action="store_const", const="icmp",
                       help="Nmap ping sweep only")
    parser.add_argument("-v", "--version", action="store_true", help="Print version and exit")
    parser.add_argument("--tcpportrange", dest="tcpportrange", help="TCP port range in nmap format")
    parser.add_argument("--top100", action="store_true", help="Top 100 most common TCP Ports")
    parser.add_argument("--top1000", action="store_true", help="Top 1000 most common TCP Ports")
    parser.add_argument("--udpportrange", default="53,69,123,161,500,1434", help="UDP port range in nmap format")
    parser.add_argument("--nmap-minhost", type=int, default=50, help="Minimum hostgroup size for nmap")
    parser.add_argument("--nmap-minrate", type=int, default=200, help="Minimum rate for nmap")
    parser.add_argument("--masscan-maxrate", type=int, default=500, help="Maximum rate for masscan")
    parser.add_argument("--masscan-interface", help="Network interface that masscan should use")
    parser.add_argument("--outputdir", help="Output directory for all files")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> Tuple[ScanConfig, str]:
    if args.version:
        print("version 1.3")
        raise SystemExit(0)

    tcp_ports = args.tcpportrange or "1-65535"
    if args.top1000:
        tcp_ports = TOP_1000
    elif args.top100:
        tcp_ports = TOP_100

    output_dir = Path(args.outputdir).expanduser().resolve() if args.outputdir else Path.cwd() / dt.datetime.now().strftime("%Y-%m-%d-%H:%M")

    config = ScanConfig(
        output_dir=output_dir,
        targets_file=Path("targets.ip").resolve(),
        exclude_file=Path("exclude.ip").resolve(),
        tcp_port_range=tcp_ports,
        udp_port_range=args.udpportrange,
        nmap_min_host=args.nmap_minhost,
        nmap_min_rate=args.nmap_minrate,
        masscan_max_rate=args.masscan_maxrate,
        masscan_interface=args.masscan_interface,
    )
    scantype = args.scantype or "help"
    return config, scantype


def execute_scans(config: ScanConfig, scantype: str) -> None:
    if scantype == "help":
        print("Usage: python aio_enum.py [options]\n")
        print("Use -h/--help to display available options.")
        return

    check_dependencies()
    setup_environment(config)
    ip_checker()

    if scantype == "icmp":
        ping_sweep(config)
        summary_ping_sweep(config)
        return
    nmap_settings(config)

    if scantype in {"default", "quick", "scans", "all"}:
        massscan_port_scan(config)

    ping_sweep(config)

    if scantype == "default":
        nmap_fast_port_scan(config)
    elif scantype == "quick":
        nmap_port_scan(config)
    elif scantype in {"scans", "all"}:
        nmap_port_scan(config)
    elif scantype == "nmap":
        nmap_all_hosts_port_scan(config)

    combiner(config)
    _, host_ports = port_parser(config)

    if scantype in {"scans", "all", "nmap"}:
        nse(config)
        other_scans(config)
    if scantype == "all":
        discovery_scans(config)

    summary(config, host_ports)
    csv_parser(config)
    html_parser(config)


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("\n[+] No options provided!")
        argv = ["--help"]
    args = parse_arguments(argv)
    config, scantype = build_config(args)
    check_root()
    execute_scans(config, scantype)


if __name__ == "__main__":
    main()
