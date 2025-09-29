#!/usr/bin/env python3
"""Nmap NSE and auxiliary scans implemented in Python."""
from __future__ import annotations

import socket
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from config import ScanConfig
from utils import COLOURS, colour_text, run_command


@dataclass(frozen=True)
class NmapTask:
    description: str
    port_file: str
    output_name: str
    safe_arguments: Sequence[str]
    unsafe_arguments: Sequence[str] | None = None

    def arguments(self, allow_unsafe: bool) -> Sequence[str]:
        if allow_unsafe and self.unsafe_arguments:
            return self.unsafe_arguments
        return self.safe_arguments


def _hosts_from_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    return hosts


def _run_nmap_task(config: ScanConfig, task: NmapTask) -> None:
    hosts_path = config.output_dir / "open-ports" / task.port_file
    hosts = _hosts_from_file(hosts_path)
    if not hosts:
        return
    print(
        f"\n[{colour_text('+', COLOURS.green)}] {task.description} {colour_text(task.port_file.split('.')[0], COLOURS.yellow)}"
    )
    command = [
        "nmap",
        *task.arguments(config.allow_unsafe_nse),
        "-iL",
        str(hosts_path),
        "-oN",
        str(config.output_dir / "nse_scans" / task.output_name),
        "--stats-every",
        "60s",
        "--min-hostgroup",
        str(config.nmap_min_host),
        f"--min-rate={config.nmap_min_rate}",
    ]
    run_command(command)


def _write_command_output(path: Path, command: Sequence[str], result) -> None:
    """Persist the executed command and captured output to ``path``."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"# Command: {' '.join(command)}\n")
        handle.write(f"# Exit status: {result.returncode}\n\n")
        if result.stdout:
            handle.write(result.stdout)
        if result.stderr:
            if result.stdout:
                handle.write("\n")
            handle.write("# stderr:\n")
            handle.write(result.stderr)


def _capture_banner(host: str, port: int, *, timeout: float = 5.0) -> str:
    """Return a short banner from *host*:*port*, if available."""

    max_bytes = 4096
    data = bytearray()
    try:
        with closing(socket.create_connection((host, port), timeout=timeout)) as sock:
            sock.settimeout(timeout)
            while len(data) < max_bytes:
                try:
                    chunk = sock.recv(max_bytes - len(data))
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                if len(chunk) < max_bytes - len(data):
                    break
    except OSError as exc:  # pragma: no cover - network dependent
        return f"Failed to capture banner: {exc}\n"
    if not data:
        return "No banner captured before timeout.\n"
    return data.decode(errors="replace")


def nse(config: ScanConfig) -> None:
    """Execute targeted NSE scans for high-value ports.

    Only scripts tagged safe by the upstream Nmap project are executed by
    default. Setting ``config.allow_unsafe_nse`` re-enables the legacy,
    intrusive allowlist.
    """

    tasks = [
        NmapTask(
            description="running scans for port",
            port_file="21.txt",
            output_name="ftp.txt",
            safe_arguments=["-sC", "-sV", "-p", "21", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "21",
                "--script=ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor",
            ],
        ),
        NmapTask(
            "running scans for port",
            "22.txt",
            "ssh.txt",
            safe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "22",
                "--script=ssh2-enum-algos",  # Tagged "safe" upstream.
            ],
        ),
        NmapTask(
            "running scans for port",
            "23.txt",
            "telnet.txt",
            safe_arguments=["-sC", "-sV", "-p", "23", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "23",
                "--script=telnet-encryption,banner,telnet-ntlm-info,tn3270-info",
            ],
        ),
        NmapTask(
            "running scans for port",
            "25.txt",
            "smtp.txt",
            safe_arguments=["-sC", "-sV", "-p", "25", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "25",
                "--script=smtp-commands,smtp-open-relay,smtp-ntlm-info,smtp-enum-users.nse",
                "--script-args",
                "smtp-enum-users.methods={EXPN,VRFY}",
            ],
        ),
        NmapTask(
            "running scans for port",
            "53.txt",
            "dns.txt",
            safe_arguments=["-sU", "-p", "53", "--script=safe"],
            unsafe_arguments=[
                "-sU",
                "-p",
                "53",
                "--script=dns-recursion,dns-service-discovery,dns-cache-snoop.nse,dns-nsec-enum",
                "--script-args",
                "dns-nsec-enum.domains=example.com",
            ],
        ),
        NmapTask(
            "running scans for port",
            "80.txt",
            "http.txt",
            safe_arguments=["-sC", "-sV", "-p", "80", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "80",
                "--script=http-default-accounts,http-enum,http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-dombased-xss,http-phpself-xss,http-wordpress-enum,http-wordpress-users",
            ],
        ),
        NmapTask(
            "running scans for port",
            "110.txt",
            "pop3.txt",
            safe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "110",
                "--script=pop3-capabilities",  # Tagged "safe" upstream.
            ],
        ),
        NmapTask(
            "running scans for port",
            "111.txt",
            "nfs111.txt",
            safe_arguments=["-sV", "-p", "111", "--script=safe"],
            unsafe_arguments=["-sV", "-p", "111", "--script=nfs-showmount,nfs-ls"],
        ),
        NmapTask(
            "running scans for port",
            "123.txt",
            "ntp.txt",
            safe_arguments=[
                "-sU",
                "-p",
                "123",
                "--script=ntp-info",  # Tagged "safe" upstream.
            ],
            unsafe_arguments=["-sU", "-p", "123", "--script=ntp-info,ntp-monlist"],
        ),
        NmapTask(
            "running scans for port",
            "161.txt",
            "snmp.txt",
            safe_arguments=["-sC", "-sU", "-p", "161", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sU",
                "-p",
                "161",
                "--script=snmp-interfaces,snmp-sysdescr,snmp-netstat,snmp-processes",
            ],
        ),
        NmapTask(
            "running scans for port",
            "443.txt",
            "https.txt",
            safe_arguments=["-sC", "-sV", "-p", "443", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "443",
                "--script=http-default-accounts,http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-dombased-xss,http-phpself-xss,http-wordpress-enum",
            ],
        ),
    ]

    for task in tasks:
        _run_nmap_task(config, task)

    # Additional dedicated scans for SSL and other services
    ssl_hosts = _hosts_from_file(config.output_dir / "open-ports" / "443.txt")
    if ssl_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] running scans for port {colour_text('443', COLOURS.yellow)}"
        )
        ssl_script = (
            "--script=ssl-poodle,ssl-heartbleed,ssl-enum-ciphers,ssl-cert-intaddr"
            if config.allow_unsafe_nse
            else "--script=ssl-cert,ssl-enum-ciphers"
        )
        # ssl-cert and ssl-enum-ciphers are both tagged as safe in Nmap's script database.
        ssl_command = [
            "nmap",
            "-sC",
            "-sV",
            "-p",
            "443",
            "-iL",
            str(config.output_dir / "open-ports" / "443.txt"),
            "--version-light",
            ssl_script,
            "-oN",
            str(config.output_dir / "nse_scans" / "ssl.txt"),
            "--stats-every",
            "60s",
            "--min-hostgroup",
            str(config.nmap_min_host),
            f"--min-rate={config.nmap_min_rate}",
        ]
        if config.allow_unsafe_nse:
            ssl_command.extend(["--script-args", "vulns.showall"])
        run_command(ssl_command)

    additional_tasks = [
        NmapTask(
            "running scans for port",
            "445.txt",
            "smb.txt",
            safe_arguments=["-sC", "-sV", "-p", "445", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "445",
                "--script=smb-enum-shares.nse,smb-os-discovery.nse,smb-enum-users.nse,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-vuln-uptime",
            ],
        ),
        NmapTask(
            "running scans for port",
            "1521.txt",
            "oracle.txt",
            safe_arguments=["-sV", "-p", "1521", "--script=safe"],
            unsafe_arguments=["-p", "1521-1560", "--script=oracle-sid-brute"],
        ),
        NmapTask(
            "running scans for port",
            "2049.txt",
            "nfs2049.txt",
            safe_arguments=["-sV", "-p", "2049", "--script=safe"],
            unsafe_arguments=["-sV", "-p", "2049", "--script=nfs-showmount,nfs-ls"],
        ),
        NmapTask(
            "running scans for port",
            "3306.txt",
            "mysql.txt",
            safe_arguments=["-sC", "-sV", "-p", "3306", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "3306",
                "--script=mysql-empty-password,mysql-users,mysql-enum,mysql-audit",
                "--script-args",
                "mysql-audit.username='root',mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'",
            ],
        ),
        NmapTask(
            "running scans for port",
            "5900.txt",
            "vnc.txt",
            safe_arguments=["-sC", "-sV", "-p", "5900", "--script=safe"],
            unsafe_arguments=["-sC", "-sV", "-p", "5900", "--script=banner,vnc-title"],
        ),
        NmapTask(
            "running scans for port",
            "8080.txt",
            "http8080.txt",
            safe_arguments=["-sC", "-sV", "-p", "8080", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "8080",
                "--script=http-default-accounts,http-title,http-robots.txt,http-methods,http-shellshock,http-dombased-xss,http-phpself-xss",
            ],
        ),
        NmapTask(
            "running scans for port",
            "8443.txt",
            "https8443.txt",
            safe_arguments=["-sC", "-sV", "-p", "8443", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "8443",
                "--script=http-default-accounts,http-title,http-robots.txt,http-methods,http-shellshock,http-dombased-xss,http-phpself-xss",
            ],
        ),
        NmapTask(
            "running scans for port",
            "27017.txt",
            "mongodb.txt",
            safe_arguments=["-sC", "-sV", "-p", "27017", "--script=safe"],
            unsafe_arguments=[
                "-sC",
                "-sV",
                "-p",
                "27017",
                "--script=mongodb-info,mongodb-databases",
            ],
        ),
    ]

    for task in additional_tasks:
        _run_nmap_task(config, task)


def other_scans(config: ScanConfig) -> None:
    """Run auxiliary enumeration tasks for selected services."""

    ike_hosts = _hosts_from_file(config.output_dir / "open-ports" / "500.txt")
    if ike_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] running scans for port {colour_text('500', COLOURS.yellow)}"
        )
        run_command(
            [
                "nmap",
                "-sU",
                "-p",
                "500",
                "-iL",
                str(config.output_dir / "open-ports" / "500.txt"),
                "--script=ike-version",  # Tagged "safe" upstream.
                "-oN",
                str(config.output_dir / "nse_scans" / "ike.txt"),
                "--stats-every",
                "60s",
                "--min-hostgroup",
                str(config.nmap_min_host),
                f"--min-rate={config.nmap_min_rate}",
            ]
        )
        for host in ike_hosts:
            result = run_command(
                ["ike-scan", "-A", "-M", host, "--id=GroupVPN"],
                capture_output=True,
                check=False,
            )
            out_file = config.output_dir / "nse_scans" / f"IKE-{host}.txt"
            with out_file.open("a", encoding="utf-8") as handle:
                handle.write(result.stdout)
                handle.write(result.stderr)

    smb139_hosts = _hosts_from_file(config.output_dir / "open-ports" / "139.txt")
    smb445_hosts = _hosts_from_file(config.output_dir / "open-ports" / "445.txt")
    if smb139_hosts or smb445_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Running further scans for {colour_text('SMB ports', COLOURS.yellow)}"
        )
        for host in smb139_hosts + smb445_hosts:
            result = run_command(["nbtscan", host], capture_output=True, check=False)
            out_file = config.output_dir / "nse_scans" / f"nbtscan-{host}.txt"
            with out_file.open("a", encoding="utf-8") as handle:
                handle.write(result.stdout)
                handle.write(result.stderr)

    https_hosts = _hosts_from_file(config.output_dir / "open-ports" / "443.txt")
    if https_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] running scans for port {colour_text('443', COLOURS.yellow)}"
        )
        for host in https_hosts:
            ms_result = run_command(
                [
                    "curl",
                    "-v",
                    f"https://{host}/",
                    "-H",
                    "Host: hostname",
                    "--max-time",
                    "10",
                    "-H",
                    "Range: bytes=0-18446744073709551615",
                    "-k",
                ],
                capture_output=True,
                check=False,
            )
            ms_file = config.output_dir / "nse_scans" / f"MS15034-{host}.txt"
            with ms_file.open("a", encoding="utf-8") as handle:
                handle.write(ms_result.stdout)
                handle.write(ms_result.stderr)

            autodiscover = run_command(
                [
                    "curl",
                    "-Ikv",
                    "-X",
                    "GET",
                    "-0",
                    "--max-time",
                    "10",
                    "-H",
                    "Host:",
                    f"https://{host}/autodiscover/autodiscover.xml",
                ],
                capture_output=True,
                check=False,
            )
            ad_file = (
                config.output_dir
                / "nse_scans"
                / f"internal-ip-header-check-{host}.txt"
            )
            with ad_file.open("a", encoding="utf-8") as handle:
                handle.write(autodiscover.stdout)
                handle.write(autodiscover.stderr)


def service_validation(config: ScanConfig) -> None:
    """Execute extended service validation tasks when requested."""

    open_ports_dir = config.output_dir / "open-ports"
    output_dir = config.output_dir / "nse_scans"
    alive_hosts_path = config.output_dir / "nmap" / "alive.ip"

    icmp_hosts = _hosts_from_file(alive_hosts_path)
    if icmp_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Checking ICMP timestamp responses",
        )
        for host in icmp_hosts:
            ts_command = [
                "hping3",
                "--icmp",
                "--icmp-ts",
                "-c",
                "3",
                host,
            ]
            ts_result = run_command(ts_command, capture_output=True, check=False)
            _write_command_output(
                output_dir / f"icmp-timestamp-{host}.txt",
                ts_command,
                ts_result,
            )

    telnet_hosts = _hosts_from_file(open_ports_dir / "23.txt")
    if telnet_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Validating telnet services "
            f"{colour_text('23', COLOURS.yellow)}"
        )
        for host in telnet_hosts:
            banner = _capture_banner(host, 23)
            banner_file = output_dir / f"telnet-banner-{host}.txt"
            banner_file.parent.mkdir(parents=True, exist_ok=True)
            with banner_file.open("w", encoding="utf-8") as handle:
                handle.write(f"# Telnet banner capture for {host}:23\n")
                handle.write(banner)

    ssh_hosts = _hosts_from_file(open_ports_dir / "22.txt")
    if ssh_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Enumerating SSH authentication methods "
            f"{colour_text('22', COLOURS.yellow)}"
        )
        hosts_file = open_ports_dir / "22.txt"
        auth_command = [
            "nmap",
            "-Pn",
            "-p22",
            "--script",
            "ssh-auth-methods",
            "-iL",
            str(hosts_file),
        ]
        auth_result = run_command(auth_command, capture_output=True, check=False)
        _write_command_output(output_dir / "ssh-auth-methods.txt", auth_command, auth_result)

        for host in ssh_hosts:
            algo_command = [
                "nmap",
                "-Pn",
                "-p22",
                "--script",
                "ssh-enum-algos",
                host,
            ]
            algo_result = run_command(algo_command, capture_output=True, check=False)
            _write_command_output(
                output_dir / f"ssh-enum-algos-{host}.txt",
                algo_command,
                algo_result,
            )

    ssl_ports = {"443": "https", "8443": "https-alt", "9443": "https-alt"}
    for port, label in ssl_ports.items():
        hosts = _hosts_from_file(open_ports_dir / f"{port}.txt")
        if not hosts:
            continue
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Enumerating SSL/TLS ciphers for "
            f"{colour_text(port, COLOURS.yellow)} ({label})"
        )
        hosts_file = open_ports_dir / f"{port}.txt"
        ssl_command = [
            "nmap",
            "-Pn",
            "-p",
            port,
            "--script",
            "ssl-enum-ciphers,ssl-cert,ssl-cert-intaddr",
            "-iL",
            str(hosts_file),
        ]
        ssl_result = run_command(ssl_command, capture_output=True, check=False)
        _write_command_output(
            output_dir / f"ssl-enum-ciphers-{port}.txt",
            ssl_command,
            ssl_result,
        )

    snmp_hosts = _hosts_from_file(open_ports_dir / "161.txt")
    if snmp_hosts:
        print(
            f"\n[{colour_text('+', COLOURS.green)}] Checking SNMP community strings "
            f"{colour_text('161', COLOURS.yellow)}"
        )
        hosts_file = open_ports_dir / "161.txt"
        snmp_command = [
            "nmap",
            "-sU",
            "-Pn",
            "-p161",
            "--script",
            "snmp-info",
            "--script-args",
            "snmpcommunity=public",
            "-iL",
            str(hosts_file),
        ]
        snmp_result = run_command(snmp_command, capture_output=True, check=False)
        _write_command_output(
            output_dir / "snmp-default-community.txt",
            snmp_command,
            snmp_result,
        )


def discovery_scans(config: ScanConfig) -> None:
    """Perform dictionary attacks against common web directories."""

    http_hosts = _hosts_from_file(config.output_dir / "open-ports" / "80.txt")
    if not http_hosts:
        return
    print(
        f"\n[{colour_text('+', COLOURS.green)}] Running world list scan for port {colour_text('80', COLOURS.yellow)}"
    )
    print("\nDirb default wordlist of 4612 words")
    for host in http_hosts:
        result = run_command(["dirb", f"http://{host}"], capture_output=True, check=False)
        out_file = config.output_dir / "nse_scans" / f"dirb-{host}.txt"
        with out_file.open("a", encoding="utf-8") as handle:
            handle.write(result.stdout)
            handle.write(result.stderr)
