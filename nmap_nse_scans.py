#!/usr/bin/env python3
"""Nmap NSE and auxiliary scans implemented in Python."""
from __future__ import annotations

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
