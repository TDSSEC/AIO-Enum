#!/usr/bin/env python3
"""Tkinter-based configuration GUI for the AIO-Enum toolkit."""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Literal

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


SCANTYPE_OPTIONS = {
    "Show Help": "help",
    "Default Scan (Alive hosts + ports)": "default",
    "Quick Scan (ICMP hosts only)": "quick",
    "Scans (Masscan + Nmap + NSE)": "scans",
    "All (Masscan + Nmap + NSE + Web Enum)": "all",
    "Nmap Only": "nmap",
    "ICMP Sweep": "icmp",
}

PortMode = Literal["all", "top100", "top1000", "custom"]


class AioEnumGUI:
    """GUI wrapper that gathers configuration for AIO-Enum."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("AIO-Enum Configuration")
        self.root.geometry("880x720")
        self.root.minsize(820, 640)

        self.scantype_var = tk.StringVar(value="default")
        self.port_mode_var = tk.StringVar(value="all")
        self.custom_tcp_var = tk.StringVar(value="1-65535")
        self.udp_ports_var = tk.StringVar(value="53,69,123,161,500,1434")
        self.nmap_min_host_var = tk.StringVar(value="50")
        self.nmap_min_rate_var = tk.StringVar(value="200")
        self.masscan_max_rate_var = tk.StringVar(value="500")
        self.masscan_interface_var = tk.StringVar()
        self.output_dir_var = tk.StringVar()
        self.nessus_file_var = tk.StringVar()
        self.allow_unsafe_var = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar()

        self._build_layout()

    # ------------------------------------------------------------------
    # Layout helpers
    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        for i in range(4):
            main.rowconfigure(i, weight=1)
        main.columnconfigure(0, weight=1)

        self._build_scoping_section(main)
        self._build_settings_section(main)
        self._build_command_preview(main)
        self._build_status_bar()

    def _build_scoping_section(self, parent: ttk.Frame) -> None:
        scoping_frame = ttk.LabelFrame(parent, text="Scoping", padding=10)
        scoping_frame.grid(row=0, column=0, sticky="nsew")
        scoping_frame.columnconfigure(0, weight=1)
        scoping_frame.columnconfigure(1, weight=1)

        targets_label = ttk.Label(
            scoping_frame,
            text=(
                "Target IP addresses or ranges (one per line).\n"
                "These values populate the targets.ip file used by the toolkit."
            ),
        )
        targets_label.grid(row=0, column=0, sticky="w")
        self.targets_text = tk.Text(scoping_frame, height=8, wrap="none")
        self.targets_text.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=(5, 0))

        exclude_label = ttk.Label(
            scoping_frame,
            text=(
                "Excluded IP addresses or ranges (one per line).\n"
                "These values populate the exclude.ip file used by the toolkit."
            ),
        )
        exclude_label.grid(row=0, column=1, sticky="w", padx=(10, 0))
        self.exclude_text = tk.Text(scoping_frame, height=8, wrap="none")
        self.exclude_text.grid(row=1, column=1, sticky="nsew", pady=(5, 0))

        for col in (0, 1):
            scoping_frame.rowconfigure(1, weight=1)
            scoping_frame.columnconfigure(col, weight=1)

    def _build_settings_section(self, parent: ttk.Frame) -> None:
        settings = ttk.LabelFrame(parent, text="Scan & Output Settings", padding=10)
        settings.grid(row=1, column=0, sticky="nsew", pady=10)
        for col in range(4):
            settings.columnconfigure(col, weight=1)

        # Scantype selection
        ttk.Label(settings, text="Scan type").grid(row=0, column=0, sticky="w")
        scantype_combo = ttk.Combobox(
            settings,
            values=list(SCANTYPE_OPTIONS.keys()),
            state="readonly",
        )
        scantype_combo.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        scantype_combo.set("Default Scan (Alive hosts + ports)")
        scantype_combo.bind("<<ComboboxSelected>>", self._on_scantype_change)

        # Port mode
        port_frame = ttk.Frame(settings)
        port_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(0, 10))
        port_frame.columnconfigure(0, weight=1)
        ttk.Label(port_frame, text="TCP Port Selection").grid(row=0, column=0, sticky="w")

        ttk.Radiobutton(
            port_frame,
            text="Full range (1-65535)",
            variable=self.port_mode_var,
            value="all",
            command=self._toggle_custom_ports,
        ).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(
            port_frame,
            text="Top 100",
            variable=self.port_mode_var,
            value="top100",
            command=self._toggle_custom_ports,
        ).grid(row=2, column=0, sticky="w")
        ttk.Radiobutton(
            port_frame,
            text="Top 1000",
            variable=self.port_mode_var,
            value="top1000",
            command=self._toggle_custom_ports,
        ).grid(row=3, column=0, sticky="w")
        custom_frame = ttk.Frame(port_frame)
        custom_frame.grid(row=4, column=0, sticky="ew", pady=(5, 0))
        ttk.Radiobutton(
            custom_frame,
            text="Custom:",
            variable=self.port_mode_var,
            value="custom",
            command=self._toggle_custom_ports,
        ).grid(row=0, column=0, sticky="w")
        custom_entry = ttk.Entry(custom_frame, textvariable=self.custom_tcp_var)
        custom_entry.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        custom_frame.columnconfigure(1, weight=1)

        # UDP ports and other numeric settings
        numeric_frame = ttk.Frame(settings)
        numeric_frame.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=(0, 10))
        for i in range(6):
            numeric_frame.rowconfigure(i, weight=1)
        numeric_frame.columnconfigure(1, weight=1)

        ttk.Label(numeric_frame, text="UDP ports").grid(row=0, column=0, sticky="w")
        ttk.Entry(numeric_frame, textvariable=self.udp_ports_var).grid(
            row=0, column=1, sticky="ew"
        )

        ttk.Label(numeric_frame, text="Nmap min hostgroup").grid(row=1, column=0, sticky="w")
        ttk.Entry(numeric_frame, textvariable=self.nmap_min_host_var).grid(
            row=1, column=1, sticky="ew"
        )

        ttk.Label(numeric_frame, text="Nmap min rate").grid(row=2, column=0, sticky="w")
        ttk.Entry(numeric_frame, textvariable=self.nmap_min_rate_var).grid(
            row=2, column=1, sticky="ew"
        )

        ttk.Label(numeric_frame, text="Masscan max rate").grid(row=3, column=0, sticky="w")
        ttk.Entry(numeric_frame, textvariable=self.masscan_max_rate_var).grid(
            row=3, column=1, sticky="ew"
        )

        ttk.Label(numeric_frame, text="Masscan interface (optional)").grid(
            row=4, column=0, sticky="w"
        )
        ttk.Entry(numeric_frame, textvariable=self.masscan_interface_var).grid(
            row=4, column=1, sticky="ew"
        )

        allow_box = ttk.Checkbutton(
            numeric_frame,
            text="Allow unsafe NSE scripts",
            variable=self.allow_unsafe_var,
        )
        allow_box.grid(row=5, column=0, columnspan=2, sticky="w")

        # File locations
        file_frame = ttk.Frame(settings)
        file_frame.grid(row=0, column=3, rowspan=2, sticky="nsew")
        file_frame.columnconfigure(1, weight=1)

        ttk.Label(file_frame, text="Output directory").grid(row=0, column=0, sticky="w")
        output_entry = ttk.Entry(file_frame, textvariable=self.output_dir_var)
        output_entry.grid(row=1, column=0, columnspan=2, sticky="ew")
        ttk.Button(file_frame, text="Browse", command=self._browse_output_dir).grid(
            row=1, column=2, padx=(5, 0)
        )

        ttk.Label(file_frame, text="Nessus report (.nessus)").grid(row=2, column=0, sticky="w")
        nessus_entry = ttk.Entry(file_frame, textvariable=self.nessus_file_var)
        nessus_entry.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Button(file_frame, text="Browse", command=self._browse_nessus_file).grid(
            row=3, column=2, padx=(5, 0)
        )

        button_frame = ttk.Frame(parent)
        button_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        ttk.Button(button_frame, text="Save Configuration", command=self.save_configuration).grid(
            row=0, column=0, padx=(0, 5), sticky="ew"
        )
        ttk.Button(button_frame, text="Copy Command", command=self.copy_command).grid(
            row=0, column=1, padx=(5, 0), sticky="ew"
        )

    def _build_command_preview(self, parent: ttk.Frame) -> None:
        preview = ttk.LabelFrame(parent, text="Command Preview & Notes", padding=10)
        preview.grid(row=3, column=0, sticky="nsew")
        preview.columnconfigure(0, weight=1)
        preview.rowconfigure(0, weight=1)

        self.command_text = tk.Text(preview, height=8, wrap="word", state=tk.DISABLED)
        self.command_text.grid(row=0, column=0, sticky="nsew")

    def _build_status_bar(self) -> None:
        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w")
        status.grid(row=1, column=0, sticky="ew")

    # ------------------------------------------------------------------
    # Event handlers
    def _on_scantype_change(self, event: tk.Event[tk.Misc]) -> None:
        widget = event.widget
        if isinstance(widget, ttk.Combobox):
            choice = widget.get()
            self.scantype_var.set(SCANTYPE_OPTIONS.get(choice, "default"))

    def _toggle_custom_ports(self) -> None:
        mode: PortMode = self.port_mode_var.get()  # type: ignore[assignment]
        if mode == "custom":
            return
        if mode == "all":
            self.custom_tcp_var.set("1-65535")
        elif mode == "top100":
            self.custom_tcp_var.set("top-100")
        elif mode == "top1000":
            self.custom_tcp_var.set("top-1000")

    def _browse_output_dir(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir_var.set(directory)

    def _browse_nessus_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select Nessus report",
            filetypes=[("Nessus reports", "*.nessus"), ("All files", "*.*")],
        )
        if filename:
            self.nessus_file_var.set(filename)

    # ------------------------------------------------------------------
    # Core logic
    def save_configuration(self) -> None:
        try:
            output_dir = Path(self.output_dir_var.get()).expanduser().resolve()
        except Exception as exc:  # pragma: no cover - gui input validation
            messagebox.showerror("Invalid directory", f"Unable to parse output directory: {exc}")
            return

        if not self.output_dir_var.get().strip():
            messagebox.showwarning("Missing output directory", "Please choose an output directory.")
            return

        targets = self.targets_text.get("1.0", tk.END).strip()
        if not targets:
            messagebox.showwarning("Missing targets", "Please provide at least one target address.")
            return

        output_dir.mkdir(parents=True, exist_ok=True)

        targets_path = output_dir / "targets.ip"
        targets_path.write_text(targets + "\n", encoding="utf-8")

        exclude = self.exclude_text.get("1.0", tk.END).strip()
        exclude_path = output_dir / "exclude.ip"
        exclude_path.write_text(exclude + "\n" if exclude else "", encoding="utf-8")

        mode: PortMode = self.port_mode_var.get()  # type: ignore[assignment]
        port_config = {
            "mode": mode,
            "custom_range": self.custom_tcp_var.get().strip(),
        }

        nessus_file = self.nessus_file_var.get().strip() or None

        config_payload = {
            "scantype": self.scantype_var.get(),
            "tcp_ports": port_config,
            "udp_ports": self.udp_ports_var.get().strip(),
            "nmap_min_host": self.nmap_min_host_var.get().strip(),
            "nmap_min_rate": self.nmap_min_rate_var.get().strip(),
            "masscan_max_rate": self.masscan_max_rate_var.get().strip(),
            "masscan_interface": self.masscan_interface_var.get().strip() or None,
            "nessus_file": nessus_file,
            "allow_unsafe_nse": self.allow_unsafe_var.get(),
            "output_dir": str(output_dir),
            "targets_file": str(targets_path),
            "exclude_file": str(exclude_path),
        }

        config_file = output_dir / "aio_enum_gui_config.json"
        config_file.write_text(json.dumps(config_payload, indent=2), encoding="utf-8")

        command = self._build_command_preview(config_payload)
        self._update_command_preview(command)
        self.status_var.set(
            f"Saved configuration to {config_file}. Run the command below from the output directory."
        )
        messagebox.showinfo(
            "Configuration saved",
            "Targets and configuration saved. Review the command preview for execution details.",
        )

    def _build_command_preview(self, config_payload: dict[str, object]) -> str:
        args: list[str] = []
        scantype = config_payload.get("scantype", "help")
        flag_lookup = {
            "default": "-1",
            "quick": "-2",
            "scans": "-3",
            "all": "-4",
            "nmap": "-5",
            "icmp": "-6",
        }
        if scantype in flag_lookup:
            args.append(flag_lookup[scantype])

        port_config = config_payload.get("tcp_ports", {})
        mode = port_config.get("mode") if isinstance(port_config, dict) else "all"
        custom_range = (
            port_config.get("custom_range") if isinstance(port_config, dict) else "1-65535"
        )
        if mode == "top100":
            args.append("--top100")
        elif mode == "top1000":
            args.append("--top1000")
        elif mode == "custom" and custom_range:
            args.extend(["--tcpportrange", str(custom_range)])

        udp_ports = config_payload.get("udp_ports")
        if udp_ports:
            args.extend(["--udpportrange", str(udp_ports)])

        nmap_min_host = config_payload.get("nmap_min_host")
        if nmap_min_host:
            args.extend(["--nmap-minhost", str(nmap_min_host)])

        nmap_min_rate = config_payload.get("nmap_min_rate")
        if nmap_min_rate:
            args.extend(["--nmap-minrate", str(nmap_min_rate)])

        masscan_max_rate = config_payload.get("masscan_max_rate")
        if masscan_max_rate:
            args.extend(["--masscan-maxrate", str(masscan_max_rate)])

        masscan_interface = config_payload.get("masscan_interface")
        if masscan_interface:
            args.extend(["--masscan-interface", str(masscan_interface)])

        nessus_file = config_payload.get("nessus_file")
        if nessus_file:
            args.extend(["--nessus-file", str(nessus_file)])

        if config_payload.get("allow_unsafe_nse"):
            args.append("--allow-unsafe-nse")

        output_dir = config_payload.get("output_dir")
        if output_dir:
            args.extend(["--outputdir", str(output_dir)])

        script_path = Path(__file__).resolve().with_name("aio_enum.py")
        exe = sys.executable or "python"
        command = shlex.join([exe, str(script_path), *args])

        output_dir_str = str(output_dir) if output_dir else "."
        command_lines = [
            "# Run from within the selected output directory to use the generated targets/exclude files",
            f"cd {shlex.quote(output_dir_str)}",
            f"sudo {command}",
        ]
        return "\n".join(command_lines)

    def _update_command_preview(self, text: str) -> None:
        self.command_text.configure(state=tk.NORMAL)
        self.command_text.delete("1.0", tk.END)
        self.command_text.insert("1.0", text)
        self.command_text.configure(state=tk.DISABLED)

    def copy_command(self) -> None:
        text = self.command_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Nothing to copy", "Generate a command first by saving the configuration.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Command copied to clipboard.")

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    AioEnumGUI().run()


if __name__ == "__main__":
    main()
