#!/usr/bin/env python3
"""Utility helpers for the Python rewrite of AIO-Enum."""
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence


@dataclass(frozen=True)
class Colours:
    """ANSI colour palette used across the CLI output."""

    red: str = "\033[01;31m"
    green: str = "\033[01;32m"
    yellow: str = "\033[01;33m"
    blue: str = "\033[01;34m"
    bold: str = "\033[01;01m"
    reset: str = "\033[00m"

    def wrap(self, text: str, colour: str) -> str:
        return f"{colour}{text}{self.reset}"


COLOURS = Colours()


def colour_text(text: str, colour: str) -> str:
    """Return *text* wrapped in the ANSI code for *colour*."""

    return COLOURS.wrap(text, colour)


class CommandExecutionError(RuntimeError):
    """Raised when a subprocess returns a non-zero exit status."""


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = True,
    capture_output: bool = False,
    env: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    """Run *command* and return the completed process.

    Parameters
    ----------
    command:
        The command to execute. Each element represents one argument.
    cwd:
        Working directory for the command.
    check:
        When ``True`` (the default) an exception is raised if the command
        exits with a non-zero status code.
    capture_output:
        When ``True`` stdout/stderr is captured and returned to the caller.
    env:
        Optional environment mapping.
    """

    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            check=check,
            capture_output=capture_output,
            text=True,
            env=env,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - thin wrapper
        raise CommandExecutionError(
            f"Command '{' '.join(command)}' exited with status {exc.returncode}"
        ) from exc
    return result


def ensure_tools_installed(tools: Iterable[str]) -> list[str]:
    """Return a list of tools that are missing from ``$PATH``."""

    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def abort(message: str, *, exit_code: int = 1) -> None:
    """Print *message* to stderr and terminate the process."""

    print(message, file=sys.stderr)
    raise SystemExit(exit_code)
