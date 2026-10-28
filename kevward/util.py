"""Thin, testable wrappers around shell-outs and privilege checks."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Cmd:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run(args: list[str], timeout: int = 120, input_: str | None = None) -> Cmd:
    """Run a command, capturing output. Never raises on non-zero exit.

    Commands are always passed as an argv list (never a shell string), so there
    is no shell interpolation of any value.
    """
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_,
            check=False,
        )
        return Cmd(p.returncode, p.stdout or "", p.stderr or "")
    except FileNotFoundError:
        return Cmd(127, "", f"command not found: {args[0]}")
    except subprocess.TimeoutExpired:
        return Cmd(124, "", f"timed out after {timeout}s: {' '.join(args)}")


def which(name: str) -> str | None:
    return shutil.which(name)


def have(name: str) -> bool:
    return which(name) is not None


def is_root() -> bool:
    return os.geteuid() == 0


def reboot_pending() -> bool:
    """True if the kernel/packages flagged that a reboot is needed."""
    return os.path.exists("/var/run/reboot-required") or os.path.exists(
        "/run/reboot-required"
    )
