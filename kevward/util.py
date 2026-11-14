# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

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


REBOOT_PKGS_FILES = ("/run/reboot-required.pkgs", "/var/run/reboot-required.pkgs")


def reboot_pending_pkgs() -> list[str]:
    """Packages that asked for the pending reboot (``reboot-required.pkgs``),
    de-duplicated in file order; [] when unknown. Read-only."""
    for path in REBOOT_PKGS_FILES:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError:
            continue
        seen: list[str] = []
        for line in text.splitlines():
            name = line.strip()
            if name and name not in seen:
                seen.append(name)
        return seen
    return []


def format_pkgs(pkgs: list[str], limit: int = 3) -> str:
    """'libc6, dbus' / 'a, b, c +2 more' for compact display."""
    shown = ", ".join(pkgs[:limit])
    if len(pkgs) > limit:
        shown += f" +{len(pkgs) - limit} more"
    return shown


def reboot_kind(pkgs: list[str]) -> str:
    """'kernel' if any package needs a reboot to take effect at all (kernel,
    firmware, microcode); 'userspace' if only libraries/daemons asked (e.g.
    libc6: running processes keep the old copy until restarted); '' if unknown.
    """
    if not pkgs:
        return ""
    for p in pkgs:
        if p.startswith("linux-") or p.endswith("-microcode"):
            return "kernel"
    return "userspace"


def pkg_needs_reboot(pkg: str) -> bool:
    """True if upgrading this package implies a reboot: the kernel image or the
    C runtime (glibc).

    Deliberately narrow. The old heuristic ``startswith(("linux-", "libc"))``
    over-flagged: ``linux-firmware-*`` (firmware blobs), ``linux-headers-*``,
    ``linux-tools-*``, ``linux-libc-dev`` all start with ``linux-`` but need no
    reboot, and the ``libc`` prefix swept in unrelated libraries (``libcurl``,
    ``libcups``, ``libcairo``, …). Only the kernel image and glibc do.
    """
    return (
        pkg.startswith("linux-image")
        or pkg == "libc6"
        or pkg.startswith("libc6-")
    )
