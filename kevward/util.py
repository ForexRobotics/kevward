# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Thin, testable wrappers around shell-outs and privilege checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass


@dataclass
class Cmd:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run(args: list[str], timeout: int = 120, input_: str | None = None,
        cwd: str | os.PathLike | None = None, env: dict[str, str] | None = None,
        clean_env: bool = False) -> Cmd:
    """Run a command, capturing output. Never raises on non-zero exit.

    Commands are always passed as an argv list (never a shell string), so there
    is no shell interpolation of any value. ``cwd`` sets the working directory
    (e.g. a project for ``npm audit``, #154). ``env`` adds variables to the
    current environment; with ``clean_env`` it *is* the environment (nothing
    inherited, e.g. no ``PIP_*`` for ssh-gate's self.update, #190).
    """
    if clean_env:
        child_env: dict[str, str] | None = dict(env or {})
    else:
        child_env = {**os.environ, **env} if env else None
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_,
            cwd=cwd,
            env=child_env,
            check=False,
        )
        return Cmd(p.returncode, p.stdout or "", p.stderr or "")
    except FileNotFoundError:
        if cwd is not None and not os.path.isdir(cwd):
            return Cmd(127, "", f"working directory not found: {cwd}")
        return Cmd(127, "", f"command not found: {args[0]}")
    except NotADirectoryError:
        return Cmd(127, "", f"working directory is not a directory: {cwd}")
    except subprocess.TimeoutExpired:
        return Cmd(124, "", f"timed out after {timeout}s: {' '.join(args)}")


def run_stream(args: list[str], timeout: int | None = None,
               env: dict[str, str] | None = None, prefix: str = "  | ",
               stream=None) -> Cmd:
    """Run a command, echoing its output line by line while capturing it (#170).

    For long installs (a kernel: unpack + initramfs + grub) so the operator
    sees progress instead of a silent terminal. stdin is /dev/null, so nothing
    can wait on a prompt. stderr is merged into stdout. ``timeout`` None or 0
    means no limit; on expiry the child is killed and rc is 124. Never raises.
    """
    out = stream if stream is not None else sys.stderr
    try:
        p = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, **env} if env else None,
        )
    except FileNotFoundError:
        return Cmd(127, "", f"command not found: {args[0]}")
    expired = threading.Event()

    def _kill() -> None:
        expired.set()
        p.kill()

    timer = threading.Timer(timeout, _kill) if timeout else None
    if timer:
        timer.daemon = True
        timer.start()
    lines: list[str] = []
    try:
        assert p.stdout is not None
        for line in p.stdout:
            lines.append(line)
            try:
                out.write(prefix + line)
                out.flush()
            except (OSError, ValueError):
                pass
        rc = p.wait()
    finally:
        if timer:
            timer.cancel()
    text = "".join(lines)
    if expired.is_set():
        return Cmd(124, text, f"timed out after {timeout}s: {' '.join(args)}")
    return Cmd(rc, text, "" if rc == 0 else text)


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
