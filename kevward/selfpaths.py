# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""``gate.selfpaths`` (#222): every path the console's way into this host
runs, so an execution allow-list (truthgate enforce mode) can keep it open:
sshd → login shell → launcher → python → sudo → kevward → the programs
kevward runs. Read-only."""

from __future__ import annotations

import hashlib
import os
import pwd
import shutil
import sys
from pathlib import Path

#: Every external program kevward may run (report, apply, firewall, harden,
#: setup, uninstall, self.update, ssh-gate jobs). tests/test_selfpaths.py
#: fails when the code runs a program that is not listed here.
COMMANDS = (
    "apache2ctl", "apt-cache", "apt-config", "apt-get", "busctl", "composer", "doveconf", "dpkg",
    "dpkg-query", "fail2ban-client", "ip", "logwatch", "nft", "nginx", "node", "npm", "php", "pro",
    "shutdown", "snap", "ss", "sshd", "sysctl", "systemctl", "systemd-run", "ufw", "uname",
    "visudo", "wp",
)
_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _sha256(path: str | None) -> str | None:
    if not path:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def shebang(path: str) -> str | None:
    """The interpreter of a ``#!`` script (pip's launcher), or None."""
    try:
        with open(path, "rb") as fh:
            first = fh.readline(512)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    parts = first[2:].decode("utf-8", "replace").split()
    if not parts:
        return None
    if Path(parts[0]).name == "env" and len(parts) > 1:  # #!/usr/bin/env python3
        return shutil.which(parts[1], path=_PATH)
    return parts[0]


def login_shell(user: str | None) -> str | None:
    try:
        return pwd.getpwnam(user).pw_shell if user else pwd.getpwuid(os.getuid()).pw_shell
    except KeyError:
        return None


def selfpaths(environ=None, prefix: Path | None = None) -> dict:
    from . import __version__
    from . import gate_apply as ga
    from .ssh_gate import VENV_PREFIX, install_info

    environ = os.environ if environ is None else environ
    inst = install_info(prefix or VENV_PREFIX)
    launcher = str(Path(inst["prefix"]) / "bin" / "kevward")
    if not os.path.exists(launcher):
        launcher = shutil.which("kevward", path=_PATH) or os.path.abspath(sys.argv[0])
    interp = shebang(launcher) or sys.executable
    real = os.path.realpath(interp) if interp else None
    # sshd runs the forced command with the login shell of the user the key
    # belongs to; for the operate role that is the user sudo was called from.
    user = environ.get("SUDO_USER") or None
    return {
        "version": __version__,
        "launcher": launcher,
        "launcher_sha256": _sha256(launcher),
        "interpreter": {"path": interp, "realpath": real, "sha256": _sha256(real)},
        "shell": login_shell(user),
        "sudo": shutil.which("sudo", path=_PATH),
        "package_dir": str(Path(__file__).resolve().parent),
        "install": inst,
        "commands": {c: shutil.which(c, path=_PATH) for c in COMMANDS},
        # truthgate binds an apply window to the first unit of this shape (#247)
        "apply_units": {
            "transient_prefix": "kevward-apply-",
            "transient_pattern": ("^kevward-apply-" + ga._JOB_ID.pattern.strip("^$")
                                  + r"\.service$"),
            "transient_exec": f"{launcher} apply -c <config> --yes --expect-plan "
                              "<plan_hash> --job <job_id> [--reboot-at <time>]",
            "timer_service": "kevward-apply.service",
            "report_service": "kevward-report.service",
        },
    }
