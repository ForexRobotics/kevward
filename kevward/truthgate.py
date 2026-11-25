# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Relay of ``truthgate.*`` ssh-gate ops, and ``gate.capabilities`` (#219).

FR Security Centre manages truthgate through kevward's ssh-gate: same keys,
same envelope. kevward does not parse truthgate's requests. It passes the
exact request bytes to ``<truthgate_path> ssh-gate --role <role>`` and returns
its one-line response. truthgate's own gate decides what each role may do.

Before running the binary (as root for the operate role), the file and every
parent directory must be root-owned and not group/world-writable. The child
gets a clean environment with who-is-calling variables, its own process
group, and SIGTERM then SIGKILL on timeout. stderr is discarded.
"""

from __future__ import annotations

import json
import os
import pwd
import stat
from pathlib import Path

from .ssh_gate import GateError

PREFIX = "truthgate."
MAX_RESPONSE = 4 * 1024 * 1024
KILL_GRACE_S = 5.0
_PATH_ENV = "/usr/sbin:/usr/bin:/sbin:/bin"


class RawResponse(dict):
    """truthgate's response, kept byte for byte for the wire."""

    def __init__(self, data: dict, line: bytes):
        super().__init__(data)
        self.line = line


def _safe(st: os.stat_result, what: str, owner: int) -> None:
    if st.st_uid != owner:
        raise GateError("forbidden", f"truthgate: {what} is not owned by root")
    if st.st_mode & 0o022:
        raise GateError("forbidden", f"truthgate: {what} is group/world-writable")


def checked_path(path: str, owner: int = 0) -> str:
    """The real path of a trustworthy truthgate binary, or GateError:
    ``not_installed`` when nothing is there, ``forbidden`` when it is not
    safe to run as root. Checks the configured path's directories and, after
    resolving symlinks, the target and its directories."""
    p = Path(path)
    if not p.is_absolute():
        raise GateError("forbidden", "truthgate: truthgate_path must be absolute")
    if not os.path.lexists(p):
        raise GateError("not_installed", "truthgate is not installed on this host")
    real = Path(os.path.realpath(p))
    try:
        st = os.stat(real)
    except OSError:
        raise GateError("not_installed", "truthgate is not installed on this host") from None
    if not stat.S_ISREG(st.st_mode):
        raise GateError("forbidden", "truthgate: not a regular file")
    _safe(st, str(real), owner)
    seen = set()
    for d in [*p.parents, *real.parents]:
        if d in seen:
            continue
        seen.add(d)
        _safe(os.stat(d), f"directory {d}", owner)
    return str(real)


def gate_user() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return str(os.geteuid())


def relay(raw: bytes, role: str, cfg, *, client: str, key: str | None,
          timeout: float | None = None, runner=None, check=None) -> RawResponse:
    """Run truthgate's gate with ``raw`` on stdin; its response, checked."""
    from .util import run_bytes

    exe = (check or checked_path)(cfg.ssh_gate.truthgate_path)
    env = {"PATH": _PATH_ENV, "LANG": "C.UTF-8",
           "TRUTHGATE_GATE_CLIENT": client or "", "TRUTHGATE_GATE_ROLE": role}
    if key:
        env["TRUTHGATE_GATE_KEY_ID"] = key
    limit = timeout if timeout is not None else cfg.ssh_gate.truthgate_timeout_s
    r = (runner or run_bytes)([exe, "ssh-gate", "--role", role], raw, limit, env,
                              kill_grace=KILL_GRACE_S)
    if r.timed_out:
        raise GateError("timeout", f"truthgate did not answer within {limit:g}s")
    out = r.out
    if len(out) > MAX_RESPONSE:
        raise GateError("internal", "bad response from truthgate (too large)")
    line = out[:-1] if out.endswith(b"\n") else out
    if not line or b"\n" in line:
        raise GateError("internal", "bad response from truthgate")
    try:
        data = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise GateError("internal", "bad response from truthgate") from None
    if not isinstance(data, dict) or not isinstance(data.get("ok"), bool):
        raise GateError("internal", "bad response from truthgate")
    return RawResponse(data, line + b"\n")


def capabilities(role: str, cfg, ops: list[str], *, client: str, key: str | None,
                 runner=None, check=None) -> dict:
    """``gate.capabilities``: kevward's ops for this role, and truthgate's
    capabilities when it is installed and answers in time (else omitted)."""
    from . import __version__
    from .ssh_gate import PROTOCOL

    products: dict = {"kevward": {"version": __version__, "ops": ops}}
    try:
        r = relay(b'{"op":"truthgate.capabilities"}', role, cfg, client=client, key=key,
                  timeout=cfg.ssh_gate.truthgate_capabilities_timeout_s,
                  runner=runner, check=check)
        if r.get("ok") and isinstance(r.get("data"), dict):
            products["truthgate"] = r["data"]
    except GateError:
        pass
    return {"protocol": PROTOCOL, "role": role, "gate_user": gate_user(),
            "products": products}
