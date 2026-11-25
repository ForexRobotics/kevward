# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Processes still running code that an update has replaced on disk.

After apt upgrades a library (glibc, OpenSSL, ...) or a daemon binary, every
process started before the upgrade keeps executing the old copy until it is
restarted. The kernel shows such a mapping in ``/proc/<pid>/maps`` with the
suffix `` (deleted)``. Ubuntu's needrestart restarts most services by itself,
but not all of them (and not in every mode), and /run/reboot-required is only
set for a few packages, so "reboot required: no" can still mean a long-running
sshd or nginx is serving with the unpatched library.

Read-only: this only reads /proc. As non-root it sees only the caller's own
processes, so callers should say so rather than report "nothing found".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Only code from the system's own trees counts. /tmp, /dev/shm, memfd: and
# similar deleted mappings are normal for JITs, browsers and sandboxes.
CODE_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/lib32/", "/bin/", "/sbin/")
DELETED = " (deleted)"
# dpkg unpacks to <file>.dpkg-new and renames; a process that mapped the file
# mid-upgrade can show the temporary name.
DPKG_SUFFIXES = (".dpkg-new", ".dpkg-tmp")
# A process still on an old TLS library keeps serving with it: worth more
# than a cosmetic restart.
TLS_LIBS = ("libssl.so", "libcrypto.so", "libgnutls.so")


@dataclass
class StaleUnit:
    """One systemd unit (or scope) whose processes run replaced code."""

    unit: str
    pids: list[int] = field(default_factory=list)
    comms: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    @property
    def tls(self) -> bool:
        return any(os.path.basename(f).startswith(TLS_LIBS) for f in self.files)

    def hint(self) -> str:
        """What restarts this unit's processes onto the new code."""
        if self.unit.endswith(".service"):
            return f"systemctl restart {self.unit[:-len('.service')]}"
        if self.unit == "init.scope":
            return "systemctl daemon-reexec"
        if self.unit.startswith("session-") or self.unit.startswith("user@"):
            return "log out and back in"
        return "restart it (or reboot)"


def deleted_code_files(maps_text: str) -> list[str]:
    """Executable mappings of replaced system files in one ``maps`` text."""
    found: list[str] = []
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6 or "x" not in parts[1]:
            continue
        path = parts[5]
        if not path.endswith(DELETED):
            continue
        path = path[: -len(DELETED)]
        for suf in DPKG_SUFFIXES:
            if path.endswith(suf):
                path = path[: -len(suf)]
        if path.startswith(CODE_PREFIXES) and path not in found:
            found.append(path)
    return found


def unit_of(cgroup_text: str) -> str:
    """The systemd unit/scope a process belongs to, from /proc/<pid>/cgroup.

    Works for cgroup v2 (``0::/system.slice/nginx.service``) and v1 (the
    ``name=systemd`` hierarchy). Nested cgroups under a unit (e.g.
    ``.../user@1000.service/app.slice/x.scope``) keep the innermost unit."""
    path = ""
    for line in cgroup_text.splitlines():
        hid, _, rest = line.partition(":")
        ctrls, _, cg = rest.partition(":")
        if hid == "0" and ctrls == "":
            path = cg
            break
        if ctrls == "name=systemd":
            path = cg
    for comp in reversed([c for c in path.split("/") if c]):
        if comp.endswith((".service", ".scope")):
            return comp
    return "unknown"


def _read(path: str) -> str | None:
    try:
        with open(path, errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def scan(proc: str = "/proc") -> list[StaleUnit]:
    """Every unit with a process that executes a replaced file, by unit name.

    Skips kernel threads, this process, and processes in another mount
    namespace (containers: their paths are not the host's)."""
    me = os.getpid()
    try:
        my_ns = os.readlink(f"{proc}/self/ns/mnt")
    except OSError:
        my_ns = None
    units: dict[str, StaleUnit] = {}
    try:
        entries = os.listdir(proc)
    except OSError:
        return []
    for name in entries:
        if not name.isdigit() or int(name) == me:
            continue
        base = f"{proc}/{name}"
        if my_ns is not None:
            try:
                if os.readlink(f"{base}/ns/mnt") != my_ns:
                    continue
            except OSError:
                pass  # unreadable ns: judge by the maps alone
        maps = _read(f"{base}/maps")
        if not maps:
            continue
        files = deleted_code_files(maps)
        if not files:
            continue
        unit = unit_of(_read(f"{base}/cgroup") or "")
        u = units.setdefault(unit, StaleUnit(unit))
        u.pids.append(int(name))
        comm = (_read(f"{base}/comm") or "?").strip()
        if comm not in u.comms:
            u.comms.append(comm)
        for f in files:
            if f not in u.files:
                u.files.append(f)
    out = sorted(units.values(), key=lambda u: u.unit)
    for u in out:
        u.pids.sort()
    return out


# --- hypervisor processes on an old binary (#254) ---------------------------------

#: Long-running VM processes: a qemu update is not in effect for a VM until
#: the VM itself is restarted.
VM_BINARIES = ("qemu-system-", "virtiofsd", "swtpm")
_SNAP_EXE = re.compile(r"^(/snap/([\w.+-]+)/(x?\d+))/")


@dataclass
class StaleVM:
    pid: int
    exe: str
    name: str
    reason: str          # "deleted" or "snap revision N, current M"
    snap: str = ""


def vm_name(argv: list[str]) -> str:
    """The VM's name from a qemu argv: ``-name guest=foo,…`` / ``-name foo``,
    or a multipass instance directory. "" if none. Pure."""
    for i, a in enumerate(argv):
        if a == "-name" and i + 1 < len(argv):
            v = argv[i + 1]
            for part in v.split(","):
                if part.startswith("guest="):
                    return part[6:]
            return v.split(",", 1)[0]
    for a in argv:
        m = re.search(r"/multipassd/vault/instances/([^/]+)/", a)
        if m:
            return m.group(1)
    return ""


def _is_vm_binary(path: str) -> bool:
    return os.path.basename(path.removesuffix(DELETED)).startswith(VM_BINARIES)


def scan_vms(proc: str = "/proc", snap_root: str = "/snap") -> list[StaleVM]:
    """Running VM processes whose executable was replaced since they started:
    the binary is deleted, or it comes from a snap revision that is no longer
    the current one (snap refresh, e.g. multipass). Read-only."""
    out: list[StaleVM] = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return []
    for name in entries:
        if not name.isdigit():
            continue
        base = f"{proc}/{name}"
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            continue
        if not _is_vm_binary(exe):
            continue
        argv = [a for a in ((_read(f"{base}/cmdline") or "").split("\0")) if a]
        vm = vm_name(argv) or f"pid {name}"
        if exe.endswith(DELETED):
            out.append(StaleVM(int(name), exe.removesuffix(DELETED), vm, "deleted"))
            continue
        m = _SNAP_EXE.match(exe)
        if m:
            try:
                cur = os.readlink(f"{snap_root}/{m.group(2)}/current")
            except OSError:
                continue
            if cur != m.group(3):
                out.append(StaleVM(int(name), exe, vm,
                                   f"snap revision {m.group(3)}, current {cur}",
                                   snap=m.group(2)))
    return sorted(out, key=lambda v: v.pid)
