# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Processes still running replaced libraries/binaries (needrestart-style)."""

from __future__ import annotations

import os

from kevward.model import Severity
from kevward.plugins.apt_base import stale_code_finding
from kevward.stale_libs import StaleUnit, deleted_code_files, scan, unit_of

LIBSSL = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"

MAPS = f"""\
55d0c0000000-55d0c0010000 r--p 00000000 fd:01 123 /usr/sbin/sshd
55d0c0010000-55d0c0090000 r-xp 00010000 fd:01 123 /usr/sbin/sshd
7f0000000000-7f0000100000 r-xp 00000000 fd:01 456 {LIBSSL} (deleted)
7f0000100000-7f0000120000 r--p 00100000 fd:01 456 {LIBSSL} (deleted)
7f0000200000-7f0000300000 r-xp 00000000 fd:01 789 {LIBC}.dpkg-new (deleted)
7f0000400000-7f0000500000 r--p 00000000 fd:01 999 /usr/lib/locale/locale-archive (deleted)
7f0000500000-7f0000600000 r-xp 00000000 00:05 111 /memfd:jit (deleted)
7f0000600000-7f0000700000 r-xp 00000000 00:05 112 /tmp/ffiXYZ (deleted)
7f0000700000-7f0000701000 rw-p 00000000 00:00 0
"""


def test_deleted_code_files_only_executable_system_code():
    assert deleted_code_files(MAPS) == [LIBSSL, LIBC]
    assert deleted_code_files("") == []


def test_unit_of_v2_v1_and_nested():
    assert unit_of("0::/system.slice/nginx.service\n") == "nginx.service"
    assert unit_of("0::/init.scope\n") == "init.scope"
    assert unit_of("0::/user.slice/user-1000.slice/session-3.scope\n") == "session-3.scope"
    assert unit_of(
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n"
    ) == "x.scope"
    v1 = "12:pids:/system.slice/ssh.service\n1:name=systemd:/system.slice/ssh.service\n"
    assert unit_of(v1) == "ssh.service"
    assert unit_of("") == "unknown"


def _proc(tmp_path, pid, maps, cgroup, comm, ns="mnt:[1]"):
    d = tmp_path / str(pid)
    (d / "ns").mkdir(parents=True)
    (d / "maps").write_text(maps)
    (d / "cgroup").write_text(cgroup)
    (d / "comm").write_text(comm + "\n")
    os.symlink(ns, d / "ns" / "mnt")


def test_scan_groups_by_unit_and_skips_other_namespaces(tmp_path):
    (tmp_path / "self" / "ns").mkdir(parents=True)
    os.symlink("mnt:[1]", tmp_path / "self" / "ns" / "mnt")
    ssh = "0::/system.slice/ssh.service\n"
    _proc(tmp_path, 200, MAPS, ssh, "sshd")
    _proc(tmp_path, 100, MAPS, ssh, "sshd")
    _proc(tmp_path, 300, "", "0::/\n", "kthreadd")  # kernel thread: no maps
    _proc(tmp_path, 400, MAPS, "0::/system.slice/docker-ab.scope\n", "nginx",
          ns="mnt:[2]")  # container: not host paths
    _proc(tmp_path, 500, MAPS.replace(" (deleted)", ""),
          "0::/system.slice/cron.service\n", "cron")  # up to date
    units = scan(str(tmp_path))
    assert [u.unit for u in units] == ["ssh.service"]
    u = units[0]
    assert u.pids == [100, 200] and u.comms == ["sshd"]
    assert u.files == [LIBSSL, LIBC] and u.tls
    assert u.hint() == "systemctl restart ssh"


def test_scan_missing_proc(tmp_path):
    assert scan(str(tmp_path / "nope")) == []


def test_finding_none_when_nothing_stale():
    assert stale_code_finding("apt", []) is None


def test_finding_medium_for_tls_service_low_otherwise():
    ssh = StaleUnit("ssh.service", [100], ["sshd"], [LIBSSL, LIBC])
    f = stale_code_finding("apt", [ssh])
    assert f.severity == Severity.MEDIUM
    assert f.title == "1 unit still runs replaced code (ssh)"
    assert "libc.so.6, libssl.so.3 -> systemctl restart ssh" in f.detail
    assert not f.refs  # never acted on by apply()

    cron = StaleUnit("cron.service", [7], ["cron"], [LIBC])
    init = StaleUnit("init.scope", [1], ["systemd"], [LIBC])
    sess = StaleUnit("session-3.scope", [900], ["bash"], [LIBSSL])
    f = stale_code_finding("apt", [cron, init, sess])
    assert f.severity == Severity.LOW  # TLS only in a login session
    assert f.title == "3 units still run replaced code (cron, init.scope, session-3.scope)"
    assert "systemctl daemon-reexec" in f.detail
    assert "log out and back in" in f.detail


def test_finding_notes_partial_view_as_non_root():
    cron = StaleUnit("cron.service", [7], ["cron"], [LIBC])
    f = stale_code_finding("apt", [cron], complete=False)
    assert "run as root to see all" in f.detail
