# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.
# ruff: noqa: E501  (fixtures are verbatim apt-get output lines)

"""Kernel updates kept back by `apt-get upgrade` must still be reported."""

from kevward.model import FindingKind, Severity
from kevward.plugins import _apt

# Shape of the www/www2 hosts on 2026-11-07: linux-libc-dev / linux-tools-common
# upgrade, but the kernel metapackages are kept back (they need a new image).
UPGRADE = """\
Reading package lists...
Calculating upgrade...
The following packages have been kept back:
  linux-generic linux-headers-generic linux-image-generic
The following packages will be upgraded:
  linux-libc-dev linux-tools-common
2 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
Inst linux-libc-dev [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-tools-common [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [all])
Conf linux-libc-dev (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
"""

DIST = UPGRADE.split("Inst ")[0] + """\
Inst linux-libc-dev [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-tools-common [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [all])
Inst linux-image-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-modules-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-security [amd64])
Inst linux-image-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-headers-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
"""


def test_parse_inst_skips_new_packages():
    got = _apt.parse_inst(DIST)
    pkgs = [c["pkg"] for c in got]
    assert "linux-image-6.8.0-149-generic" not in pkgs  # newly installed, no [cur]
    assert "linux-generic" in pkgs and "linux-libc-dev" in pkgs
    assert all(c["kept_back"] is False for c in got)


def test_merge_flags_only_kept_back():
    merged = _apt.merge_kept_back(_apt.parse_inst(UPGRADE), _apt.parse_inst(DIST))
    kept = {c["pkg"] for c in merged if c["kept_back"]}
    assert kept == {"linux-image-generic", "linux-generic", "linux-headers-generic"}
    assert len(merged) == 5  # no duplicates of the regular upgrades


def test_kept_back_kernel_security_finding():
    merged = _apt.merge_kept_back(_apt.parse_inst(UPGRADE), _apt.parse_inst(DIST))
    by = {c["pkg"]: _apt.change_finding("apt", c) for c in merged}
    f = by["linux-image-generic"]
    assert f.kind is FindingKind.SECURITY_UPDATE and f.severity is Severity.HIGH
    assert f.title.endswith("(kept back)")
    assert "sudo apt-get install linux-image-generic" in f.detail
    assert f.reboot_required is True
    assert by["linux-generic"].reboot_required is True       # metapackage -> new kernel
    assert by["linux-headers-generic"].reboot_required is False
    assert by["linux-headers-generic"].severity is Severity.LOW  # not from -security
    assert not by["linux-libc-dev"].title.endswith("(kept back)")
    assert by["linux-libc-dev"].reboot_required is False


def test_nothing_kept_back_is_unchanged():
    up = _apt.parse_inst(UPGRADE)
    assert _apt.merge_kept_back(up, _apt.parse_inst(UPGRADE)) == up


def test_simulate_upgrade_runs_both_and_merges(monkeypatch):
    calls = []

    class R:
        def __init__(self, out):
            self.out, self.ok = out, True

    def fake_run(args, timeout=120, input_=None):
        calls.append(args[-1])
        return R({"upgrade": UPGRADE, "dist-upgrade": DIST}.get(args[-1], ""))

    monkeypatch.setattr(_apt, "run", fake_run)
    got = _apt._simulate_upgrade()
    assert calls == ["-qq", "upgrade", "dist-upgrade"]
    assert sum(c["kept_back"] for c in got) == 3
