# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Why is a reboot required? (issue #144: reboot-required.pkgs)"""

from __future__ import annotations

from kevward import util
from kevward.engine import RunResult
from kevward.model import Severity
from kevward.plugins.apt_base import reboot_finding
from kevward.reporting.html import render


def test_reboot_pending_pkgs_dedupes(monkeypatch, tmp_path):
    f = tmp_path / "reboot-required.pkgs"
    f.write_text("libc6\nlibc6\n\ndbus\n")
    monkeypatch.setattr(util, "REBOOT_PKGS_FILES", (str(tmp_path / "missing"), str(f)))
    assert util.reboot_pending_pkgs() == ["libc6", "dbus"]


def test_reboot_pending_pkgs_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(util, "REBOOT_PKGS_FILES", (str(tmp_path / "nope"),))
    assert util.reboot_pending_pkgs() == []


def test_reboot_kind():
    assert util.reboot_kind([]) == ""
    assert util.reboot_kind(["libc6"]) == "userspace"
    assert util.reboot_kind(["libc6", "linux-image-6.8.0-150-generic"]) == "kernel"
    assert util.reboot_kind(["linux-base"]) == "kernel"
    assert util.reboot_kind(["intel-microcode"]) == "kernel"


def test_format_pkgs():
    assert util.format_pkgs(["libc6"]) == "libc6"
    assert util.format_pkgs(["a", "b", "c", "d", "e"]) == "a, b, c +2 more"


def test_finding_userspace_is_low_kernel_is_medium():
    f = reboot_finding("apt", ["libc6"])
    assert f.severity == Severity.LOW
    assert f.title == "Reboot required (libc6)"
    assert "Requested by: libc6." in f.detail
    assert reboot_finding("apt", ["linux-image-6.8.0-150-generic"]).severity == Severity.MEDIUM
    unknown = reboot_finding("apt", [])
    assert unknown.severity == Severity.MEDIUM and unknown.title == "Reboot required"


def _res(pkgs, pending=True):
    return RunResult(host="h", generated_at="2026-11-14T07:00:00+00:00",
                     os="Linux", reboot_pending=pending, reboot_packages=pkgs)


def test_header_names_packages():
    assert "reboot required: <b>YES (libc6)</b>" in render(_res(["libc6"]))
    assert "reboot required: <b>YES</b>" in render(_res([]))
    assert "reboot required: <b>no</b>" in render(_res(["libc6"], pending=False))


def test_json_fields():
    d = _res(["libc6"]).to_dict()
    assert d["reboot_packages"] == ["libc6"] and d["reboot_kind"] == "userspace"
    d = _res([], pending=False).to_dict()
    assert d["reboot_packages"] == [] and d["reboot_kind"] == ""
