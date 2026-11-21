# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#171: apply says whether the plan is current, when there is nothing to
do, what was left out, and why a reboot is mentioned. No host/root."""

from __future__ import annotations

from kevward import cli, engine
from kevward.model import ActionResult, Finding, FindingKind, ServiceReport, Severity
from kevward.plugins import _apt
from kevward.util import Cmd


def _minor(pkg, reboot=False):
    return Finding(service="apt", kind=FindingKind.MINOR_UPGRADE, severity=Severity.LOW,
                   title=pkg, ref=pkg, reboot_required=reboot)


def _result(refresh=None, findings=(), actions=(), pending=False, pkgs=()):
    r = engine.RunResult("www", "t", "Linux")
    r.apt_refresh = refresh or {"state": "ok", "seconds": 3.2, "error": ""}
    r.reboot_pending = pending
    r.reboot_packages = list(pkgs)
    r.services.append(ServiceReport("apt", True, findings=list(findings),
                                    actions=list(actions)))
    return r


def _apply(monkeypatch, capsys, result, argv=("apply",)):
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: result)
    rc = cli.main(list(argv))
    return rc, capsys.readouterr().out


def test_only_minor_pending_with_kept_back_kernel(monkeypatch, capsys):
    res = _result(findings=[_minor("linux-generic", reboot=True), _minor("python3-jwt"),
                            _minor("distro-info")])
    rc, out = _apply(monkeypatch, capsys, res)
    assert rc == 0
    assert "apt lists refreshed (apt-get update ok, 3.2s)" in out
    assert "nothing to apply (0 packages)" in out
    assert "3 minor upgrades not included (use --minor)" in out
    assert ("reboot: will be required once pending updates not in this plan are "
            "installed (linux-generic)") in out
    assert "not scheduled" not in out


def test_update_failure_is_a_warning_and_exit_1(monkeypatch, capsys):
    res = _result(refresh={"state": "failed", "seconds": 0.4,
                           "error": "E: Could not get lock /var/lib/apt/lists/lock"})
    rc, out = _apply(monkeypatch, capsys, res)
    assert rc == 1
    assert ("WARNING: apt-get update failed (E: Could not get lock /var/lib/apt/lists/lock); "
            "the plan below may be stale") in out


def test_already_pending_reboot_names_packages(monkeypatch, capsys):
    res = _result(pending=True, pkgs=["libc6"])
    rc, out = _apply(monkeypatch, capsys, res)
    assert "reboot: already required (libc6)" in out
    assert "(not scheduled; use schedule-reboot" in out


def test_planned_kernel_and_no_reboot_noise(monkeypatch, capsys):
    act = ActionResult("apt", "install: linux-generic, python3-jwt", dry_run=True)
    res = _result(findings=[_minor("linux-generic", reboot=True)], actions=[act])
    _, out = _apply(monkeypatch, capsys, res, ("apply", "--minor"))
    assert "nothing to apply" not in out and "minor upgrade" not in out
    assert "reboot: will be required after these updates (linux-generic)" in out
    # Nothing pending at all: no reboot line.
    _, out = _apply(monkeypatch, capsys, _result())
    assert "reboot" not in out


def test_refresh_runs_once_per_run_and_is_recorded(monkeypatch):
    calls = []

    def fake_run(args, timeout=120, **k):
        calls.append(args[:2])
        if args[:2] == ["apt-get", "update"]:
            return Cmd(100, "", "E: Failed to fetch http://archive.ubuntu.com/x\n")
        return Cmd(0, "", "")

    monkeypatch.setattr(_apt, "run", fake_run)
    monkeypatch.setattr(_apt, "is_root", lambda: True)
    _apt.reset_simulation()
    _apt._simulate_upgrade()
    _apt._simulate_upgrade()
    assert calls.count(["apt-get", "update"]) == 1
    assert _apt.REFRESH["state"] == "failed"
    assert _apt.REFRESH["error"].startswith("E: Failed to fetch")
    monkeypatch.setattr(_apt, "is_root", lambda: False)
    _apt.reset_simulation()
    _apt._simulate_upgrade()
    assert _apt.REFRESH == {"state": "skipped", "seconds": 0.0, "error": "not root"}
    assert calls.count(["apt-get", "update"]) == 1


def test_laravel_eol_collapses_per_major():
    from datetime import date
    from pathlib import Path

    from kevward.plugins import laravel as lv

    fs = (lv.framework_findings("laravel", Path("/var/www/hokaku-app"), "v11.57.0",
                                today=date(2026, 11, 21))
          + lv.framework_findings("laravel", Path("/home/u/hokaku-app"), "v11.9.2",
                                  today=date(2026, 11, 21)))
    out = lv.collapse_eol(fs)
    eol = [f for f in out if "end of security fixes" in f.title]
    assert len(eol) == 1
    assert eol[0].title.endswith("— 2 apps") and eol[0].title.startswith("Laravel 11 ")
    assert "/var/www/hokaku-app (v11.57.0); /home/u/hokaku-app (v11.9.2)" in eol[0].detail
    assert len([f for f in out if f.severity is Severity.INFO]) == 2  # version notes stay
    single = lv.framework_findings("laravel", Path("/var/www/a"), "v11.0.0",
                                   today=date(2026, 11, 21))
    assert lv.collapse_eol(single) == single
