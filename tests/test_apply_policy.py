# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""apply honours apply_security / apply_minor per finding (issue #96)."""

from __future__ import annotations

from kevward import engine
from kevward.config import Config
from kevward.model import ActionResult, Finding, FindingKind, Severity
from kevward.plugin import ServicePlugin, select_actionable


def _f(kind: FindingKind, ref: str | None) -> Finding:
    return Finding(service="dummy", kind=kind, severity=Severity.LOW, title=str(ref), ref=ref)


SEC = _f(FindingKind.SECURITY_UPDATE, "openssl")
MINOR = _f(FindingKind.MINOR_UPGRADE, "xfsprogs")
REBOOT = _f(FindingKind.CONFIG, None)


class _Recorder(ServicePlugin):
    name = "dummy"

    def __init__(self) -> None:
        self.applied: list[list[str]] = []

    def detect(self) -> bool:
        return True

    def check(self) -> list[Finding]:
        return [SEC, MINOR, REBOOT]

    def apply(self, findings, dry_run):
        refs = [f.ref for f in findings]
        self.applied.append(refs)
        return [ActionResult(self.name, "install: " + ", ".join(refs), dry_run=dry_run)]


def _refs(fs):
    return [f.ref for f in fs]


def test_default_policy_is_security_only():
    assert _refs(select_actionable([SEC, MINOR, REBOOT], True, False)) == ["openssl"]


def test_minor_only():
    assert _refs(select_actionable([SEC, MINOR], False, True)) == ["xfsprogs"]


def test_both_and_neither():
    assert _refs(select_actionable([SEC, MINOR], True, True)) == ["openssl", "xfsprogs"]
    assert select_actionable([SEC, MINOR], False, False) == []


def test_report_passes_only_security_by_default():
    p = _Recorder()
    rep = p.report(do_apply=True, dry_run=True)
    assert p.applied == [["openssl"]]
    assert len(rep.actions) == 1


def test_report_skips_apply_when_nothing_allowed():
    p = _Recorder()
    rep = p.report(do_apply=True, dry_run=True, apply_security=False, apply_minor=False)
    assert p.applied == []
    assert rep.actions == []


def test_engine_wires_policy(monkeypatch):
    plugin = _Recorder()
    monkeypatch.setattr(engine, "load", lambda only=None: [plugin])
    cfg = Config()
    engine.run(cfg, do_apply=True, dry_run=True)
    assert plugin.applied == [["openssl"]]

    plugin.applied.clear()
    cfg.policy.apply_minor = True  # what `kevward apply --minor` sets
    engine.run(cfg, do_apply=True, dry_run=True)
    assert plugin.applied == [["openssl", "xfsprogs"]]


class _Owner(_Recorder):
    """A second plugin that owns one of the same packages (like apache vs apt)."""

    def __init__(self, name: str, refs: list[str]) -> None:
        super().__init__()
        self.name = name
        self._refs = refs

    def check(self):
        return [_f(FindingKind.SECURITY_UPDATE, r) for r in self._refs]


def test_package_claimed_by_earlier_plugin_is_not_repeated(monkeypatch):
    # issue #99: apache2 was listed under both [apache] and [apt] in a dry run
    apache = _Owner("apache", ["apache2", "apache2-bin"])
    apt = _Owner("apt", ["apache2", "apache2-bin", "apache2-data", "libglib2.0-0"])
    monkeypatch.setattr(engine, "load", lambda only=None: [apache, apt])
    res = engine.run(Config(), do_apply=True, dry_run=True)
    assert apache.applied == [["apache2", "apache2-bin"]]
    assert apt.applied == [["apache2-data", "libglib2.0-0"]]
    # findings (check/report view) are untouched
    assert len(res.services[1].findings) == 4


def test_check_only_run_claims_nothing(monkeypatch):
    apache = _Owner("apache", ["apache2"])
    apt = _Owner("apt", ["apache2"])
    monkeypatch.setattr(engine, "load", lambda only=None: [apache, apt])
    engine.run(Config(), do_apply=False, dry_run=True)
    assert apache.applied == [] and apt.applied == []


def test_dry_run_warns_when_not_root(monkeypatch, capsys):
    from kevward import cli

    monkeypatch.setattr(cli, "is_root", lambda: False)
    monkeypatch.setattr(cli, "have", lambda name: True)
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: engine.RunResult("h", "t", "Linux"))
    cli.main(["apply"])
    assert "apt package lists were not refreshed" in capsys.readouterr().out

    monkeypatch.setattr(cli, "is_root", lambda: True)
    cli.main(["apply"])
    assert "not refreshed" not in capsys.readouterr().out
