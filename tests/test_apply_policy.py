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
