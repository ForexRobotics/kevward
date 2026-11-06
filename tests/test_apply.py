# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for apply() non-root handling (monkeypatched; no root/host)."""

from __future__ import annotations

from kevward.model import Finding, FindingKind, Severity
from kevward.plugins import _apt


class _DummyApt(_apt.AptServicePlugin):
    name = "dummy"
    packages = ["dummy"]


def _finding() -> Finding:
    return Finding(
        service="dummy",
        kind=FindingKind.MINOR_UPGRADE,
        severity=Severity.LOW,
        title="dummy 1 -> 2",
        ref="dummy",
    )


def test_apply_non_root_reports_sudo_hint(monkeypatch):
    monkeypatch.setattr(_apt, "is_root", lambda: False)
    res = _DummyApt().apply([_finding()], dry_run=False)
    assert len(res) == 1
    assert res[0].ok is False
    assert res[0].changed is False
    assert "sudo" in res[0].output


def test_apply_dry_run_never_needs_root(monkeypatch):
    monkeypatch.setattr(_apt, "is_root", lambda: False)
    res = _DummyApt().apply([_finding()], dry_run=True)
    assert len(res) == 1
    assert res[0].dry_run is True
    assert res[0].ok is True
