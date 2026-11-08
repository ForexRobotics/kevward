# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The report distinguishes "reboot needed now" from "after pending updates"."""

from __future__ import annotations

from kevward.engine import RunResult
from kevward.model import Finding, FindingKind, ServiceReport, Severity
from kevward.reporting.html import render


def _res(pending: bool, kernel_update: bool) -> RunResult:
    findings = []
    if kernel_update:
        findings.append(Finding(service="apt", kind=FindingKind.MINOR_UPGRADE,
                                severity=Severity.MEDIUM,
                                title="linux-generic a -> b (kept back)",
                                reboot_required=True))
    return RunResult(host="h", generated_at="2026-11-09T00:00:00+00:00",
                     os="Linux 5.15.0-202-generic",
                     services=[ServiceReport(service="apt", present=True,
                                             findings=findings)],
                     reboot_pending=pending)


def test_status_values():
    assert _res(False, False).reboot_status == "no"
    assert _res(False, True).reboot_status == "after-updates"
    assert _res(True, False).reboot_status == "now"
    assert _res(True, True).reboot_status == "now"


def test_header_wording():
    assert "reboot required: <b>after pending updates</b>" in render(_res(False, True))
    assert "reboot required: <b>YES</b>" in render(_res(True, False))
    assert "reboot required: <b>no</b>" in render(_res(False, False))


def test_json_carries_pending_flag():
    d = _res(True, False).to_dict()
    assert d["reboot_pending"] is True and d["reboot_required"] is True
