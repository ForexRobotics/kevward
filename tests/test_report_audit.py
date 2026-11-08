# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The HTML report integrates audit findings only when audit was run."""

from __future__ import annotations

from kevward import __version__
from kevward.engine import RunResult
from kevward.model import Finding, FindingKind, Severity
from kevward.reporting.html import render


def _base(**kw) -> RunResult:
    return RunResult(host="web01", generated_at="2026-11-02T00:00:00+00:00",
                     os="Linux 6.8.0-150-generic", **kw)


def test_no_audit_section_when_not_run():
    html = render(_base())                      # audit is None
    assert "Host compromise indicators" not in html


def test_audit_section_present_but_clean():
    html = render(_base(audit=[]))              # ran, nothing found
    assert "Host compromise indicators" in html
    assert "No compromise indicators found" in html


def test_audit_finding_shown_and_counted_in_header():
    f = Finding(service="audit", kind=FindingKind.CONFIG, severity=Severity.HIGH,
                title="possible reverse shell: bash -> 185.100.1.1:4444",
                detail="ESTAB ... bash")
    html = render(_base(audit=[f]))
    assert "Host compromise indicators" in html
    assert "possible reverse shell" in html
    # the finding's severity is reflected in the header severity chips
    assert "high: <b>1</b>" in html


def test_report_shows_kevward_version():
    html = render(_base())
    assert f"kevward {__version__}" in html          # footer + header
    assert _base().to_dict()["kevward_version"] == __version__


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all report-audit tests passed")


def test_firewall_not_loaded_warning_only_when_unit_enabled():
    gone = _base(attackers={"firewall_state": {"table": False, "unit": "enabled"}})
    assert "kevward firewall not loaded" in render(gone)
    ok = _base(attackers={"firewall_state": {"table": True, "unit": "enabled"}})
    assert "kevward firewall not loaded" not in render(ok)
    never = _base(attackers={"firewall_state": {"table": False, "unit": ""}})
    assert "kevward firewall not loaded" not in render(never)
    unknown = _base(attackers={"firewall_state": {"table": None, "unit": "enabled"}})
    assert "kevward firewall not loaded" not in render(unknown)


def test_header_says_counts_include_audit_and_findings_table_explains():
    f = Finding(service="audit", kind=FindingKind.CONFIG, severity=Severity.LOW,
                title="authorized_keys has 1 forced-command key(s)", detail="")
    html = render(_base(audit=[f]))
    assert "counts include 1 audit indicator " in html
    assert "audit indicators are listed below" in html
    assert "No findings." not in html


def test_no_audit_note_without_audit_items():
    html = render(_base(audit=[]))
    assert "counts include" not in html
    assert "No findings." in html
