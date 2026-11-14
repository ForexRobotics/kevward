# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""A package change reported by a service plugin and by "apt" is shown once."""

from __future__ import annotations

from kevward.engine import RunResult
from kevward.model import Finding, FindingKind, ServiceReport, Severity
from kevward.reporting.html import render


def _upd(svc, pkg, new="2.4.52-1ubuntu4.27"):
    return Finding(service=svc, kind=FindingKind.SECURITY_UPDATE, severity=Severity.HIGH,
                   title=f"{pkg} 2.4.52-1ubuntu4.26 → {new}", ref=pkg,
                   current_version="2.4.52-1ubuntu4.26", fixed_version=new)


def _hokaku3():
    apache = [_upd("apache", "apache2"), _upd("apache", "apache2-bin")]
    apt = [_upd("apt", p) for p in ("apache2", "apache2-bin", "apache2-data", "apache2-utils")]
    apt.append(Finding(service="apt", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                       title="Reboot required"))
    return RunResult(host="h", generated_at="2026-11-14T07:00:00+00:00", os="Linux",
                     services=[ServiceReport(service="apache", present=True, findings=apache),
                               ServiceReport(service="apt", present=True, findings=apt)])


def test_high_counted_once_per_package():
    html = render(_hokaku3())
    assert "high: <b>4</b>" in html          # was 6
    assert "medium: <b>1</b>" in html        # non-package apt findings untouched
    assert html.count("apache2-bin 2.4.52") == 1
    assert "apache2-data 2.4.52" in html and "apache2-utils 2.4.52" in html
    assert "2 apt rows not repeated" in html


def test_different_target_version_is_not_a_duplicate():
    r = _hokaku3()
    r.services[1].findings[0] = _upd("apt", "apache2", new="2.4.52-1ubuntu4.28")
    assert "high: <b>5</b>" in render(r)


def test_json_keeps_every_finding():
    d = _hokaku3().to_dict()
    assert sum(len(s["findings"]) for s in d["services"]) == 7


def test_grouped_apt_row_keeps_only_unowned_packages():
    # #143: apt groups apache2* into one row; apache owns two of the four.
    r = _hokaku3()
    grouped = Finding(service="apt", kind=FindingKind.SECURITY_UPDATE, severity=Severity.HIGH,
                      title="apache2 2.4.52-1ubuntu4.26 → 2.4.52-1ubuntu4.27 (4 packages)",
                      ref="apache2", current_version="2.4.52-1ubuntu4.26",
                      fixed_version="2.4.52-1ubuntu4.27",
                      packages=["apache2", "apache2-bin", "apache2-data", "apache2-utils"])
    r.services[1].findings = [grouped, r.services[1].findings[-1]]
    html = render(r)
    assert "high: <b>3</b>" in html   # 2 under apache + 1 grouped apt row
    assert "(2 packages)" in html and "apache2-data, apache2-utils" in html
    assert "apt rows not repeated" not in html  # the row was trimmed, not hidden


def test_grouped_apt_row_fully_owned_is_hidden():
    r = _hokaku3()
    grouped = Finding(service="apt", kind=FindingKind.SECURITY_UPDATE, severity=Severity.HIGH,
                      title="apache2 x → 2.4.52-1ubuntu4.27 (2 packages)", ref="apache2",
                      fixed_version="2.4.52-1ubuntu4.27", packages=["apache2", "apache2-bin"])
    r.services[1].findings = [grouped]
    html = render(r)
    assert "high: <b>2</b>" in html and "1 apt row not repeated" in html
