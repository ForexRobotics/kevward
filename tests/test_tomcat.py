# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#135: the Tomcat plugin is discovered and silent on a host without Tomcat."""

from __future__ import annotations

from kevward.plugin import discover
from kevward.plugins import tomcat


def test_discovered():
    assert discover()["tomcat"] is tomcat.TomcatPlugin


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = tomcat.TomcatPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["tomcat9", "tomcat10"], "tomcat10.service", ["apache:tomcat"])
