# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#1: the HAProxy plugin is discovered and silent on a host without HAProxy."""

from __future__ import annotations

from kevward.plugin import discover
from kevward.plugins import haproxy


def test_discovered():
    assert discover()["haproxy"] is haproxy.HaproxyPlugin


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = haproxy.HaproxyPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["haproxy"], "haproxy.service", ["haproxy"])
