# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#131: the Exim plugin is discovered and silent on a host without Exim."""

from __future__ import annotations

from kevward.plugin import discover
from kevward.plugins import exim


def test_discovered():
    assert discover()["exim"] is exim.EximPlugin


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = exim.EximPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert p.packages == ["exim4", "exim4-base", "exim4-daemon-light", "exim4-daemon-heavy"]
    assert (p.service_unit, p.kev_terms) == ("exim4.service", ["exim"])
