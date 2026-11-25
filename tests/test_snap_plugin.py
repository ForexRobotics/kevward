# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#253: the snap plugin (fixture output in the shape of snapd 2.6x on 22.04 / 24.04)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from kevward.model import Severity
from kevward.plugins import snap as sp
from kevward.util import Cmd

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)

LIST = """\
Name       Version          Rev    Tracking       Publisher    Notes
core22     20241001         1663   latest/stable  canonical**  base
lxd        5.21.2-2f4ba6b   30131  5.21/stable    canonical**  -
multipass  1.14.1           13900  latest/stable  canonical**  held
snapd      2.66.1           23258  latest/stable  canonical**  snapd
certbot    2.11.0           4182   latest/edge    certbot-eff**  classic
"""
REFRESH = """\
Name       Version  Rev    Size   Publisher    Notes
multipass  1.15.0   14002  250MB  canonical**  -
"""


def test_parse_table():
    rows = sp.parse_table(LIST)
    assert [r["name"] for r in rows] == ["core22", "lxd", "multipass", "snapd", "certbot"]
    assert rows[2]["notes"] == "held" and rows[4]["tracking"] == "latest/edge"
    assert sp.parse_table("All snaps up to date.\n") == []
    assert sp.parse_table(REFRESH)[0]["rev"] == "14002"


def test_parse_hold():
    assert sp.parse_hold("", NOW) is None
    assert sp.parse_hold("forever", NOW).year == datetime.max.year
    assert sp.parse_hold("2026-12-31T00:00:00Z", NOW).day == 31
    assert sp.parse_hold("2026-01-01T00:00:00+00:00", NOW) is None   # in the past


def _findings(age_days=0, hold=None, held_days=0):
    inst, pend = sp.parse_table(LIST), sp.parse_table(REFRESH)
    seen = {"refresh:multipass:14002": (NOW - timedelta(days=age_days)).isoformat(),
            "held:multipass": (NOW - timedelta(days=held_days)).isoformat()}
    return sp.findings_for(inst, pend, hold, seen, NOW)


def _sev(fs, text):
    return [f.severity for f in fs if text in f.title]


def test_pending_refresh_ages():
    assert _sev(_findings(0), "refresh 1.14.1 → 1.15.0") == [Severity.LOW]
    assert _sev(_findings(8), "refresh") == [Severity.MEDIUM]
    assert _sev(_findings(31), "refresh") == [Severity.HIGH]


def test_holds_and_edge():
    fs = _findings(held_days=10, hold=sp.parse_hold("forever", NOW))
    assert _sev(fs, "held indefinitely") == [Severity.MEDIUM]
    assert _sev(fs, "multipass: refreshes held for 10 days") == [Severity.MEDIUM]
    assert _sev(fs, "certbot tracks the latest/edge") == [Severity.LOW]
    fs = _findings(held_days=2, hold=NOW + timedelta(days=3))
    assert not _sev(fs, "held")                      # short holds are normal


def test_update_seen_keeps_first_time():
    old = {"refresh:a:1": "2026-11-01T00:00:00+00:00", "refresh:gone:1": "x"}
    new = sp.update_seen(old, ["refresh:a:1", "refresh:b:2"], NOW)
    assert new["refresh:a:1"] == "2026-11-01T00:00:00+00:00"
    assert "refresh:gone:1" not in new and new["refresh:b:2"].startswith("2026-11-25")


def test_check_end_to_end(monkeypatch, tmp_path):
    def fake(argv, timeout=120, **kw):
        if argv[:2] == ["snap", "list"]:
            return Cmd(0, LIST, "")
        if argv[:3] == ["snap", "refresh", "--list"]:
            return Cmd(0, REFRESH, "")
        if argv[:2] == ["snap", "get"]:
            return Cmd(1, "", 'error: snap "core" has no "refresh.hold" configuration option')
        raise AssertionError(argv)

    monkeypatch.setattr(sp, "run", fake)
    monkeypatch.setattr(sp, "is_root", lambda: True)
    p = sp.SnapPlugin()
    p.seen_file = tmp_path / "snap-seen.json"
    fs = p.check()
    assert any("refresh 1.14.1 → 1.15.0" in f.title for f in fs)
    assert any("5 snap(s) installed, 1 refresh(es) pending" in f.title for f in fs)
    assert set(json.loads(p.seen_file.read_text())) == {"refresh:multipass:14002",
                                                         "held:multipass"}
