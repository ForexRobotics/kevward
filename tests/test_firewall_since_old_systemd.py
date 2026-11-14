# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The drop-counter window must be known on systemd < 251 (Ubuntu 22.04),
which rejects ``systemctl show --timestamp=unix``."""

from __future__ import annotations

from kevward.util import Cmd


def test_parse_monotonic_timestamp():
    from kevward.firewall import parse_monotonic_timestamp as p

    # 36 000.5 s after boot -> btime + 36000
    assert p("ActiveEnterTimestampMonotonic=36000500000\n", 1763000000) == 1763036000
    assert p("ActiveEnterTimestampMonotonic=0", 1763000000) is None  # never active
    assert p("ActiveEnterTimestampMonotonic=", 1763000000) is None
    assert p("ActiveEnterTimestampMonotonic=36000500000", None) is None  # no btime
    assert p("", 1763000000) is None


def _fake_systemctl(calls):
    """jammy-like systemctl: --timestamp=unix is an error, monotonic works."""
    def run(argv, **_):
        calls.append(argv)
        if "--timestamp=unix" in argv:
            return Cmd(1, "", "Invalid value for --timestamp: unix")
        if "ActiveEnterTimestampMonotonic" in argv:
            return Cmd(0, "ActiveEnterTimestampMonotonic=11000000\n", "")
        return Cmd(1, "", "unexpected")
    return run


def test_counters_since_falls_back_on_old_systemd(monkeypatch, tmp_path):
    from kevward import firewall as fw

    calls: list = []
    monkeypatch.setattr(fw, "COUNTERS_STAMP", str(tmp_path / "missing"))
    monkeypatch.setattr(fw, "run", _fake_systemctl(calls))
    monkeypatch.setattr(fw, "_boot_time", lambda: 1763060400)
    # unit became active 11 s after boot
    assert fw.counters_since() == 1763060411
    assert any("--timestamp=unix" in c for c in calls)


def test_stamp_still_wins_when_later(monkeypatch, tmp_path):
    from kevward import firewall as fw

    stamp = tmp_path / "stamp"
    stamp.write_text("1763100000\n")
    monkeypatch.setattr(fw, "COUNTERS_STAMP", str(stamp))
    monkeypatch.setattr(fw, "run", _fake_systemctl([]))
    monkeypatch.setattr(fw, "_boot_time", lambda: 1763060400)
    assert fw.counters_since() == 1763100000


def test_boot_time_reads_proc_stat():
    from kevward.firewall import _boot_time

    bt = _boot_time()
    assert bt is None or bt > 1_000_000_000
