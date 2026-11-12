# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for firewall drop-counter parsing (pure; no nft/root)."""

from __future__ import annotations

from kevward.firewall import parse_drop_counters

# A trimmed real `nft list table inet kevward` chain dump.
_DUMP = """
table inet kevward {
        chain input {
                type filter hook input priority mangle; policy accept;
                ip saddr @allow4 accept
                ip6 saddr @allow6 accept
                ip saddr @blocklist4 counter packets 1747 bytes 104252 drop
                ip6 saddr @blocklist6 counter packets 0 bytes 0 drop
                ip saddr @blockcidr4 counter packets 27 bytes 1260 drop
                ip6 saddr @blockcidr6 counter packets 0 bytes 0 drop
        }
}
"""


def test_parse_drop_counters_reads_each_set():
    got = parse_drop_counters(_DUMP)
    assert got["blocklist4"] == (1747, 104252)
    assert got["blockcidr4"] == (27, 1260)
    assert got["blocklist6"] == (0, 0)
    assert got["blockcidr6"] == (0, 0)


def test_parse_drop_counters_ignores_accept_rules():
    got = parse_drop_counters(_DUMP)
    assert "allow4" not in got
    assert "allow6" not in got


def test_parse_drop_counters_empty_when_no_counters():
    # An older table whose drop rules carry no `counter` keyword.
    old = "ip saddr @blocklist4 drop\nip saddr @blockcidr4 drop\n"
    assert parse_drop_counters(old) == {}
    assert parse_drop_counters("") == {}


# --- counters window ("since <when>") -------------------------------------- #
def test_parse_unit_timestamp():
    from kevward.firewall import parse_unit_timestamp
    assert parse_unit_timestamp("ActiveEnterTimestamp=@1762898400\n") == 1762898400
    assert parse_unit_timestamp("ActiveEnterTimestamp=") is None      # never started
    assert parse_unit_timestamp("ActiveEnterTimestamp=@0") is None
    assert parse_unit_timestamp("ActiveEnterTimestamp=Thu 2026-11-12") is None
    assert parse_unit_timestamp("") is None


def test_counters_since_takes_later_of_stamp_and_boot_unit(monkeypatch, tmp_path):
    from kevward import firewall as fw
    from kevward.util import Cmd

    stamp = tmp_path / "stamp"
    stamp.write_text("1762800000\n")
    monkeypatch.setattr(fw, "COUNTERS_STAMP", str(stamp))
    monkeypatch.setattr(fw, "run", lambda *a, **k: Cmd(
        0, "ActiveEnterTimestamp=@1762898400\n", ""))
    assert fw.counters_since() == 1762898400          # boot reload is later
    stamp.write_text("1762900000\n")
    assert fw.counters_since() == 1762900000          # later `firewall apply`


def test_counters_since_none_when_nothing_known(monkeypatch, tmp_path):
    from kevward import firewall as fw
    from kevward.util import Cmd

    monkeypatch.setattr(fw, "COUNTERS_STAMP", str(tmp_path / "missing"))
    monkeypatch.setattr(fw, "run", lambda *a, **k: Cmd(1, "", "no systemd"))
    assert fw.counters_since() is None


def test_stamp_written_on_counter_reset(monkeypatch, tmp_path):
    from kevward import firewall as fw

    stamp = tmp_path / "sub" / "stamp"
    monkeypatch.setattr(fw, "COUNTERS_STAMP", str(stamp))
    fw._stamp_counter_reset()
    assert int(stamp.read_text()) > 1_700_000_000


def test_html_window_label():
    from kevward.reporting.html import _fw_window

    gen = "2026-11-11T22:13:14+00:00"
    assert _fw_window(None, gen) == "since last ruleset load"
    # 2026-11-11 13:13:14 UTC = 9 h before generated_at
    nine_h = 1794402794
    assert _fw_window(nine_h, gen) == "since 2026-11-11 13:13 UTC, 9.0 h"
    assert _fw_window(nine_h - 3 * 86400, gen) == "since 2026-11-08 13:13 UTC, 3.4 days"
    assert _fw_window(nine_h + 10 * 3600, gen) == "since 2026-11-11 23:13 UTC"  # clock skew
