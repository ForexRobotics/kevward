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
