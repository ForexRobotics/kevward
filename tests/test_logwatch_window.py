# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

from datetime import datetime, timedelta, timezone

from kevward.integrations.logwatch import parse_log_time, summarize_failures
from kevward.reporting.html import _ssh_window

JST = timezone(timedelta(hours=9))
NOW = datetime(2026, 11, 7, 10, 0, 0, tzinfo=JST)


def test_parse_rfc3339():
    ts = parse_log_time(
        "2026-11-07T09:43:01.123456+09:00 host sshd[1]: Invalid user a from 1.2.3.4", NOW)
    assert ts == datetime(2026, 11, 7, 9, 43, 1, 123456, tzinfo=JST)


def test_parse_rfc3339_short_fraction_and_z():
    ts = parse_log_time("2026-11-07T00:00:00.5Z host x", NOW)
    assert ts == datetime(2026, 11, 7, 0, 0, 0, 500000, tzinfo=timezone.utc)


def test_parse_classic_syslog_uses_local_zone_and_year():
    ts = parse_log_time("Nov  7 09:43:01 host sshd[1]: x", NOW)
    assert ts == datetime(2026, 11, 7, 9, 43, 1, tzinfo=JST)


def test_classic_syslog_year_rollover():
    jan = datetime(2027, 1, 2, 0, 0, tzinfo=JST)
    assert parse_log_time("Dec 30 23:00:00 host x", jan).year == 2026


def test_unparseable_is_none():
    assert parse_log_time("garbage line", NOW) is None


def test_summarize_counts_window_and_recent_slices():
    lines = [
        # 20 days ago (history only)
        "Oct 18 10:00:00 h sshd[1]: Failed password for root from 77.239.124.78 port 1 ssh2",
        "Oct 18 10:00:01 h sshd[1]: Failed password for root from 77.239.124.78 port 1 ssh2",
        # 3 days ago (7d slice)
        "2026-11-04T10:00:00+09:00 h sshd[2]: Invalid user bob from 2.57.121.25 port 2",
        # 1 hour ago (24h slice)
        "2026-11-07T09:00:00+09:00 h sshd[3]: Invalid user eve from 185.244.235.133 port 3",
        "2026-11-07T09:30:00+09:00 h sshd[3]: Invalid user eve from 185.244.235.133 port 3",
        # not a failure
        "2026-11-07T09:31:00+09:00 h sshd[4]: Accepted publickey for ktakahashi from 106.73.233.64",
    ]
    agg = summarize_failures(lines, NOW)
    assert sum(agg["counts"].values()) == 5
    assert agg["counts"]["77.239.124.78"] == 2
    assert agg["attempts_24h"] == 2
    assert agg["sources_24h"] == 1
    assert agg["attempts_7d"] == 3
    assert agg["first"] == datetime(2026, 10, 18, 10, 0, 0, tzinfo=JST)
    assert agg["last"] == datetime(2026, 11, 7, 9, 30, 0, tzinfo=JST)


def test_html_labels_period_and_recent():
    lw = {
        "ssh_total_attempts": 477768,
        "ssh_window_start": "2026-10-11T00:00:05+09:00",
        "ssh_window_end": "2026-11-07T06:59:00+09:00",
        "ssh_attempts_24h": 0,
        "ssh_attempts_7d": 12,
        "ssh_sources_24h": 0,
    }
    suffix, recent = _ssh_window(lw)
    assert "2026-10-11 → 2026-11-07" in suffix
    assert "last 24h: <b>0</b>" in recent and "last 7d: <b>12</b>" in recent


def test_html_no_window_when_no_data():
    assert _ssh_window({"ssh_total_attempts": 0}) == ("", "")
    # older JSON without the new keys still renders
    assert _ssh_window({"ssh_total_attempts": 5}) == ("", "")
