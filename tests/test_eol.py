# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for shared EOL date reasoning (pure; no root/network/host)."""

from __future__ import annotations

from datetime import date

from kevward.plugins._eol import _parse_ym, eol_phase, months_between


def test_parse_ym():
    assert _parse_ym("2027-04") == date(2027, 4, 1)
    assert _parse_ym("bad") is None
    assert _parse_ym("2027") is None


def test_months_between():
    assert months_between(date(2026, 11, 1), date(2027, 4, 1)) == 5
    assert months_between(date(2026, 11, 1), date(2026, 11, 1)) == 0
    assert months_between(date(2026, 11, 1), date(2025, 12, 1)) == -11


def test_eol_phase_far_out_is_not_flagged():
    # The regression this fixes: a version supported for years is not flagged.
    today = date(2026, 11, 6)
    assert eol_phase("2028-12", today=today) is None  # PHP 8.4, ~25 months out
    assert eol_phase("2027-12", today=today) is None  # PHP 8.3, ~13 months out


def test_eol_phase_near():
    today = date(2026, 11, 6)
    assert eol_phase("2026-12", today=today) == "near"  # PHP 8.2, ~1 month
    assert eol_phase("2027-04", today=today) == "near"  # Node 22, ~5 months


def test_eol_phase_after():
    today = date(2026, 11, 6)
    assert eol_phase("2025-12", today=today) == "after"  # PHP 8.1, past
    assert eol_phase("2026-11", today=today) == "after"  # ends this month
    assert eol_phase("2026-04", today=today) == "after"  # Node 20, past


def test_eol_phase_window_is_configurable():
    today = date(2026, 1, 1)
    assert eol_phase("2026-10", today=today) is None  # 9 months, default window 6
    assert eol_phase("2026-10", today=today, near_months=12) == "near"


def test_eol_phase_bad_input_is_safe():
    assert eol_phase("nonsense") is None
    assert eol_phase("") is None
