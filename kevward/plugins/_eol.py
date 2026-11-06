# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Shared end-of-life date reasoning for runtime-version plugins.

Pure and side-effect-free so it can be unit-tested without a host: given an
"end of support" month (``YYYY-MM``) and today's date, decide whether a version
is already past support (``"after"``), close to it (``"near"``), or still
comfortably supported (``None`` -> emit no finding).

This replaces the earlier "flag every known version" behaviour, which marked a
version as near/after end of support even when its support ran for years yet
(e.g. PHP 8.4, supported to 2028-12, flagged in 2026).
"""

from __future__ import annotations

from datetime import date


def _parse_ym(ym: str) -> date | None:
    """Parse a ``YYYY-MM`` support-end marker to the first of that month."""
    try:
        year, month = ym.split("-", 1)
        return date(int(year), int(month), 1)
    except (ValueError, AttributeError):
        return None


def months_between(start: date, end: date) -> int:
    """Whole calendar months from ``start`` to ``end`` (negative if end < start)."""
    return (end.year - start.year) * 12 + (end.month - start.month)


def eol_phase(eol_ym: str, *, today: date | None = None, near_months: int = 6) -> str | None:
    """Classify an end-of-support month relative to today.

    Returns one of:
      * ``"after"`` - support ended on or before the current month,
      * ``"near"``  - support ends within ``near_months`` months,
      * ``None``    - support ends further out than that (do not flag).
    """
    end = _parse_ym(eol_ym)
    if end is None:
        return None
    left = months_between(today or date.today(), end)
    if left <= 0:
        return "after"
    if left <= near_months:
        return "near"
    return None
