# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Lightweight attacker signal from auth logs (logwatch-style, no dependency).

If `logwatch` is installed we capture its summary; independently we parse
sshd auth failures directly so the report works even without logwatch.
"""

from __future__ import annotations

import gzip
import re
from collections import Counter
from datetime import datetime, timedelta
from glob import glob
from pathlib import Path

from ..util import have, run

_IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"
_FAILED = re.compile(rf"Failed password for .*? from {_IP}")
_INVALID = re.compile(rf"Invalid user \S+ from {_IP}")

# Ubuntu 24.04+ rsyslog writes RFC 3339 stamps; 22.04 and older write the
# classic "Mon DD HH:MM:SS" form with no year.
_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?"
)
_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_log_time(line: str, now: datetime) -> datetime | None:
    """Timestamp at the start of an auth.log line as an aware datetime, or None.

    ``now`` must be timezone-aware; it supplies the local zone for classic
    syslog stamps and the year they lack (a stamp more than a day in the future
    is taken to be from the previous year, e.g. a December line read in January).
    """
    m = _RFC3339.match(line)
    if m:
        base, frac, tz = m.groups()
        try:
            dt = datetime.fromisoformat(base)
        except ValueError:
            return None
        if frac:
            dt = dt.replace(microsecond=int((frac + "000000")[:6]))
        if tz in (None, ""):
            return dt.replace(tzinfo=now.tzinfo)
        if tz == "Z":
            tz = "+00:00"
        elif ":" not in tz:
            tz = tz[:3] + ":" + tz[3:]
        try:
            return datetime.fromisoformat(dt.isoformat() + tz)
        except ValueError:
            return None
    m = _SYSLOG.match(line)
    if m:
        mon = _MONTHS.get(m.group(1))
        if not mon:
            return None
        try:
            dt = datetime(now.year, mon, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=now.tzinfo)
        except ValueError:
            return None
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt
    return None


def _iter_lines(log_glob: str):
    for path in sorted(glob(log_glob)):
        p = Path(path)
        try:
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", errors="ignore") as fh:  # type: ignore[operator]
                yield from fh
        except OSError:
            continue


def summarize_failures(lines, now: datetime) -> dict:
    """Pure aggregation of sshd auth failures over ``lines``.

    Besides the all-time per-IP counts it records the time span the counted
    lines cover and how many attempts fall in the last 24 hours / 7 days, so a
    report can say whether a big number is history or happening now.
    """
    counts: Counter = Counter()
    first = last = None
    n24 = n7d = 0
    src24: set[str] = set()
    d1, d7 = now - timedelta(days=1), now - timedelta(days=7)
    for line in lines:
        m = _FAILED.search(line) or _INVALID.search(line)
        if not m:
            continue
        ip = m.group(1)
        counts[ip] += 1
        ts = parse_log_time(line, now)
        if ts is None:
            continue
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts
        if ts >= d7:
            n7d += 1
            if ts >= d1:
                n24 += 1
                src24.add(ip)
    return {
        "counts": counts,
        "first": first,
        "last": last,
        "attempts_24h": n24,
        "attempts_7d": n7d,
        "sources_24h": len(src24),
    }


def ssh_auth_failures(log_glob: str = "/var/log/auth.log*") -> Counter:
    now = datetime.now().astimezone()
    return summarize_failures(_iter_lines(log_glob), now)["counts"]


def logwatch_summary() -> str | None:
    if not have("logwatch"):
        return None
    res = run(
        ["logwatch", "--range", "yesterday", "--service", "sshd", "--output", "stdout"],
        timeout=120,
    )
    return res.out if res.ok else None


def collect(log_glob: str = "/var/log/auth.log*") -> dict:
    now = datetime.now().astimezone()
    agg = summarize_failures(_iter_lines(log_glob), now)
    fails: Counter = agg["counts"]
    iso = lambda d: d.isoformat(timespec="seconds") if d else None  # noqa: E731
    return {
        "logwatch_available": have("logwatch"),
        "ssh_failed_logins": fails.most_common(50),
        "ssh_unique_sources": len(fails),
        "ssh_total_attempts": sum(fails.values()),
        # Window the totals above cover (all rotated auth.log* files), plus
        # recent slices so a large historical total is not read as current.
        "ssh_window_start": iso(agg["first"]),
        "ssh_window_end": iso(agg["last"]),
        "ssh_attempts_24h": agg["attempts_24h"],
        "ssh_attempts_7d": agg["attempts_7d"],
        "ssh_sources_24h": agg["sources_24h"],
    }
