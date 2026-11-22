# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Reboot handling: report, schedule in a maintenance window, or (opt-in) now.

Uses systemd where available (``shutdown`` schedules a timed reboot). Nothing
here runs unless the caller explicitly asks and policy permits it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .util import have, is_root, run

#: Where systemd-logind keeps a pending `shutdown -r HH:MM` (USEC=, MODE=).
#: Readable without root. `shutdown --show` would be simpler, but it only
#: exists from systemd 250 and Ubuntu 22.04 ships 249 (#114).
SCHEDULED_FILE = "/run/systemd/shutdown/scheduled"


def _next_window(now: datetime, hhmm: str) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def schedule_reboot(window_start: str,
                    message: str = "kevward maintenance") -> tuple[bool, str]:
    """Schedule a reboot at the next occurrence of ``window_start`` (HH:MM).

    Returns ``(ok, human-readable message)``. Requires root.
    """
    if not is_root():
        return False, "skipped: scheduling a reboot requires root"
    if not have("shutdown"):
        return False, "skipped: `shutdown` not available"
    now = datetime.now()
    target = _next_window(now, window_start)
    # shutdown accepts an absolute HH:MM.
    res = run(["shutdown", "-r", target.strftime("%H:%M"), message])
    if res.ok:
        return True, f"reboot scheduled for {target:%Y-%m-%d %H:%M} local"
    return False, f"failed to schedule reboot: {res.err.strip() or res.out.strip()}"


def cancel_reboot() -> tuple[bool, str]:
    """Cancel a pending scheduled shutdown/reboot (``shutdown -c``)."""
    if not is_root():
        return False, "skipped: cancelling a reboot requires root"
    if not have("shutdown"):
        return False, "skipped: `shutdown` not available"
    before = scheduled_reboot()
    res = run(["shutdown", "-c"])
    if not res.ok:
        return False, f"failed to cancel: {res.err.strip() or res.out.strip()}"
    if before.get("state") == "none":
        return True, "nothing was scheduled"
    return True, "scheduled reboot cancelled"


#: systemd's USEC_INFINITY: logind reports "nothing scheduled" as this or 0.
USEC_INFINITY = 2**64 - 1


def _from_usec(usec: int) -> datetime | None:
    """Realtime microseconds -> UTC datetime; None for 0, infinity or out of range."""
    if usec <= 0 or usec >= USEC_INFINITY:
        return None
    try:
        return datetime.fromtimestamp(usec / 1_000_000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def parse_scheduled(text: str) -> tuple[datetime, str] | None:
    """``(when (UTC), mode)`` from logind's scheduled file, or None. Pure.

    The file holds ``USEC=<realtime microseconds>`` and ``MODE=reboot`` (or
    poweroff/halt/...).
    """
    fields = dict(
        line.split("=", 1) for line in (text or "").splitlines() if "=" in line
    )
    usec = fields.get("USEC", "").strip()
    when = _from_usec(int(usec)) if usec.isdigit() else None
    if when is None:
        return None
    return when, (fields.get("MODE", "").strip() or "reboot")


def parse_busctl_scheduled(text: str) -> tuple[datetime, str] | None:
    """Parse ``busctl get-property ... ScheduledShutdown``: ``(st) "reboot" 1731...``."""
    m = re.search(r'"([^"]*)"\s+(\d+)', text or "")
    when = _from_usec(int(m.group(2))) if m else None
    if when is None:
        return None
    return when, (m.group(1) or "reboot")


def scheduled_reboot(path: str | None = None) -> dict:
    """Whether a shutdown/reboot is scheduled. Read-only, fail-soft: anything
    unexpected gives ``{"state": "unknown"}``, never an exception.

    Returns ``{"state": "scheduled", "at": <ISO 8601 UTC>, "mode": "reboot"}``,
    ``{"state": "none"}``, or ``{"state": "unknown"}`` when neither the file
    nor logind could be read.
    """
    try:
        return _scheduled_reboot(path)
    except Exception:
        return {"state": "unknown"}


def _scheduled_reboot(path: str | None) -> dict:
    p = path or SCHEDULED_FILE
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            got = parse_scheduled(fh.read())
        if got is None:
            return {"state": "none"}
        return {"state": "scheduled", "at": got[0].isoformat(), "mode": got[1]}
    except FileNotFoundError:
        if path is not None:
            return {"state": "none"}
    except OSError:
        pass
    if have("busctl"):
        r = run(["busctl", "get-property", "org.freedesktop.login1",
                 "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                 "ScheduledShutdown"], timeout=10)
        if r.ok:
            got = parse_busctl_scheduled(r.out)
            if got is None:
                return {"state": "none"}
            return {"state": "scheduled", "at": got[0].isoformat(), "mode": got[1]}
    # No file and no logind answer: on a systemd host a missing file means
    # nothing is scheduled.
    return {"state": "none"} if path is None and _systemd_host() else {"state": "unknown"}


def _systemd_host() -> bool:
    import os
    return os.path.isdir("/run/systemd/system")


def describe(st: dict) -> str:
    """``2026-11-13 21:00 JST (reboot)``, ``none`` or ``unknown``."""
    if st.get("state") != "scheduled":
        return st.get("state") or "unknown"
    try:
        when = datetime.fromisoformat(st["at"]).astimezone()
    except (KeyError, ValueError):
        return "unknown"
    mode = st.get("mode") or "reboot"
    return f"{when:%Y-%m-%d %H:%M %Z}" + ("" if mode == "reboot" else f" ({mode})")
