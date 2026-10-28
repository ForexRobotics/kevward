"""Reboot handling: report, schedule in a maintenance window, or (opt-in) now.

Uses systemd where available (``shutdown`` schedules a timed reboot). Nothing
here runs unless the caller explicitly asks and policy permits it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .util import have, is_root, run


def _next_window(now: datetime, hhmm: str) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def schedule_reboot(window_start: str, message: str = "patchward maintenance") -> str:
    """Schedule a reboot at the next occurrence of ``window_start`` (HH:MM).

    Returns a human-readable description of what was scheduled. Requires root.
    """
    if not is_root():
        return "skipped: scheduling a reboot requires root"
    if not have("shutdown"):
        return "skipped: `shutdown` not available"
    now = datetime.now()
    target = _next_window(now, window_start)
    # shutdown accepts an absolute HH:MM.
    res = run(["shutdown", "-r", target.strftime("%H:%M"), message])
    if res.ok:
        return f"reboot scheduled for {target:%Y-%m-%d %H:%M} local"
    return f"failed to schedule reboot: {res.err.strip() or res.out.strip()}"


def cancel_reboot() -> str:
    if not is_root():
        return "skipped: requires root"
    res = run(["shutdown", "-c"])
    return "pending reboot cancelled" if res.ok else f"nothing to cancel: {res.err.strip()}"


def reboot_now(message: str = "patchward immediate reboot") -> str:
    if not is_root():
        return "skipped: requires root"
    res = run(["shutdown", "-r", "+1", message])
    return "reboot in 1 minute" if res.ok else f"failed: {res.err.strip()}"
