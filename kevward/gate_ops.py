# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""ssh-gate phase 2 ops: reboot scheduling (#198) and the report timer (#199).

Both reuse kevward's existing host-side mechanisms — ``shutdown`` /
systemd-logind for reboots (#114) and ``kevward schedule`` for the timer
(#69) — so something scheduled by hand and through the gate look the same,
and nothing depends on the console being awake. Host policy still decides:
a reboot needs ``[policy] allow_reboot = true`` on the host.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Config
from .ssh_gate import GateError

MIN_LEAD = timedelta(minutes=5)
MAX_LEAD = timedelta(days=7)
_REASON = re.compile(r"^[\w .,:;()/@+#'-]{0,80}$", re.UNICODE)


def _record(changes_file: Path, rec: dict) -> None:
    try:
        changes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(changes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass  # syslog still has it


def _last_gate_schedule(changes_file: Path, at: str | None) -> dict | None:
    """The change-log record that set the reboot scheduled for ``at``."""
    if not at:
        return None
    try:
        lines = changes_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    want = _parse_at(at)
    for ln in reversed(lines):
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if rec.get("kind") == "reboot.schedule":
            try:
                if abs((_parse_at(rec["at"]) - want).total_seconds()) < 90:
                    return rec
            except (KeyError, GateError):
                continue
    return None


def _parse_at(value) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise GateError("bad_request", "at must be an ISO 8601 time with an offset, "
                        "e.g. 2026-11-23T03:00+09:00")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError("bad_request", f"not an ISO 8601 time: {value!r}") from None
    if when.tzinfo is None:
        raise GateError("bad_request", "at needs a UTC offset (e.g. +09:00)")
    return when


# --- reboot (#198) ------------------------------------------------------------------

def op_reboot_status(*, changes_file: Path) -> dict:
    from . import scheduler
    from .util import reboot_kind, reboot_pending, reboot_pending_pkgs

    st = scheduler.scheduled_reboot()
    pkgs = reboot_pending_pkgs() if reboot_pending() else []
    by = _last_gate_schedule(changes_file, st.get("at"))
    return {
        "scheduled": st,
        "set_by": ({"via": "ssh-gate", "client": by.get("client"), "time": by.get("time"),
                    "reason": by.get("reason")} if by else
                   ({"via": "host"} if st.get("state") == "scheduled" else None)),
        "required": bool(reboot_pending()),
        "packages": pkgs,
        "kind": reboot_kind(pkgs) if pkgs else "",
    }


def op_reboot_schedule(cfg: Config, args: dict, *, changes_file: Path, client: str,
                       now: datetime, runner=None) -> dict:
    from . import scheduler
    from .util import run

    runner = runner or run
    when = _parse_at(args.get("at"))
    reason = args.get("reason", "")
    if not isinstance(reason, str) or not _REASON.match(reason):
        raise GateError("bad_request", "reason: at most 80 plain characters")
    replace = args.get("replace", False)
    if not isinstance(replace, bool):
        raise GateError("bad_request", "replace must be true or false")
    if not cfg.policy.allow_reboot:
        raise GateError("forbidden", "reboots are not allowed on this host "
                        "([policy] allow_reboot = true in the host's config)")
    lead = when - now
    if lead < MIN_LEAD:
        raise GateError("bad_request", "at must be at least 5 minutes in the future")
    if lead > MAX_LEAD:
        raise GateError("bad_request", "at must be within 7 days")
    current = scheduler.scheduled_reboot()
    if current.get("state") == "scheduled" and not replace:
        raise GateError("conflict", f"a reboot is already scheduled for "
                        f"{current.get('at')}; send \"replace\": true to move it")
    minutes = max(1, math.ceil(lead.total_seconds() / 60))
    msg = "kevward (ssh-gate)" + (f": {reason}" if reason else "")
    r = runner(["shutdown", "-r", f"+{minutes}", msg], timeout=30)
    if r.rc != 0:
        raise GateError("internal", "shutdown failed: " + (r.err or r.out).strip()[:200])
    at = (now + timedelta(minutes=minutes)).astimezone(timezone.utc)
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "reboot.schedule", "at": at.isoformat(timespec="seconds"),
                           "reason": reason, "replaced": current if replace else None})
    return {"scheduled": {"state": "scheduled", "at": at.isoformat(timespec="seconds"),
                          "mode": "reboot"}, "replaced": current.get("state") == "scheduled"}


def op_reboot_cancel(*, changes_file: Path, client: str, now: datetime,
                     runner=None) -> dict:
    from . import scheduler
    from .util import run

    runner = runner or run
    current = scheduler.scheduled_reboot()
    if current.get("state") != "scheduled":
        raise GateError("not_found", "no reboot is scheduled")
    r = runner(["shutdown", "-c"], timeout=30)
    if r.rc != 0:
        raise GateError("internal", "shutdown -c failed: " + (r.err or r.out).strip()[:200])
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "reboot.cancel", "was": current})
    return {"cancelled": current}


# --- report timer (#199) -------------------------------------------------------------

def op_schedule_status() -> dict:
    from . import schedule as sch

    props, warns = sch.status()
    return {"timer": props, "calendar": sch.calendar_of(props.get("TimersCalendar", "")),
            "warnings": warns}


def op_schedule_install(*, changes_file: Path, client: str, now: datetime,
                        paths=None) -> dict:
    from . import schedule as sch

    ok_, msgs = sch.install(paths=paths)
    if not ok_:
        raise GateError("internal", "; ".join(msgs)[:300])
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "schedule.install", "messages": msgs})
    return {"messages": msgs}
