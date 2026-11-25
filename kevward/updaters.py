# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Automatic updaters and truthgate's enforce mode (#229, #247).

Under truthgate's enforce mode, package changes only work inside a
maintenance window. Outside one, dpkg's new binaries are blocked and packages
are left half-configured. So:

- ``kevward apply`` (shell, the weekly timer, a console job) refuses when
  truthgate enforces and no ``apply`` window is open (#247);
- the report warns when unattended-upgrades or ``kevward-apply.timer`` would
  run there (#229, #247), and says what unattended-upgrades installed lately
  so "nothing pending" can be told apart from "already installed" (#229).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model import Finding, FindingKind, Severity

REFUSED_FILE = Path("/var/lib/kevward/apply-refused.json")
UU_LOG = Path("/var/log/unattended-upgrades/unattended-upgrades.log")
STATUS_TIMEOUT_S = 10
EXIT_REFUSED = 5   # 4 is apply --job's busy lock (gate_apply.EXIT_BUSY)
REFUSED_NOTICE_DAYS = 8


# --- truthgate status ---------------------------------------------------------------

def truthgate_status(cfg, *, runner=None, check=None) -> dict:
    """``truthgate.status`` through the relay, reduced to what kevward needs:
    ``{"installed", "readable", "mode", "maintenance", "error"}``. Never raises."""
    from .ssh_gate import GateError
    from .truthgate import relay

    try:
        r = relay(b'{"op":"truthgate.status"}', "read", cfg, client="local", key=None,
                  timeout=min(STATUS_TIMEOUT_S, cfg.ssh_gate.truthgate_timeout_s),
                  runner=runner, check=check)
    except GateError as e:
        if e.code == "not_installed":
            return {"installed": False, "readable": False, "mode": None,
                    "maintenance": None, "error": ""}
        return {"installed": True, "readable": False, "mode": None, "maintenance": None,
                "error": e.message}
    except Exception as e:  # noqa: BLE001 - a status read must never break apply/report
        return {"installed": True, "readable": False, "mode": None, "maintenance": None,
                "error": type(e).__name__}
    if not r.get("ok") or not isinstance(r.get("data"), dict):
        return {"installed": True, "readable": False, "mode": None, "maintenance": None,
                "error": str(r.get("error") or r.get("code") or "bad response")[:200]}
    d = r["data"]
    m = d.get("maintenance")
    return {"installed": True, "readable": True, "mode": d.get("mode"),
            "maintenance": m if isinstance(m, dict) else None, "error": ""}


def apply_refusal(st: dict) -> str | None:
    """Why ``apply`` must not run now, or None (#247). Pure. A wrong "go on"
    breaks the host; a wrong "refuse" only delays updates."""
    if not st.get("installed"):
        return None
    if not st.get("readable"):
        return ("truthgate is installed but its status cannot be read "
                f"({st.get('error') or 'no answer'}); not applying. Apply from the console")
    if st.get("mode") != "enforce":
        return None
    if (st.get("maintenance") or {}).get("kind") == "apply":
        return None
    return ("truthgate is enforcing and no maintenance window is open; "
            "apply from the console")


def record_refusal(reason: str, source: str, now: datetime | None = None,
                   path: Path = REFUSED_FILE) -> None:
    now = now or datetime.now(timezone.utc)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps({"time": now.isoformat(timespec="seconds"),
                                   "source": source, "reason": reason}) + "\n")
        os.replace(tmp, path)
    except OSError:
        pass


def last_refusal(path: Path = REFUSED_FILE) -> dict | None:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) and d.get("time") else None
    except (OSError, ValueError):
        return None


def refusal_source(environ=None) -> str:
    environ = os.environ if environ is None else environ
    return "systemd" if environ.get("INVOCATION_ID") else "cli"


# --- unattended-upgrades ------------------------------------------------------------

def uu_state(run=None) -> dict:
    """Is unattended-upgrades installed, enabled in apt's periodic config, and
    its timer active? Read-only."""
    from .util import run as _run

    run = run or _run
    q = run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"], timeout=15)
    installed = q.ok and "install ok installed" in q.out
    enabled = False
    if installed:
        c = run(["apt-config", "dump", "APT::Periodic::Unattended-Upgrade"], timeout=15)
        m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"([^"]*)"', c.out or "")
        enabled = bool(m and m.group(1).strip() not in ("", "0"))
    t = run(["systemctl", "is-active", "apt-daily-upgrade.timer"], timeout=15)
    timer = t.ok and t.out.strip() == "active"
    return {"installed": installed, "enabled": enabled, "timer_active": timer,
            "active": installed and enabled and timer}


def apply_timer_enabled(run=None) -> bool:
    from .util import run as _run

    r = (run or _run)(["systemctl", "is-enabled", "kevward-apply.timer"], timeout=15)
    return r.ok and r.out.strip() == "enabled"


_UU_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.]\d+ INFO "
                      r"Packages that will be upgraded: (.+)$")


def uu_installed(text: str, now: datetime) -> dict:
    """Packages unattended-upgrades upgraded in the last 24 h and 7 days,
    from its log (local time stamps, read as UTC: day-level counts). Pure."""
    day, week = [], []
    for ln in text.splitlines():
        m = _UU_LINE.match(ln.strip())
        if not m:
            continue
        try:
            t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        pkgs = m.group(2).split()
        if now - t <= timedelta(days=7):
            week += pkgs
            if now - t <= timedelta(hours=24):
                day += pkgs
    return {"day": sorted(set(day)), "week": sorted(set(week))}


# --- findings -------------------------------------------------------------------------

def enforce_findings(st: dict, uu: dict, apply_timer: bool) -> list[Finding]:
    """MEDIUM for an automatic updater on a host truthgate enforces. Pure."""
    if st.get("mode") != "enforce":
        return []
    out = []
    if uu.get("active"):
        out.append(Finding(
            service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
            title="two automatic updaters: unattended-upgrades runs while truthgate enforces",
            detail="Outside a maintenance window dpkg's new binaries are blocked and packages "
                   "are left half-configured. Updates should go through kevward (console "
                   "apply) inside a window: turn unattended-upgrades off on this host "
                   "(APT::Periodic::Unattended-Upgrade \"0\")."))
    if apply_timer:
        out.append(Finding(
            service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
            title="kevward-apply.timer is enabled, but truthgate enforces: updates are not "
                  "applied automatically on this host",
            detail="The weekly apply is refused while no maintenance window is open (#247). "
                   "Apply from the console, or disable the timer "
                   "(systemctl disable --now kevward-apply.timer)."))
    return out


def refused_findings(rec: dict | None, now: datetime) -> list[Finding]:
    if not rec:
        return []
    try:
        t = datetime.fromisoformat(rec["time"])
    except (KeyError, ValueError, TypeError):
        return []
    if now - t > timedelta(days=REFUSED_NOTICE_DAYS):
        return []
    who = {"systemd": "the scheduled apply", "cli": "`kevward apply`",
           "job": "a console apply job"}.get(rec.get("source"), "an apply")
    return [Finding(service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                    title=f"{who} was refused at {rec['time']}: updates are waiting",
                    detail=f"{rec.get('reason') or ''}. Nothing was installed.")]


def uu_findings(done: dict) -> list[Finding]:
    if not done.get("week"):
        return []
    day, week = done["day"], done["week"]
    shown = ", ".join(week[:12]) + (f" (+{len(week) - 12})" if len(week) > 12 else "")
    return [Finding(service="apt", kind=FindingKind.CONFIG, severity=Severity.INFO,
                    title=f"unattended-upgrades installed {len(day)} package(s) in the last "
                          f"24 h, {len(week)} in 7 days",
                    detail=f"{shown}. From {UU_LOG}.")]


def host_findings(cfg, now: datetime | None = None, *, run=None, status=None,
                  uu_log: Path = UU_LOG, refused: Path = REFUSED_FILE) -> list[Finding]:
    """Everything above for the report. Never raises."""
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    try:
        st = status if status is not None else truthgate_status(cfg)
        if st.get("mode") == "enforce":
            out += enforce_findings(st, uu_state(run), apply_timer_enabled(run))
    except Exception:  # noqa: BLE001
        pass
    out += refused_findings(last_refusal(refused), now)
    try:
        out += uu_findings(uu_installed(uu_log.read_text(errors="replace"), now))
    except OSError:
        pass
    return out
