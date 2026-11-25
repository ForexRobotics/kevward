# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""`kevward schedule`: own the daily report timer (#69).

The report timer used to be copied by hand from ``systemd/``, and the four
production hosts drifted apart (three fired at exactly 07:00 with no delay,
which helped get the hosts rate-limited by ubuntu.com on 2026-11-07).

``install`` writes the service and timer only when they do not exist yet, and
always puts the schedule in a drop-in (``kevward-report.timer.d/50-kevward.conf``)
so a hand-edited unit is never overwritten. A small state file records which
files ``install`` created, and ``uninstall`` removes only those plus the
drop-in. ``status`` is read-only.

Unit rendering and ``systemctl show`` parsing are pure for unit tests; every
command goes through ``kevward.util.run`` as an argv list.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from .util import have, is_root, run

UNIT_DIR = Path("/etc/systemd/system")
STATE_FILE = Path("/var/lib/kevward/schedule.json")
SERVICE = "kevward-report.service"
TIMER = "kevward-report.timer"
DROPIN_NAME = "50-kevward.conf"

DEFAULT_AT = "07:00"
DEFAULT_JITTER = "20min"
DEFAULT_ARGS = "report --trends --audit -o /var/log/kevward/report.html"
#: What the read-only report service must still write (#227): its reports,
#: caches and state, and apt's package lists (``apt-get update``, #171).
RW_PATHS = ("/var/log/kevward", "/var/cache/kevward", "/var/lib/kevward",
            "/var/lib/apt/lists", "/var/cache/apt")
#: Managed drop-in for the service: always rewritten, so hosts whose unit was
#: written by an older kevward get the paths without touching the unit.
SERVICE_DROPIN_NAME = "50-kevward-paths.conf"

_AT = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_SPAN = re.compile(r"^\d+\s*(us|ms|s|sec|m|min|h|hr|d)?$")


@dataclass(frozen=True)
class Paths:
    unit_dir: Path = UNIT_DIR
    state_file: Path = STATE_FILE

    @property
    def service(self) -> Path:
        return self.unit_dir / SERVICE

    @property
    def timer(self) -> Path:
        return self.unit_dir / TIMER

    @property
    def dropin(self) -> Path:
        return self.unit_dir / f"{TIMER}.d" / DROPIN_NAME

    @property
    def service_dropin(self) -> Path:
        return self.unit_dir / f"{SERVICE}.d" / SERVICE_DROPIN_NAME


def validate(at: str, jitter: str) -> str | None:
    """Error message for a bad ``--at`` / ``--jitter``, else None. Pure."""
    if not _AT.match(at or ""):
        return f"--at must be HH:MM (24h), got {at!r}"
    if not _SPAN.match((jitter or "").strip()):
        return f"--jitter must be a systemd time span like 20min or 900s, got {jitter!r}"
    return None


def kevward_exe() -> str:
    """Absolute path of the kevward launcher to put in ExecStart."""
    found = shutil.which("kevward")
    return found or os.path.realpath(sys.argv[0])


def render_service(exe: str, args: str = DEFAULT_ARGS) -> str:
    """The report service. Read-only by design; no PrivateTmp/ProtectHome,
    which would hide /tmp and /home from the audit checks."""
    return f"""# Written by `kevward schedule install` (#69). Edit freely: install never
# overwrites an existing unit; the schedule lives in {TIMER}.d/{DROPIN_NAME}.
[Unit]
Description=kevward defensive posture report
Documentation=https://github.com/ForexRobotics/kevward
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Read-only: findings, attacker IPs, CISA KEV trends, audit. Makes no changes.
ExecStart={exe} {args}
ProtectSystem=strict
ReadWritePaths={" ".join("-" + p for p in RW_PATHS)}
NoNewPrivileges=true
"""


def render_timer() -> str:
    return f"""# Written by `kevward schedule install` (#69). The time and the random
# delay are set in {TIMER}.d/{DROPIN_NAME}; change them with
# `kevward schedule install --at HH:MM --jitter 20min`.
[Unit]
Description=Run kevward posture report daily

[Timer]
OnCalendar=*-*-* {DEFAULT_AT}:00
Persistent=true

[Install]
WantedBy=timers.target
"""


def render_dropin(at: str, jitter: str) -> str:
    """Schedule drop-in. ``OnCalendar=`` first clears the base unit's value.

    ``FixedRandomDelay=yes`` (systemd 247+) keeps each host's offset stable
    from day to day, so hosts stay spread out instead of re-colliding.
    """
    return f"""# Managed by `kevward schedule` (#69); rewritten by `kevward schedule install`.
[Timer]
OnCalendar=
OnCalendar=*-*-* {at}:00
RandomizedDelaySec={jitter.strip()}
FixedRandomDelay=yes
"""


def _read_state(paths: Paths) -> dict:
    try:
        return json.loads(paths.state_file.read_text())
    except (OSError, ValueError):
        return {}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".kevward-tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def render_service_dropin() -> str:
    """ReadWritePaths for the report service (#227). Additive to the unit's own
    list; "-" so a missing directory never stops the report from starting."""
    return f"""# Written by `kevward schedule install` (#227); rewritten on every install.
# ProtectSystem=strict keeps the report read-only; these are the exceptions:
# kevward's own logs/cache/state and apt's lists for `apt-get update`.
# The audit must see the real /home and /tmp (authorized_keys, dropped files),
# so units from older examples with ProtectHome/PrivateTmp are corrected (#246).
[Service]
ReadWritePaths={" ".join("-" + p for p in RW_PATHS)}
ProtectHome=no
PrivateTmp=no
"""


def missing_rw_paths(value: str) -> list[str]:
    """RW_PATHS not in a ``systemctl show -p ReadWritePaths`` value. Pure."""
    have_ = {tok.lstrip("-+") for tok in (value or "").split()}
    return [p for p in RW_PATHS if p not in have_]


def plan_install(paths: Paths, at: str, jitter: str, exe: str,
                 args: str = DEFAULT_ARGS) -> list[tuple[Path, str, bool]]:
    """Files ``install`` would write: (path, content, newly created). Pure
    apart from checking which files exist."""
    out: list[tuple[Path, str, bool]] = []
    if not paths.service.exists():
        out.append((paths.service, render_service(exe, args), True))
    if not paths.timer.exists():
        out.append((paths.timer, render_timer(), True))
    out.append((paths.dropin, render_dropin(at, jitter), not paths.dropin.exists()))
    out.append((paths.service_dropin, render_service_dropin(),
                not paths.service_dropin.exists()))
    return out


def recorded(paths: Paths | None = None) -> tuple[str, str]:
    """The schedule the last ``install`` used (#235), else the defaults."""
    paths = paths or Paths()
    state = _read_state(paths)
    at, jitter = state.get("at"), state.get("jitter")
    if isinstance(at, str) and isinstance(jitter, str) and validate(at, jitter) is None:
        return at, jitter
    return DEFAULT_AT, DEFAULT_JITTER


def refresh(*, dry_run: bool = False, paths: Paths | None = None) -> tuple[bool, list[str]]:
    """Bring kevward's managed service drop-in up to date (#235); run by
    ``self.update`` through ``setup --refresh``. Never creates a timer, never
    touches the schedule or the operator's unit; nothing to do when the report
    service is not installed."""
    paths = paths or Paths()
    if not paths.service.exists():
        return True, [f"{SERVICE} is not installed: nothing to refresh"]
    text = render_service_dropin()
    try:
        current = paths.service_dropin.read_text()
    except OSError:
        current = None
    if current == text:
        return True, [f"{paths.service_dropin} is up to date"]
    if dry_run:
        return True, [f"would {'create' if current is None else 'update'} "
                      f"{paths.service_dropin}"]
    if not is_root():
        return False, ["refreshing the report service drop-in requires root"]
    try:
        _write(paths.service_dropin, text)
    except OSError as e:
        return False, [f"failed to write {paths.service_dropin}: {e}"]
    msgs = [f"{'created' if current is None else 'updated'} {paths.service_dropin}"]
    if have("systemctl"):
        r = run(["systemctl", "daemon-reload"], timeout=30)
        if not r.ok:
            return False, msgs + [f"systemctl daemon-reload failed: {(r.err or r.out).strip()}"]
    return True, msgs


def report_active(runner=None) -> bool:
    """Whether the report service is running right now (#240)."""
    r = (runner or run)(["systemctl", "is-active", SERVICE], timeout=10)
    return (r.out or "").strip() in ("active", "activating", "reloading")


def start_report(*, restart: bool = False, runner=None,
                 paths: Paths | None = None) -> str | dict:
    """Start the daily report service now, without waiting (#240): the same
    unit as the timer, so the same arguments and sandbox. ``restart`` replaces
    a run already in progress (it may predate an apply). Returns "started",
    "skipped" (no report service on this host) or {"error": …}."""
    paths = paths or Paths()
    if not paths.service.exists():
        return "skipped"
    r = (runner or run)(["systemctl", "restart" if restart else "start", "--no-block",
                         SERVICE], timeout=30)
    if r.rc != 0:
        return {"error": ((r.err or r.out or "").strip() or f"exit {r.rc}")[:200]}
    return "started"


def install(at: str | None = None, jitter: str | None = None, *, dry_run: bool = False,
            paths: Paths | None = None, exe: str | None = None) -> tuple[bool, list[str]]:
    """Write units/drop-in, reload systemd, enable and restart the timer.
    ``at`` / ``jitter`` default to what the previous install recorded (#235),
    so re-running it (or ssh-gate ``schedule.install``) never moves the timer."""
    paths = paths or Paths()
    rec_at, rec_jitter = recorded(paths)
    at = at or rec_at
    jitter = jitter or rec_jitter
    err = validate(at, jitter)
    if err:
        return False, [err]
    plan = plan_install(paths, at, jitter, exe or kevward_exe())
    if dry_run:
        msgs = ["DRY RUN (pass --yes to install)"]
        for path, text, new in plan:
            msgs.append(f"would {'create' if new else 'update'} {path}:")
            msgs.extend("    " + ln for ln in text.rstrip().splitlines())
        return True, msgs
    if not is_root():
        return False, ["installing the timer requires root (sudo)"]
    if not have("systemctl"):
        return False, ["systemctl not found: this host does not run systemd"]
    state = _read_state(paths)
    created = set(state.get("created", []))
    msgs: list[str] = []
    for path, text, new in plan:
        try:
            _write(path, text)
        except OSError as e:
            return False, msgs + [f"failed to write {path}: {e}"]
        if new and path not in (paths.dropin, paths.service_dropin):
            created.add(str(path))
        msgs.append(f"{'created' if new else 'updated'} {path}")
    for d in ("/var/lib/kevward", "/var/cache/kevward", "/var/log/kevward"):
        try:  # ReadWritePaths needs them to exist to make them writable
            os.makedirs(d, mode=0o755, exist_ok=True)
        except OSError:
            pass
    try:
        _write(paths.state_file, json.dumps(
            {"created": sorted(created), "at": at, "jitter": jitter}, indent=2) + "\n")
    except OSError as e:
        msgs.append(f"warning: could not record install state in {paths.state_file}: {e}")
    for cmd in (["systemctl", "daemon-reload"],
                ["systemctl", "enable", TIMER],
                ["systemctl", "restart", TIMER]):
        r = run(cmd, timeout=30)
        if not r.ok:
            return False, msgs + [f"{' '.join(cmd)} failed: {(r.err or r.out).strip()}"]
    msgs.append(f"{TIMER}: daily at {at} + up to {jitter} (fixed per host), enabled")
    return True, msgs


def uninstall(*, paths: Paths | None = None) -> tuple[bool, list[str]]:
    """Disable the timer and remove only what ``install`` created."""
    paths = paths or Paths()
    if not is_root():
        return False, ["removing the timer requires root (sudo)"]
    state = _read_state(paths)
    created = [Path(p) for p in state.get("created", [])]
    msgs: list[str] = []
    if paths.timer in created and have("systemctl"):
        run(["systemctl", "disable", "--now", TIMER], timeout=30)
        msgs.append(f"disabled {TIMER}")
    for path in [paths.dropin, paths.service_dropin, *created]:
        try:
            path.unlink()
            msgs.append(f"removed {path}")
        except FileNotFoundError:
            pass
        except OSError as e:
            msgs.append(f"could not remove {path}: {e}")
    for d in (paths.dropin.parent, paths.service_dropin.parent):
        try:
            d.rmdir()  # only if now empty: other drop-ins stay
        except OSError:
            pass
    try:
        paths.state_file.unlink()
    except OSError:
        pass
    if not created and not msgs:
        msgs.append("nothing to remove (install did not create any units here)")
    elif paths.timer not in created:
        msgs.append(f"{TIMER} was not created by kevward: left in place"
                    + (" (back on its own schedule)" if paths.timer.exists() else ""))
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], timeout=30)
    return True, msgs


_SHOW_PROPS = ["TimersCalendar", "RandomizedDelayUSec", "FixedRandomDelay",
               "NextElapseUSecRealtime", "LastTriggerUSec", "UnitFileState",
               "ActiveState", "Persistent"]


def parse_show(text: str) -> dict[str, str]:
    """``systemctl show -p A -p B`` output -> {A: value}. Pure."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def calendar_of(timers_calendar: str) -> str:
    """``{ OnCalendar=*-*-* 07:00:00 ; next_elapse=... }`` -> ``*-*-* 07:00:00``."""
    m = re.search(r"OnCalendar=([^;}]+)", timers_calendar or "")
    return m.group(1).strip() if m else (timers_calendar or "").strip()


def status_warnings(props: dict[str, str], dropin_exists: bool,
                    rw_paths: str | None = None) -> list[str]:
    """What looks wrong compared with what ``install`` would set. Pure."""
    warn: list[str] = []
    if props.get("UnitFileState") not in ("enabled", "enabled-runtime", "static"):
        warn.append(f"{TIMER} is not enabled ({props.get('UnitFileState') or 'not found'})")
    if props.get("ActiveState") and props.get("ActiveState") != "active":
        warn.append(f"{TIMER} is {props.get('ActiveState')}")
    if props.get("RandomizedDelayUSec") in (None, "", "0"):
        warn.append("no random delay: hosts fire at the same second "
                    "(run `sudo kevward schedule install`)")
    if props.get("FixedRandomDelay") == "no":
        warn.append("FixedRandomDelay=no: the delay changes every day")
    if not dropin_exists:
        warn.append(f"no {DROPIN_NAME} drop-in: the timer is not managed by kevward")
    for prop, bad in (("ProtectHome", ("yes", "read-only", "tmpfs", "true")),
                      ("PrivateTmp", ("yes", "true"))):
        if props.get(prop, "").lower() in bad:
            warn.append(f"{SERVICE} has {prop}={props[prop]}: the audit cannot see the real "
                        f"{'/home' if prop == 'ProtectHome' else '/tmp'} (run `sudo kevward "
                        "schedule install` or update kevward)")
    if rw_paths is not None:
        missing = missing_rw_paths(rw_paths)
        if missing:
            warn.append(f"{SERVICE} cannot write {', '.join(missing)}: apt-get update and "
                        "kevward's state fail in timer runs (run `sudo kevward schedule "
                        "install`)")
    return warn


def status(paths: Paths | None = None) -> tuple[dict, list[str]]:
    """Effective timer settings and warnings. Read-only, no root needed."""
    paths = paths or Paths()
    if not have("systemctl"):
        return {}, ["systemctl not found: this host does not run systemd"]
    args = ["systemctl", "show", TIMER] + [a for p in _SHOW_PROPS for a in ("-p", p)]
    r = run(args, timeout=15)
    props = parse_show(r.out) if r.ok else {}
    svc = parse_show(run(["systemctl", "show", SERVICE, "-p", "Result", "-p",
                          "ExecMainStatus", "-p", "ReadWritePaths", "-p", "LoadState",
                          "-p", "ProtectHome", "-p", "PrivateTmp"],
                         timeout=15).out)
    props["ServiceResult"] = svc.get("Result", "")
    props["ExecMainStatus"] = svc.get("ExecMainStatus", "")
    props["ReadWritePaths"] = svc.get("ReadWritePaths", "")
    if svc.get("LoadState") == "loaded":
        props["ProtectHome"] = svc.get("ProtectHome", "")
        props["PrivateTmp"] = svc.get("PrivateTmp", "")
    props["dropin"] = str(paths.dropin) if paths.dropin.exists() else ""
    rw = props["ReadWritePaths"] if svc.get("LoadState") == "loaded" else None
    return props, status_warnings(props, paths.dropin.exists(), rw)
