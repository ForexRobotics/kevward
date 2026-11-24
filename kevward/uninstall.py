# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""`kevward uninstall`: remove kevward from this host cleanly (#192).

Only kevward knows what it installed, so the cleanup lives here; a console
just calls it from an administrator login (not through ssh-gate: this removes
the gate and its own program while running).

Removed: the report / firewall / harden systemd units, the ssh-gate sudoers
file, ssh-gate lines in authorized_keys (``cat …report.html`` collector lines
only with ``remove_collector_keys``), setup's fail2ban drop-in, kevward's
nft tables and their boot persistence, the harden sysctl drop-in, the
launcher and finally /opt/kevward. Config, reports and state stay unless
``purge``.

Firewall rules (the important part):
- kevward's tables only ever *drop* (policy accept, plus accept sets that
  only short-cut kevward's own chain), so deleting them can never narrow
  what is allowed and cannot lock out SSH. That is checked, not assumed:
  if a live kevward table holds anything else (a hand-added rule, a
  ``policy drop``, a jump), nothing is changed and ``conflict`` is returned
  with the manual steps.
- Persistence is removed *before* the tables, and the run refuses if another
  boot file (e.g. /etc/nftables.conf) mentions a kevward table, so no rule
  can come back after a reboot (the 2026-11-08 class of accident).

Without ``yes`` it is a dry run.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import syslog  # noqa: F401  (imported before /opt/kevward may be deleted)
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .ssh_gate import CHANGES_FILE, VENV_PREFIX, GateError
from .util import run

UNITS = ("kevward-report.timer", "kevward-report.service", "kevward-firewall.service",
         "kevward-harden.service")
NFT_TABLES = ("kevward", "kevward_harden")
_OWN_GATE = re.compile(r'command="(?:sudo -n )?/[\w./-]*/kevward ssh-gate --role '
                       r'(?:read|operate)"')
_COLLECTOR = re.compile(r'command="cat /var/log/kevward/report\.html"')

# Lines a kevward table may contain (nft list output), anything else -> conflict.
_ELEM = r"[0-9a-fA-F.:/]+(?: timeout [0-9a-z]+)?(?: expires [0-9a-z]+)?"
_SAFE_NFT = [
    re.compile(r"^table inet kevward(_harden)? \{$"),
    re.compile(r"^set \w+ \{$"),
    re.compile(r"^type ipv[46]_addr$"),
    re.compile(r"^flags [a-z, ]+$"),
    re.compile(r"^auto-merge$"),
    # Set elements: address/prefix, optionally "timeout X" / "expires Y" each;
    # nft prints several per line (#234). The first line starts "elements = {".
    re.compile(rf"^(?:elements = \{{\s*)?(?:{_ELEM}[,\s}}]*)+$"),
    re.compile(r"^chain \w+ \{$"),
    re.compile(r"^type filter hook (input|prerouting) priority [-\w +]+; policy accept;$"),
    re.compile(r"^size \d+$"),
    re.compile(r"^ip6? saddr @\w+ (counter packets \d+ bytes \d+ )?(accept|drop)$"),
    re.compile(r"^ip hdrlength != 5 (counter packets \d+ bytes \d+ )?drop$"),
    re.compile(r"^\}$"),
]


@dataclass
class Env:
    etc: Path = Path("/etc")
    prefix: Path = VENV_PREFIX
    launcher: Path = Path("/usr/local/bin/kevward")
    data_dirs: tuple = (Path("/var/log/kevward"), Path("/var/lib/kevward"),
                        Path("/var/cache/kevward"))
    changes_file: Path = CHANGES_FILE
    homes: object = None                 # () -> list[Path]; default: all passwd homes
    runner: object = None
    now: datetime | None = None
    is_root: object = None

    def home_dirs(self) -> list[Path]:
        if self.homes:
            return list(self.homes())
        seen: list[Path] = []
        for pw in pwd.getpwall():
            h = Path(pw.pw_dir)
            if h not in seen and (h / ".ssh" / "authorized_keys").is_file():
                seen.append(h)
        return seen


@dataclass
class Plan:
    actions: list[dict] = field(default_factory=list)

    def add(self, kind: str, target, **detail) -> None:
        self.actions.append({"kind": kind, "target": str(target), **detail})


def nft_table_safe(listing: str) -> list[str]:
    """Lines of an ``nft list table`` dump that are not kevward's own shapes.
    Empty = safe to delete (it can only drop, never narrow). Pure."""
    bad = []
    for raw in listing.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if not any(p.match(s) for p in _SAFE_NFT):
            bad.append(s)
    return bad


def strip_gate_lines(text: str, collector: bool) -> tuple[str, int]:
    """authorized_keys without kevward's ssh-gate lines (and collector lines
    if asked). Returns (new text, removed count). Pure."""
    kept, removed = [], 0
    for ln in text.splitlines():
        if _OWN_GATE.search(ln) or (collector and _COLLECTOR.search(ln)):
            removed += 1
            continue
        kept.append(ln)
    return ("\n".join(kept) + "\n" if kept else ""), removed


def _atomic(path: Path, text: str) -> None:
    st = os.lstat(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _launcher_is_ours(path: Path, prefix: Path) -> bool:
    try:
        if path.is_symlink():
            return str(prefix) in os.readlink(path)
        return str(prefix) in path.read_text(errors="replace")[:4096]
    except OSError:
        return False


def plan_uninstall(env: Env, *, purge: bool, remove_collector_keys: bool) -> Plan:
    """Everything that would be removed, after the firewall safety checks.
    Raises GateError(conflict) when the firewall state cannot be judged."""
    r = env.runner or run
    plan = Plan()
    # --- firewall: check first, so a conflict changes nothing at all -------
    nft_ok = r(["nft", "--version"], timeout=10).rc == 0
    for table in NFT_TABLES:
        if not nft_ok:
            break
        lst = r(["nft", "list", "table", "inet", table], timeout=15)
        if lst.rc != 0:
            continue
        bad = nft_table_safe(lst.out)
        if bad:
            raise GateError("conflict", (
                f"table inet {table} contains rules kevward did not write "
                f"({bad[0][:80]!r}); nothing was changed. Review it, then remove by "
                f"hand: `nft list table inet {table}`, `nft delete table inet {table}`, "
                "and run `kevward uninstall` again."))
        plan.add("nft_table", f"inet {table}")
    for boot in (env.etc / "nftables.conf",):
        try:
            text = boot.read_text(errors="replace")
        except OSError:
            continue
        if re.search(r"\bkevward\b", text):
            raise GateError("conflict", (
                f"{boot} mentions kevward; a kevward table there would come back on "
                "the next boot. Remove those lines by hand first; nothing was changed."))
    # --- units and their files -----------------------------------------------
    unit_dir = env.etc / "systemd" / "system"
    for u in UNITS:
        if (unit_dir / u).exists() or (unit_dir / f"{u}.d").exists():
            plan.add("unit", u)
    for f in (env.etc / "kevward" / "firewall.nft", env.etc / "kevward" / "harden.nft",
              env.etc / "sysctl.d" / "99-kevward-mptcp.conf",
              env.etc / "sudoers.d" / "kevward-ssh-gate",
              env.etc / "fail2ban" / "jail.d" / "kevward-console.local"):
        if f.exists():
            plan.add("file", f)
    # --- authorized_keys -------------------------------------------------------
    for home in env.home_dirs():
        ak = home / ".ssh" / "authorized_keys"
        try:
            if ak.is_symlink() or not ak.is_file():
                continue
            text = ak.read_text(errors="replace")
        except OSError:
            continue
        _, n = strip_gate_lines(text, remove_collector_keys)
        if n:
            plan.add("authorized_keys", ak, lines=n)
    # --- program and data -------------------------------------------------------
    if purge:
        for d in [env.etc / "kevward", *env.data_dirs]:
            if d.exists():
                plan.add("purge", d)
    if env.launcher.exists() and _launcher_is_ours(env.launcher, env.prefix):
        plan.add("launcher", env.launcher)
    if env.prefix.exists():
        plan.add("program", env.prefix)
    return plan


def execute(env: Env, plan: Plan, *, remove_collector_keys: bool) -> list[str]:
    """Carry out a plan; persistence first, tables after, program last."""
    r = env.runner or run
    errors: list[str] = []
    units = [a["target"] for a in plan.actions if a["kind"] == "unit"]
    for u in units:
        r(["systemctl", "disable", "--now", u], timeout=30)
    unit_dir = env.etc / "systemd" / "system"
    for u in units:
        for p in (unit_dir / u, unit_dir / f"{u}.d"):
            try:
                shutil.rmtree(p) if p.is_dir() else p.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                errors.append(f"{p}: {e.strerror}")
    for a in plan.actions:
        if a["kind"] == "file":
            try:
                Path(a["target"]).unlink()
            except OSError as e:
                errors.append(f"{a['target']}: {e.strerror}")
    if units:
        r(["systemctl", "daemon-reload"], timeout=30)
    if any(a["target"].endswith("99-kevward-mptcp.conf") for a in plan.actions):
        r(["sysctl", "--system"], timeout=30)
    if any(a["target"].endswith("kevward-console.local") for a in plan.actions):
        r(["fail2ban-client", "reload"], timeout=60)
    # Tables only after nothing can bring them back.
    for a in plan.actions:
        if a["kind"] == "nft_table":
            d = r(["nft", "delete", "table", *a["target"].split()], timeout=15)
            if d.rc != 0:
                errors.append(f"nft delete table {a['target']}: {(d.err or '').strip()}")
    for a in plan.actions:
        if a["kind"] == "authorized_keys":
            p = Path(a["target"])
            try:
                new, _ = strip_gate_lines(p.read_text(errors="replace"),
                                          remove_collector_keys)
                _atomic(p, new)
            except OSError as e:
                errors.append(f"{p}: {e.strerror}")
    for a in plan.actions:
        if a["kind"] == "purge":
            shutil.rmtree(a["target"], ignore_errors=True)
    for a in plan.actions:
        if a["kind"] == "launcher":
            try:
                Path(a["target"]).unlink()
            except OSError as e:
                errors.append(f"{a['target']}: {e.strerror}")
    for a in plan.actions:          # last: this is the running program
        if a["kind"] == "program":
            shutil.rmtree(a["target"], ignore_errors=True)
    return errors


def _user_of(home: Path) -> str:
    for pw in pwd.getpwall():
        if Path(pw.pw_dir) == home:
            return pw.pw_name
    return home.name


def _write_snapshot(env: Env, path: Path) -> None:
    from .setup import snapshot_host

    try:
        snap = snapshot_host(env.etc, [(_user_of(h), h) for h in env.home_dirs()],
                             env.data_dirs[1] / "schedule.json")
        snap["time"] = (env.now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(snap, indent=1) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass  # the uninstall itself must not fail over this


def uninstall(*, yes: bool = False, purge: bool = False,
              remove_collector_keys: bool = False, env: Env | None = None) -> dict:
    env = env or Env()
    now = env.now or datetime.now(timezone.utc)
    is_root = env.is_root or (lambda: os.geteuid() == 0)
    if yes and not is_root():
        raise GateError("forbidden", "kevward uninstall must run as root (sudo)")
    plan = plan_uninstall(env, purge=purge, remove_collector_keys=remove_collector_keys)
    snap_path = env.data_dirs[1] / "setup-snapshot.json"
    if not purge:
        # Saved first, so `kevward setup --restore` can put the keys, timer and
        # fail2ban exemption back after a reinstall (#236). --purge keeps nothing.
        plan.actions.insert(0, {"kind": "snapshot", "target": str(snap_path)})
    if not yes:
        return {"dry_run": True, "purge": purge, "actions": plan.actions}
    if not purge:
        _write_snapshot(env, snap_path)
    summary = ", ".join(f"{a['kind']} {a['target']}" for a in plan.actions) or "nothing"
    if not purge:
        try:
            env.changes_file.parent.mkdir(parents=True, exist_ok=True)
            with open(env.changes_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"time": now.isoformat(timespec="seconds"),
                                     "kind": "uninstall", "client": "local",
                                     "actions": plan.actions}) + "\n")
        except OSError:
            pass
    try:
        syslog.openlog("kevward-uninstall", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, f"uninstall (purge={purge}): {summary}")
    except Exception:
        pass
    errors = execute(env, plan, remove_collector_keys=remove_collector_keys)
    return {"dry_run": False, "purge": purge, "actions": plan.actions, "errors": errors}
