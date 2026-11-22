# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""`kevward setup`: make a host console-ready in one root command (#191).

Run right after kevward is pip-installed into the /opt/kevward venv. It writes
what used to be pasted by hand — on 2026-11-22 a long authorized_keys line was
mixed up several times and fail2ban ended up blocking the operator:

- ``--read-key`` / ``--operate-key``: ssh-gate lines in the console user's
  authorized_keys (validated key, existing line for the same key or the same
  managed comment replaced, never duplicated; ownership / mode / symlink
  checks; atomic write)
- ``--operate-key`` also writes /etc/sudoers.d/kevward-ssh-gate (checked
  with ``visudo -cf``, 0440)
- ``--ssh-gate``: ``[ssh_gate] enabled = true`` (validated, backed up)
- ``--timer``: the daily report timer, as ``kevward schedule install``
- ``--fail2ban-ignore``: an additive ``ignoreip`` drop-in, if fail2ban exists
- ``--refresh``: post-update steps (none yet; called by ssh-gate self.update)

Running it twice gives the same result. ``--dry-run`` lists the changes and
writes nothing. It never turns on kevward's nft firewall.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import pwd
import re
import stat
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, tomllib
from .ssh_gate import (
    CHANGES_FILE,
    VENV_PREFIX,
    GateError,
    replace_config,
    to_toml,
    validate_candidate,
)
from .util import run

SUDOERS_NAME = "kevward-ssh-gate"
F2B_NAME = "kevward-console.local"
KEY_TYPES = {
    "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
_COMMENT = re.compile(r"^[A-Za-z0-9@._:+/=-]{1,100}$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass
class Env:
    """Where setup writes. Tests point everything into a temp dir."""

    etc: Path = Path("/etc")
    prefix: Path = VENV_PREFIX
    changes_file: Path = CHANGES_FILE
    unit_dir: Path = Path("/etc/systemd/system")
    lookup_user: object = None          # name -> (uid, gid, home); default pwd
    runner: object = None               # util.run-compatible
    now: datetime | None = None
    is_root: object = None

    def user(self, name: str) -> tuple[int, int, Path]:
        if self.lookup_user:
            return self.lookup_user(name)
        pw = pwd.getpwnam(name)
        return pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)


@dataclass
class Plan:
    actions: list[dict] = field(default_factory=list)

    def add(self, kind: str, path: Path | str, action: str, **detail) -> None:
        self.actions.append({"kind": kind, "path": str(path), "action": action, **detail})


# --- keys (pure) ----------------------------------------------------------------

def parse_pubkey(line: str) -> tuple[str, str, str]:
    """'ssh-ed25519 AAAA… comment' -> (type, base64 blob, comment). Validates
    as ``ssh-keygen -l`` would for the parts that matter here."""
    if not isinstance(line, str) or "\n" in line or "\r" in line or '"' in line:
        raise GateError("bad_request", "public key must be one line without quotes")
    parts = line.strip().split()
    if len(parts) != 3:
        raise GateError("bad_request", "public key must be '<type> <base64> <comment>' "
                        "(the comment names the console line; no options)")
    ktype, b64, comment = parts
    if ktype not in KEY_TYPES:
        raise GateError("bad_request", f"unsupported key type: {ktype}")
    try:
        blob = base64.b64decode(b64, validate=True)
        (n,) = struct.unpack(">I", blob[:4])
        inner = blob[4:4 + n].decode("ascii")
    except (binascii.Error, struct.error, UnicodeDecodeError, ValueError):
        raise GateError("bad_request", "public key data is not valid base64 key data") \
            from None
    if inner != ktype or len(blob) < 4 + n + 16:
        raise GateError("bad_request", "public key data does not match its type")
    if not _COMMENT.match(comment):
        raise GateError("bad_request", "key comment must be 1-100 of [A-Za-z0-9@._:+/=-]")
    return ktype, b64, comment


def gate_command(role: str, prefix: Path = VENV_PREFIX) -> str:
    exe = f"{prefix}/bin/kevward ssh-gate --role {role}"
    return exe if role == "read" else f"sudo -n {exe}"


def gate_line(role: str, key: str, prefix: Path = VENV_PREFIX) -> str:
    ktype, b64, comment = parse_pubkey(key)
    return f'command="{gate_command(role, prefix)}",restrict {ktype} {b64} {comment}'


def _blob_and_comment(line: str) -> tuple[str | None, str | None, str]:
    """(base64 blob, comment, forced command) of an authorized_keys line."""
    from .audit import forced_commands

    s = line.strip()
    if not s or s.startswith("#"):
        return None, None, ""
    toks = s.split()
    for i, t in enumerate(toks):
        if t in KEY_TYPES and i + 1 < len(toks):
            cmds = forced_commands(s)
            return toks[i + 1], " ".join(toks[i + 2:]) or None, cmds[0] if cmds else ""
    return None, None, ""


def merge_authorized_keys(text: str, wanted: list[str]) -> str:
    """Put each wanted gate line in; drop any line with the same key, or a
    kevward ssh-gate line with the same comment (a rotated console key).
    Other lines are kept in order. Pure; idempotent."""
    want = []
    for ln in wanted:
        blob, comment, _ = _blob_and_comment(ln)
        want.append((ln, blob, comment))
    blobs = {b for _, b, _ in want}
    comments = {c for _, _, c in want}
    kept: list[str] = []
    for ln in text.splitlines():
        blob, comment, cmd = _blob_and_comment(ln)
        if blob and blob in blobs:
            continue
        if comment in comments and " ssh-gate --role " in cmd and "kevward" in cmd:
            continue
        kept.append(ln)
    return "\n".join(kept + [w for w, _, _ in want]).strip("\n") + "\n"


# --- file safety ------------------------------------------------------------------

def _check_owned(path: Path, uid: int, what: str, must_exist: bool) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if must_exist:
            raise GateError("not_found", f"{what} {path} does not exist") from None
        return False
    if stat.S_ISLNK(st.st_mode):
        raise GateError("forbidden", f"{what} {path} is a symlink; refusing")
    if st.st_uid not in (uid, 0):
        raise GateError("forbidden", f"{what} {path} is not owned by the user or root")
    if st.st_mode & 0o022:
        raise GateError("forbidden", f"{what} {path} is group/world-writable; fix it first")
    return True


def _read_nofollow(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _atomic(path: Path, text: str, mode: int, uid: int | None = None,
            gid: int | None = None) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if uid is not None:
            os.chown(tmp, uid, gid if gid is not None else -1)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- steps ------------------------------------------------------------------------

def step_keys(env: Env, plan: Plan, user: str, read_key: str | None,
              operate_key: str | None, dry_run: bool) -> None:
    wanted = []
    if read_key:
        wanted.append(gate_line("read", read_key, env.prefix))
    if operate_key:
        wanted.append(gate_line("operate", operate_key, env.prefix))
    if not wanted:
        return
    uid, gid, home = env.user(user)
    sshdir, ak = home / ".ssh", home / ".ssh" / "authorized_keys"
    _check_owned(home, uid, "home", must_exist=True)
    have_dir = _check_owned(sshdir, uid, ".ssh", must_exist=False)
    have_file = have_dir and _check_owned(ak, uid, "authorized_keys", must_exist=False)
    old = _read_nofollow(ak) if have_file else ""
    new = merge_authorized_keys(old, wanted)
    if new == old:
        plan.add("authorized_keys", ak, "unchanged")
        return
    plan.add("authorized_keys", ak, "update" if have_file else "create", lines=wanted)
    if dry_run:
        return
    if not have_dir:
        sshdir.mkdir(mode=0o700)
        os.chown(sshdir, uid, gid)
    _atomic(ak, new, 0o600, uid, gid)


def sudoers_text(user: str, prefix: Path = VENV_PREFIX) -> str:
    return ("# Managed by `kevward setup` (#191): the ssh-gate operate role only.\n"
            f"{user} ALL=(root) NOPASSWD: {prefix}/bin/kevward ssh-gate --role operate\n")


def step_sudoers(env: Env, plan: Plan, user: str, dry_run: bool) -> None:
    path = env.etc / "sudoers.d" / SUDOERS_NAME
    text = sudoers_text(user, env.prefix)
    try:
        old = _read_nofollow(path)
    except FileNotFoundError:
        old = None
    if old == text:
        plan.add("sudoers", path, "unchanged")
        return
    plan.add("sudoers", path, "create" if old is None else "update", lines=[text.splitlines()[1]])
    if dry_run:
        return
    runner = env.runner or run
    fd, tmp = tempfile.mkstemp(prefix=".kevward-sudoers.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o440)
        chk = runner(["visudo", "-cf", tmp], timeout=30)
        if chk.rc != 0:
            raise GateError("internal", "visudo rejected the sudoers line: "
                            + (chk.err or chk.out).strip()[:200])
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def step_ssh_gate(env: Env, plan: Plan, dry_run: bool, now: datetime) -> None:
    path = env.etc / "kevward" / "config.toml"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = b""
    try:
        data = tomllib.loads(raw.decode("utf-8")) if raw else {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise GateError("bad_request", f"{path} is not valid TOML; fix it first") from None
    current = Config.from_dict(data)
    if current.warnings:
        raise GateError("bad_request", f"{path} has ignored settings; fix them first: "
                        + "; ".join(current.warnings))
    if current.ssh_gate.enabled:
        plan.add("config", path, "unchanged", key="ssh_gate.enabled")
        return
    data.setdefault("ssh_gate", {})["enabled"] = True
    text = to_toml(data)
    plan.add("config", path, "update" if raw else "create", key="ssh_gate.enabled",
             value=True)
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_candidate(path, text)
    backup = replace_config(path, raw, text, now)
    plan.actions[-1]["backup"] = str(backup) if backup else None


def step_timer(env: Env, plan: Plan, dry_run: bool) -> None:
    from . import schedule as sch

    paths = sch.Paths(unit_dir=env.unit_dir)
    exe = str(env.prefix / "bin" / "kevward")
    for path, _text, new in sch.plan_install(paths, sch.DEFAULT_AT, sch.DEFAULT_JITTER, exe):
        plan.add("timer", path, "create" if new else "update")
    if dry_run:
        return
    ok, msgs = sch.install(paths=paths, exe=exe)
    if not ok:
        raise GateError("internal", "timer: " + "; ".join(msgs)[:300])


def fail2ban_text(nets: list[str]) -> str:
    return ("# Managed by `kevward setup` (#191): never ban the console's address.\n"
            "# %(known/ignoreip)s keeps every ignoreip set before this file.\n"
            "[DEFAULT]\n"
            f"ignoreip = %(known/ignoreip)s {' '.join(nets)}\n")


def step_fail2ban(env: Env, plan: Plan, nets: list[str], dry_run: bool) -> None:
    clean = []
    for n in nets:
        try:
            clean.append(str(ipaddress.ip_network(n, strict=False)))
        except ValueError:
            raise GateError("bad_request", f"not an IP address or CIDR: {n!r}") from None
    jd = env.etc / "fail2ban" / "jail.d"
    if not jd.is_dir():
        plan.add("fail2ban", jd, "skipped", reason="fail2ban is not installed")
        return
    path = jd / F2B_NAME
    text = fail2ban_text(clean)
    try:
        old = _read_nofollow(path)
    except FileNotFoundError:
        old = None
    if old == text:
        plan.add("fail2ban", path, "unchanged")
        return
    plan.add("fail2ban", path, "create" if old is None else "update", ignoreip=clean)
    if dry_run:
        return
    _atomic(path, text, 0o644)
    r = (env.runner or run)(["fail2ban-client", "reload"], timeout=60)
    if r.rc != 0:
        raise GateError("internal", "fail2ban-client reload failed: "
                        + (r.err or r.out).strip()[:200])


# --- entry point ------------------------------------------------------------------

def setup(*, console_user: str | None = None, read_key: str | None = None,
          operate_key: str | None = None, ssh_gate: bool = False, timer: bool = False,
          fail2ban_ignore: list[str] | None = None, refresh: bool = False,
          dry_run: bool = False, env: Env | None = None) -> dict:
    """Run the requested steps; returns the plan (what changed / would change).
    Raises GateError with an ssh-gate code."""
    env = env or Env()
    now = env.now or datetime.now(timezone.utc)
    is_root = env.is_root or (lambda: os.geteuid() == 0)
    if (read_key or operate_key) and not console_user:
        raise GateError("bad_request", "--console-user is required with --read-key / "
                        "--operate-key")
    if console_user and not _USER.match(console_user):
        raise GateError("bad_request", f"invalid user name: {console_user!r}")
    if not (read_key or operate_key or ssh_gate or timer or fail2ban_ignore or refresh):
        raise GateError("bad_request", "nothing to do: give --read-key, --operate-key, "
                        "--ssh-gate, --timer, --fail2ban-ignore or --refresh")
    if not dry_run and not is_root():
        raise GateError("forbidden", "kevward setup must run as root (sudo)")
    if (read_key or operate_key) and not (env.prefix / "bin" / "kevward").exists():
        raise GateError("not_found", f"kevward is not installed in {env.prefix} "
                        "(the ssh-gate lines point there)")
    if console_user:
        try:
            env.user(console_user)
        except KeyError:
            raise GateError("not_found", f"no such user: {console_user}") from None
    # Validate every key before writing anything.
    for k in (read_key, operate_key):
        if k:
            parse_pubkey(k)
    plan = Plan()
    step_keys(env, plan, console_user or "", read_key, operate_key, dry_run)
    if operate_key:
        step_sudoers(env, plan, console_user, dry_run)
    if ssh_gate:
        step_ssh_gate(env, plan, dry_run, now)
    if timer:
        step_timer(env, plan, dry_run)
    if fail2ban_ignore:
        step_fail2ban(env, plan, fail2ban_ignore, dry_run)
    # refresh: no post-update steps exist yet (#190 calls it once there are).
    changed = [a for a in plan.actions if a["action"] in ("create", "update")]
    if changed and not dry_run:
        _record(env, now, changed)
    return {"dry_run": dry_run, "changed": bool(changed), "actions": plan.actions}


def _record(env: Env, now: datetime, changed: list[dict]) -> None:
    rec = {"time": now.isoformat(timespec="seconds"), "kind": "setup",
           "client": "local", "actions": changed}
    try:
        env.changes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(env.changes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass
    try:
        import syslog

        syslog.openlog("kevward-setup", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, "setup: " + ", ".join(
            f"{a['action']} {a['kind']} {a['path']}" for a in changed))
    except Exception:
        pass
