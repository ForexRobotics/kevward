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
- ``--refresh``: post-update steps, run by ssh-gate self.update with the new
  version (#235): bring kevward's managed unit drop-ins up to date.
- ``--restore``: re-apply what ``kevward uninstall`` saved in
  /var/lib/kevward/setup-snapshot.json (keys, timer, fail2ban), so removing
  and reinstalling kevward needs no hand work (#236).

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
    exe = f"{prefix}/bin/kevward"
    return ("# Managed by `kevward setup` (#191): the ssh-gate operate role only.\n"
            "# SSH_CONNECTION is kept so the change log records the console's\n"
            "# address (#214); sshd sets it and the forced command cannot change it.\n"
            f'Defaults!{exe} env_keep += "SSH_CONNECTION"\n'
            f"{user} ALL=(root) NOPASSWD: {exe} ssh-gate --role operate\n")


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


#: Settings setup may turn on in config.toml, by flag (#191).
CONFIG_FLAGS = {
    "ssh_gate": ("ssh_gate", "enabled"),
    "self_update": ("ssh_gate", "self_update"),
    "allow_reboot": ("policy", "allow_reboot"),
}


def step_config(env: Env, plan: Plan, settings: list[tuple[str, str]], dry_run: bool,
                now: datetime) -> None:
    """Set each ``(table, key)`` to true in config.toml, in one validated write."""
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
    todo = []
    for table, key in settings:
        if getattr(getattr(current, table), key) is True:
            plan.add("config", path, "unchanged", key=f"{table}.{key}")
        else:
            todo.append((table, key))
    if not todo:
        return
    for table, key in todo:
        data.setdefault(table, {})[key] = True
        plan.add("config", path, "update" if raw else "create", key=f"{table}.{key}",
                 value=True)
    if dry_run:
        return
    text = to_toml(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_candidate(path, text)
    backup = replace_config(path, raw, text, now)
    plan.actions[-1]["backup"] = str(backup) if backup else None


def step_timer(env: Env, plan: Plan, dry_run: bool, at: str | None = None,
               jitter: str | None = None) -> None:
    from . import schedule as sch

    paths = sch.Paths(unit_dir=env.unit_dir)
    exe = str(env.prefix / "bin" / "kevward")
    rec_at, rec_jitter = sch.recorded(paths)
    at, jitter = at or rec_at, jitter or rec_jitter
    for path, _text, new in sch.plan_install(paths, at, jitter, exe):
        plan.add("timer", path, "create" if new else "update")
    if dry_run:
        return
    ok, msgs = sch.install(at, jitter, paths=paths, exe=exe)
    if not ok:
        raise GateError("internal", "timer: " + "; ".join(msgs)[:300])


#: fail2ban's own default when nothing sets ignoreip.
F2B_BASE = ["127.0.0.1/8", "::1"]


def _f2b_files(f2b: Path) -> list[Path]:
    """The files fail2ban reads before ours, in its order: jail.conf,
    jail.d/*.conf, jail.local, jail.d/*.local (those after ours win anyway)."""
    jd = f2b / "jail.d"
    out = [f2b / "jail.conf", *sorted(jd.glob("*.conf")), f2b / "jail.local"]
    out += [p for p in sorted(jd.glob("*.local")) if p.name < F2B_NAME]
    return [p for p in out if p.is_file()]


def existing_ignoreip(f2b: Path) -> list[str]:
    """The ``[DEFAULT] ignoreip`` in effect before setup's file. Interpolations
    (``%(...)s``) are dropped: they are what broke fail2ban (the
    www2 setup of 2026-11-22)."""
    import configparser

    value = None
    for path in _f2b_files(f2b):
        cp = configparser.RawConfigParser(strict=False, interpolation=None,
                                          inline_comment_prefixes=("#", ";"))
        try:
            cp.read_string(path.read_text(encoding="utf-8", errors="replace"))
        except (configparser.Error, OSError):
            continue
        if cp.defaults().get("ignoreip") is not None:
            value = cp.defaults()["ignoreip"]
    tokens = re.split(r"[\s,]+", value or "")
    return [t for t in tokens if t and "%(" not in t]


def merge_ignoreip(existing: list[str], nets: list[str]) -> list[str]:
    out: list[str] = []
    for t in [*F2B_BASE, *existing, *nets]:
        if t not in out:
            out.append(t)
    return out


def fail2ban_text(ips: list[str]) -> str:
    return ("# Managed by `kevward setup` (#191): never ban the console's address.\n"
            "# fail2ban cannot use %(known/ignoreip)s in [DEFAULT], so the ignoreip\n"
            "# in effect before this file is copied in. After changing ignoreip\n"
            "# elsewhere, run `kevward setup --fail2ban-ignore <ip>` again.\n"
            "[DEFAULT]\n"
            f"ignoreip = {' '.join(ips)}\n")


def step_fail2ban(env: Env, plan: Plan, nets: list[str], dry_run: bool) -> None:
    clean = []
    for n in nets:
        try:
            clean.append(str(ipaddress.ip_network(n, strict=False)))
        except ValueError:
            raise GateError("bad_request", f"not an IP address or CIDR: {n!r}") from None
    f2b = env.etc / "fail2ban"
    jd = f2b / "jail.d"
    if not jd.is_dir():
        plan.add("fail2ban", jd, "skipped", reason="fail2ban is not installed")
        return
    path = jd / F2B_NAME
    ips = merge_ignoreip(existing_ignoreip(f2b), clean)
    text = fail2ban_text(ips)
    try:
        old = _read_nofollow(path)
    except FileNotFoundError:
        old = None
    if old == text:
        plan.add("fail2ban", path, "unchanged")
        return
    plan.add("fail2ban", path, "create" if old is None else "update", ignoreip=ips)
    if dry_run:
        return
    runner = env.runner or run
    _atomic(path, text, 0o644)
    # Never leave a file behind that stops fail2ban at its next start.
    t = runner(["fail2ban-client", "-t"], timeout=60)
    if t.rc != 0:
        if old is None:
            path.unlink(missing_ok=True)
        else:
            _atomic(path, old, 0o644)
        plan.actions.pop()
        raise GateError("internal", "fail2ban-client -t rejected the new ignoreip, so "
                        f"{path} was {'removed' if old is None else 'restored'}: "
                        + (t.err or t.out).strip()[-200:])
    r = runner(["fail2ban-client", "reload"], timeout=60)
    if r.rc != 0:
        raise GateError("internal", "fail2ban-client reload failed (the file passed "
                        "fail2ban-client -t): " + (r.err or r.out).strip()[:200])


# --- entry point ------------------------------------------------------------------

# --- refresh (#235) and snapshot / restore (#236) ---------------------------------

SNAPSHOT = Path("/var/lib/kevward/setup-snapshot.json")
_ROLE = re.compile(r"ssh-gate --role (read|operate)")


def step_refresh(env: Env, plan: Plan, dry_run: bool) -> None:
    from . import schedule as sch

    paths = sch.Paths(unit_dir=env.unit_dir)
    ok_, msgs = sch.refresh(dry_run=dry_run, paths=paths)
    if not ok_:
        raise GateError("internal", "refresh: " + "; ".join(msgs)[:300])
    changed = any(m.startswith(("created", "updated", "would")) for m in msgs)
    plan.add("refresh", paths.service_dropin, "update" if changed else "unchanged",
             messages=msgs)


def _key_part(line: str) -> str | None:
    """``type base64 [comment]`` of an authorized_keys line, options dropped."""
    toks = line.strip().split()
    for i, t in enumerate(toks):
        if t in KEY_TYPES and i + 1 < len(toks):
            return " ".join(toks[i:])
    return None


def snapshot_host(etc: Path, homes: list[tuple[str, Path]], state_file: Path) -> dict:
    """What setup put on this host, in setup's own terms, so ``setup
    --restore`` can put it back after an uninstall (#236). Pure apart from
    reading files; holds public keys and addresses only."""
    users = []
    for name, home in homes:
        try:
            text = (home / ".ssh" / "authorized_keys").read_text(errors="replace")
        except OSError:
            continue
        keys: dict[str, str] = {}
        for ln in text.splitlines():
            m = _ROLE.search(ln)
            if m and "kevward" in ln and m.group(1) not in keys:
                k = _key_part(ln)
                if k:
                    keys[m.group(1)] = k
        if keys:
            users.append({"user": name, "read_key": keys.get("read"),
                          "operate_key": keys.get("operate")})
    timer = None
    try:
        st = json.loads(state_file.read_text())
        if st.get("at"):
            timer = {"at": st["at"], "jitter": st.get("jitter")}
    except (OSError, ValueError, AttributeError):
        pass
    f2b: list[str] = []
    try:
        for ln in (etc / "fail2ban" / "jail.d" / F2B_NAME).read_text().splitlines():
            if ln.strip().startswith("ignoreip"):
                f2b = [t for t in re.split(r"[\s,]+", ln.split("=", 1)[1])
                       if t and t not in F2B_BASE and "%(" not in t]
    except (OSError, IndexError):
        pass
    return {"version": 1, "users": users, "timer": timer, "fail2ban_ignore": f2b}


def restore(*, dry_run: bool = False, env: Env | None = None,
            path: Path = SNAPSHOT) -> dict:
    """``setup --restore``: run setup with what the snapshot recorded."""
    try:
        snap = json.loads(path.read_text())
    except FileNotFoundError:
        raise GateError("not_found", f"no snapshot at {path} (kevward uninstall writes one; "
                        "--purge does not keep it)") from None
    except (OSError, ValueError) as e:
        raise GateError("internal", f"unreadable snapshot {path}: {e}") from None
    users = snap.get("users") or []
    timer = snap.get("timer")
    f2b = snap.get("fail2ban_ignore") or []
    if not (users or timer or f2b):
        raise GateError("not_found", f"{path} records nothing to restore")
    actions: list[dict] = []
    first = True
    for u in users or [{}]:
        d = setup(console_user=u.get("user"), read_key=u.get("read_key"),
                  operate_key=u.get("operate_key"),
                  ssh_gate=bool(u.get("read_key") or u.get("operate_key")),
                  timer=bool(timer) and first,
                  timer_at=(timer or {}).get("at"), timer_jitter=(timer or {}).get("jitter"),
                  fail2ban_ignore=f2b if (first and f2b) else None,
                  dry_run=dry_run, env=env)
        actions += d["actions"]
        first = False
    return {"dry_run": dry_run, "restored_from": str(path),
            "changed": any(a["action"] in ("create", "update") for a in actions),
            "actions": actions}


def setup(*, console_user: str | None = None, read_key: str | None = None,
          operate_key: str | None = None, ssh_gate: bool = False, timer: bool = False,
          fail2ban_ignore: list[str] | None = None, refresh: bool = False,
          self_update: bool = False, allow_reboot: bool = False,
          timer_at: str | None = None, timer_jitter: str | None = None,
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
    if not (read_key or operate_key or ssh_gate or timer or fail2ban_ignore or refresh
            or self_update or allow_reboot):
        raise GateError("bad_request", "nothing to do: give --read-key, --operate-key, "
                        "--ssh-gate, --self-update, --allow-reboot, --timer, "
                        "--fail2ban-ignore or --refresh")
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
    settings = [CONFIG_FLAGS[n] for n, on in (("ssh_gate", ssh_gate),
                                              ("self_update", self_update),
                                              ("allow_reboot", allow_reboot)) if on]
    # The authorized_keys lines go last: when an earlier step fails, the
    # console's keys still work the old way and nothing points at a gate
    # that is not ready.
    try:
        if settings:
            step_config(env, plan, settings, dry_run, now)
        if fail2ban_ignore:
            step_fail2ban(env, plan, fail2ban_ignore, dry_run)
        if timer:
            step_timer(env, plan, dry_run, timer_at, timer_jitter)
        if operate_key:
            step_sudoers(env, plan, console_user, dry_run)
        step_keys(env, plan, console_user or "", read_key, operate_key, dry_run)
        if refresh:
            step_refresh(env, plan, dry_run)
    except GateError as e:
        changed = [a for a in plan.actions if a["action"] in ("create", "update")]
        if changed and not dry_run:
            _record(env, now, changed)
            done = ", ".join(f"{a['action']} {a['kind']} {a['path']}" for a in changed)
            raise GateError(e.code, f"{e.message} (already applied before this step: "
                            f"{done})") from None
        raise
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
