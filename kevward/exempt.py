# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""``client.exempt``: one fail2ban exemption slot per console key (#291).

A console that works from an office line whose address changes calls this
op from the new address. kevward puts **the caller's own address** (from the
SSH connection, never an argument) into the slot of the calling key and drops
the address that was there, so old addresses do not pile up in ``ignoreip``
and get handed to someone else by the ISP.

- Slots live in /var/lib/kevward/exempt-slots.json, ``{key name: {address, since}}``.
- They are written to their own file, jail.d/zz-kevward-console-slot.local, as
  ``[sshd] ignoreip = %(known/ignoreip)s <slot addresses>``: what was in
  effect stays, and exemptions added by hand (``setup --fail2ban-ignore``,
  jail.local) are never touched.
- The file is checked with ``fail2ban-client -t``, fail2ban is reloaded, and
  the sshd jail's ignoreip must then hold everything it held before plus the
  new address; otherwise the previous file and slots are put back.
- Only keys with a name (``--key-name``, 0.21+) have a slot.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path

from .ssh_gate import GateError

SLOTS_FILE = Path("/var/lib/kevward/exempt-slots.json")
SLOT_CONF_NAME = "zz-kevward-console-slot.local"
F2B_DIR = Path("/etc/fail2ban")


def _addr(client: str) -> str:
    try:
        return str(ipaddress.ip_address((client or "").strip()))
    except ValueError:
        raise GateError("precondition_failed", "the caller's address is not known "
                        "(no SSH_CONNECTION); nothing to exempt") from None


def _key(key: str | None) -> str:
    if not key:
        raise GateError("precondition_failed", "this console key has no name, so it has "
                        "no exemption slot; register the console's keys again "
                        "(kevward setup, 0.21 or later)")
    return key


def read_slots(path: Path = SLOTS_FILE) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and isinstance(v.get("address"), str)}


def slot_of(key: str | None, path: Path = SLOTS_FILE) -> str | None:
    """The address in ``key``'s slot, or None (for ``client.exempt_slot``)."""
    if not key:
        return None
    return (read_slots(path).get(key) or {}).get("address")


def render(slots: dict) -> str | None:
    """The jail.d file for these slots, or None when there are none. Pure."""
    addrs = []
    for k in sorted(slots):
        a = slots[k]["address"]
        if a not in addrs:
            addrs.append(a)
    if not addrs:
        return None
    lines = [f"#   {k}: {slots[k]['address']} (since {slots[k].get('since', '?')})"
             for k in sorted(slots)]
    return ("# Managed by kevward (ssh-gate client.exempt, #291): one exemption per\n"
            "# console key, replaced when the key is used from a new address.\n"
            "# Do not edit; exemptions of your own go elsewhere and are kept.\n"
            + "\n".join(lines) + "\n"
            "[sshd]\n"
            f"ignoreip = %(known/ignoreip)s {' '.join(addrs)}\n")


def sshd_ignoreip(runner) -> list[str] | None:
    """What fail2ban's sshd jail ignores now (``fail2ban-client get sshd
    ignoreip``), or None when it cannot be read."""
    r = runner(["fail2ban-client", "get", "sshd", "ignoreip"], timeout=30)
    if r.rc != 0:
        return None
    out = []
    for ln in (r.out or "").splitlines():
        ln = re.sub(r"^[\s|`\-]+", "", ln).strip()
        if not ln or ln.lower().startswith(("these ip", "no ip")):
            continue
        out += [t for t in re.split(r"[\s,]+", ln) if t]
    return out


def _covered(addr: str, tokens: list[str]) -> bool:
    ip = ipaddress.ip_address(addr)
    for t in tokens:
        try:
            n = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if n.version == ip.version and ip in n:
            return True
    return False


def _write(path: Path, text: str | None) -> None:
    from .setup import _atomic

    if text is None:
        path.unlink(missing_ok=True)
    else:
        _atomic(path, text, 0o644)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _change(new_slots: dict, *, f2b_dir: Path, slots_file: Path, runner,
            must_include: str | None) -> bool:
    """Write slots and the jail.d file, check and reload fail2ban; put the
    previous state back on any failure. Returns fail2ban_ignored for
    ``must_include`` (True when it is None)."""
    jd = f2b_dir / "jail.d"
    if not jd.is_dir():
        raise GateError("precondition_failed", "fail2ban is not installed on this host")
    conf = jd / SLOT_CONF_NAME
    before = sshd_ignoreip(runner)
    if before is None:
        raise GateError("precondition_failed", "fail2ban's sshd jail is not running "
                        "(fail2ban-client get sshd ignoreip failed)")
    old_conf, old_slots = _read(conf), _read(slots_file)

    def restore(why: str):
        _write(conf, old_conf)
        if old_slots is None:
            slots_file.unlink(missing_ok=True)
        else:
            _write_slots_text(slots_file, old_slots)
        runner(["fail2ban-client", "reload"], timeout=60)
        raise GateError("internal", f"{why}; the previous exemptions were put back")

    _write(conf, render(new_slots))
    t = runner(["fail2ban-client", "-t"], timeout=60)
    if t.rc != 0:
        restore("fail2ban-client -t rejected the exemption file: "
                + (t.err or t.out).strip()[-200:])
    _write_slots_text(slots_file, json.dumps(new_slots, indent=1, sort_keys=True) + "\n")
    r = runner(["fail2ban-client", "reload"], timeout=60)
    if r.rc != 0:
        restore("fail2ban-client reload failed: " + (r.err or r.out).strip()[:200])
    after = sshd_ignoreip(runner)
    if after is None:
        restore("fail2ban's sshd jail did not come back after the reload")
    gone = [t for t in before if t not in after
            and t not in {s["address"] for s in read_slots_from_text(old_slots).values()}]
    if gone:
        restore("the reload dropped exemptions that were in effect: " + ", ".join(gone[:5]))
    return True if must_include is None else _covered(must_include, after)


def read_slots_from_text(text: str | None) -> dict:
    try:
        d = json.loads(text or "{}")
        return {k: v for k, v in d.items() if isinstance(v, dict) and "address" in v}
    except (ValueError, AttributeError):
        return {}


def _write_slots_text(path: Path, text: str) -> None:
    from .setup import _atomic

    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic(path, text, 0o644)


class _Lock:
    def __init__(self, path: Path):
        self.path = path.with_name(path.name + ".lock")

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            raise GateError("conflict", "another client.exempt is running") from None
        return self

    def __exit__(self, *a):
        self.fh.close()


def op_exempt(*, client: str, key: str | None, now: datetime, changes_file: Path,
              runner=None, f2b_dir: Path = F2B_DIR, slots_file: Path = SLOTS_FILE) -> dict:
    """Put the caller's address into its key's slot (operate)."""
    from .gate_ops import _record
    from .util import run

    addr, name = _addr(client), _key(key)
    runner = runner or run
    with _Lock(slots_file):
        slots = read_slots(slots_file)
        prev = (slots.get(name) or {}).get("address")
        if prev == addr:
            current = sshd_ignoreip(runner)
            if current is not None and _covered(addr, current):
                return {"address": addr, "replaced": None, "key": name,
                        "fail2ban_ignored": True}
            prev = None   # in the slot but not in effect (file removed?): write it again
        new = dict(slots)
        new[name] = {"address": addr, "since": now.isoformat(timespec="seconds")}
        ignored = _change(new, f2b_dir=f2b_dir, slots_file=slots_file, runner=runner,
                          must_include=addr)
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "client.exempt", "address": addr, "replaced": prev})
    return {"address": addr, "replaced": prev, "key": name, "fail2ban_ignored": ignored}


def op_exempt_clear(*, client: str, key: str | None, now: datetime, changes_file: Path,
                    runner=None, f2b_dir: Path = F2B_DIR,
                    slots_file: Path = SLOTS_FILE) -> dict:
    """Empty the calling key's slot (operate)."""
    from .gate_ops import _record
    from .util import run

    name = _key(key)
    runner = runner or run
    with _Lock(slots_file):
        slots = read_slots(slots_file)
        prev = (slots.get(name) or {}).get("address")
        if prev is None:
            return {"cleared": None, "key": name}
        new = {k: v for k, v in slots.items() if k != name}
        _change(new, f2b_dir=f2b_dir, slots_file=slots_file, runner=runner,
                must_include=None)
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "client.exempt_clear", "replaced": prev})
    return {"cleared": prev, "key": name}


def uninstall_paths(etc: Path) -> list[Path]:
    return [etc / "fail2ban" / "jail.d" / SLOT_CONF_NAME]

