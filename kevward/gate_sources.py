# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Where ssh-gate operations come from (#283, #285).

- A **known** source is one the host already trusts: fail2ban's ``ignoreip``,
  kevward's firewall allowlist, or ``[ssh_gate] known_sources``.
- A **new** source is one whose first operation in the change log is recent
  and which is not known. The report shows it at medium for 2 days, so an
  update / apply / config change from somewhere unusual is not lost among the
  info lines.
- ``gate.capabilities`` tells the console whether its current address is
  exempt, so it can warn before a few failed key logins ban it on every host.

Read-only. The change log is append-only, so "seen before" needs no state of
its own, and the first report after an upgrade does not turn old sources
into new ones.
"""

from __future__ import annotations

import configparser
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model import Finding, FindingKind, Severity

F2B_DIR = Path("/etc/fail2ban")
NEW_SOURCE_DAYS = 2
# Change-log kinds that are not operations from a console.
_NOT_REMOTE = {"setup"}


def _networks(tokens) -> list:
    nets = []
    for t in tokens or []:
        t = str(t).strip()
        if not t or "%(" in t:
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            continue  # host names: fail2ban resolves them, we do not
    return nets


def matches(address: str, tokens) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in _networks(tokens))


# --- fail2ban ---------------------------------------------------------------------

def _f2b_files(f2b: Path) -> list[Path]:
    jd = f2b / "jail.d"
    out = [f2b / "jail.conf", *sorted(jd.glob("*.conf")), f2b / "jail.local",
           *sorted(jd.glob("*.local"))]
    return [p for p in out if p.is_file()]


def fail2ban_ignoreip(f2b: Path = F2B_DIR) -> list[str] | None:
    """The ``ignoreip`` tokens that apply to the sshd jail ([DEFAULT] and
    [sshd], files in fail2ban's order, later wins per section), or None when
    fail2ban is not configured here. Interpolations are dropped."""
    files = _f2b_files(f2b)
    if not files:
        return None
    default = sshd = None
    for path in files:
        cp = configparser.RawConfigParser(strict=False, interpolation=None,
                                          inline_comment_prefixes=("#", ";"))
        try:
            cp.read_string(path.read_text(encoding="utf-8", errors="replace"))
        except (configparser.Error, OSError):
            continue
        if cp.defaults().get("ignoreip") is not None:
            default = cp.defaults()["ignoreip"]
        if cp.has_section("sshd") and "ignoreip" in cp._sections["sshd"]:  # noqa: SLF001
            sshd = cp._sections["sshd"]["ignoreip"]  # noqa: SLF001
    tokens = re.split(r"[\s,]+", " ".join(v for v in (default, sshd) if v))
    return [t for t in tokens if t and "%(" not in t]


# --- kevward firewall ---------------------------------------------------------------

def _persisted_allow(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"set allow[46]\s*\{(.*?)\n\s*\}", text, re.S):
        e = re.search(r"elements\s*=\s*\{([^}]*)\}", m.group(1), re.S)
        if e:
            out += [x.strip() for x in e.group(1).replace("\n", " ").split(",") if x.strip()]
    return out


def firewall_allow(cfg, *, in_use=None, persisted: str | None = None) -> list[str] | None:
    """kevward's firewall allowlist when the blocklist is in use, else None:
    the built-in floor, ``[firewall] allow`` and the accept sets of the saved
    ruleset (which hold the console addresses ``setup`` passed)."""
    from . import firewall as fw

    used = fw.in_use() if in_use is None else in_use
    if not used:
        return None
    if persisted is None:
        try:
            persisted = Path(fw.PERSIST_FILE).read_text(encoding="utf-8")
        except OSError:
            persisted = ""
    return [*fw._DEFAULT_ALLOW, *(cfg.firewall.allow or []),  # noqa: SLF001
            *_persisted_allow(persisted)]


# --- the address of a caller ---------------------------------------------------------

_READ = object()


def address_status(address: str, cfg, *, f2b=_READ, fw_allow=_READ, seen=None) -> dict:
    """For ``gate.capabilities`` (#285). ``f2b`` / ``fw_allow``: token lists,
    or None when not in use; by default read from the host. ``null`` in the
    result means "not in use / cannot tell"."""
    f2b = fail2ban_ignoreip() if f2b is _READ else f2b
    fw_allow = firewall_allow(cfg) if fw_allow is _READ else fw_allow
    configured = matches(address, cfg.ssh_gate.known_sources)
    st = {
        "address": address or None,
        "fail2ban_ignored": None if f2b is None else matches(address, f2b),
        "firewall_allowed": None if fw_allow is None else matches(address, fw_allow),
        "configured": configured,
        "seen_before": bool(seen and address in seen),
    }
    st["known_source"] = bool(configured or st["fail2ban_ignored"]
                              or st["firewall_allowed"] or st["seen_before"])
    return st


# --- new sources in the change log (#283) -----------------------------------------------

def all_changes(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("time"):
            out.append(rec)
    return out


def _t(rec: dict) -> datetime | None:
    try:
        t = datetime.fromisoformat(rec["time"])
    except (KeyError, ValueError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def seen_sources(records: list[dict]) -> set[str]:
    return {r["client"] for r in records
            if r.get("client") and r.get("kind") not in _NOT_REMOTE}


def new_source_findings(records: list[dict], now: datetime, is_known) -> list[Finding]:
    """MEDIUM per source whose first operation is less than NEW_SOURCE_DAYS
    old and which ``is_known(address)`` does not trust. Pure."""
    first: dict[str, datetime] = {}
    ops: dict[str, list[dict]] = {}
    for r in records:
        c, t = r.get("client"), _t(r)
        if not c or t is None or r.get("kind") in _NOT_REMOTE:
            continue
        if c not in first or t < first[c]:
            first[c] = t
        ops.setdefault(c, []).append(r)
    out = []
    for c, t0 in sorted(first.items(), key=lambda kv: kv[1]):
        if now - t0 > timedelta(days=NEW_SOURCE_DAYS) or is_known(c):
            continue
        recs = ops[c]
        kinds = []
        for r in recs:
            k = r.get("kind") or "config.set"
            if k not in kinds:
                kinds.append(k)
        keys = sorted({r["key"] for r in recs if r.get("key")})
        key = f" (key {', '.join(keys)})" if keys else ""
        out.append(Finding(
            service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
            title=f"NEW source: {', '.join(kinds)} via ssh-gate from {c}{key}",
            detail=(f"First operation from {c} at {t0.isoformat(timespec='seconds')}; "
                    f"{len(recs)} operation(s) since. This address is not in fail2ban's "
                    "ignoreip, kevward's firewall allowlist or [ssh_gate] known_sources, "
                    "and had not been used before. If it was you (another network), add "
                    "it to [ssh_gate] known_sources or ignore this; shown for "
                    f"{NEW_SOURCE_DAYS} days. If not, revoke the console's operate key.")))
    return out


def host_new_source_findings(cfg, changes_file: Path, now: datetime | None = None,
                             *, f2b=_READ, fw_allow=_READ) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    records = all_changes(changes_file)
    f2b = fail2ban_ignoreip() if f2b is _READ else f2b
    fw_allow = firewall_allow(cfg) if fw_allow is _READ else fw_allow

    def known(addr: str) -> bool:
        return (matches(addr, cfg.ssh_gate.known_sources) or matches(addr, f2b or [])
                or matches(addr, fw_allow or []))
    return new_source_findings(records, now, known)
