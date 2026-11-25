# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""snap packages (#253): pending refreshes, holds and their age.

Security-relevant software can come from snaps that the apt checks never see:
multipass (with its own qemu and dnsmasq), LXD, certbot, the core snaps.
Snaps have no USN mapping, so the age of a pending refresh is the signal:
LOW when first seen, MEDIUM after 7 days, HIGH after 30. Refreshes held
(system-wide or per snap) for more than 7 days are MEDIUM, a snap tracking an
``edge`` channel is LOW.

Report-only: snapd refreshes snaps itself, and holds are the operator's.
When it runs as root it remembers when each pending refresh / hold was first
seen in /var/lib/kevward/snap-seen.json; otherwise every one is "new".
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import ServicePlugin, register
from ..util import have, is_root, run

SEEN_FILE = Path("/var/lib/kevward/snap-seen.json")
SNAPD_SOCKET = "/run/snapd.socket"
MEDIUM_DAYS = 7
HIGH_DAYS = 30
HOLD_DAYS = 7


def parse_table(text: str) -> list[dict]:
    """``snap list`` / ``snap refresh --list`` text -> one dict per row, keyed
    by the lower-cased header. Pure."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("Name"):
        return []
    head = [h.lower() for h in lines[0].split()]
    rows = []
    for ln in lines[1:]:
        cells = ln.split()
        if len(cells) < len(head):
            cells += [""] * (len(head) - len(cells))
        rows.append(dict(zip(head, cells[:len(head) - 1] + [" ".join(cells[len(head) - 1:])],
                             strict=True)))
    return rows


def parse_hold(value: str, now: datetime) -> datetime | None:
    """``snap get system refresh.hold``: an RFC 3339 time or ``forever``.
    The time until which refreshes are held, or None if not held. Pure."""
    v = (value or "").strip()
    if not v:
        return None
    if v == "forever":
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t if t > now else None


def _age_days(seen: dict, key: str, now: datetime) -> float:
    try:
        return (now - datetime.fromisoformat(seen[key])).total_seconds() / 86400
    except (KeyError, ValueError, TypeError):
        return 0.0


def update_seen(seen: dict, keys: list[str], now: datetime) -> dict:
    """Keep first-seen times for the keys still present; add new ones. Pure."""
    return {k: seen.get(k) or now.isoformat(timespec="seconds") for k in keys}


def findings_for(installed: list[dict], pending: list[dict], hold_until: datetime | None,
                 seen: dict, now: datetime) -> list[Finding]:
    """Findings from parsed snap state. ``seen`` already updated. Pure."""
    out: list[Finding] = []
    have_rev = {r["name"]: r for r in installed}
    for p in pending:
        name = p.get("name", "")
        cur = have_rev.get(name, {})
        age = _age_days(seen, f"refresh:{name}:{p.get('rev', '')}", now)
        sev = (Severity.HIGH if age >= HIGH_DAYS else
               Severity.MEDIUM if age >= MEDIUM_DAYS else Severity.LOW)
        since = f"pending for {int(age)} day(s)" if age >= 1 else "pending"
        out.append(Finding(
            service="snap", kind=FindingKind.MINOR_UPGRADE, severity=sev,
            title=f"snap {name}: refresh {cur.get('version', '?')} → "
                  f"{p.get('version', '?')} {since}",
            detail=f"Revision {cur.get('rev', '?')} → {p.get('rev', '?')} "
                   f"({cur.get('tracking') or 'no channel'}). snapd refreshes snaps on its "
                   "own schedule; a refresh that stays pending is usually held or failing "
                   f"(`snap changes`, `sudo snap refresh {name}`).",
            current_version=cur.get("version"), fixed_version=p.get("version")))
    if hold_until is not None:
        forever = hold_until.year == datetime.max.year
        if forever or hold_until - now > timedelta(days=HOLD_DAYS):
            out.append(Finding(
                service="snap", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                title="snap refreshes are held "
                      + ("indefinitely" if forever else f"until {hold_until:%Y-%m-%d}"),
                detail="`snap get system refresh.hold`: no snap receives updates, including "
                       "security fixes, until then. `sudo snap refresh --unhold` lifts it."))
    for r in installed:
        name = r.get("name", "")
        notes = r.get("notes", "")
        if "held" in notes.split(","):
            age = _age_days(seen, f"held:{name}", now)
            if age >= HOLD_DAYS:
                out.append(Finding(
                    service="snap", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                    title=f"snap {name}: refreshes held for {int(age)} days",
                    detail=f"`sudo snap refresh --unhold {name}` lifts it."))
        tracking = r.get("tracking", "")
        if tracking.endswith("edge") or tracking == "edge":
            out.append(Finding(
                service="snap", kind=FindingKind.CONFIG, severity=Severity.LOW,
                title=f"snap {name} tracks the {tracking} channel",
                detail="Edge builds are untested daily builds; a server usually tracks "
                       f"stable (`sudo snap refresh {name} --channel=latest/stable`)."))
    return out


@register
class SnapPlugin(ServicePlugin):
    name = "snap"
    supports_apply = False
    kev_terms = ["snapd"]
    seen_file: Path = SEEN_FILE

    def detect(self) -> bool:
        return have("snap") and os.path.exists(SNAPD_SOCKET)

    def version(self) -> str | None:
        r = run(["snap", "version"], timeout=15)
        for ln in r.out.splitlines() if r.ok else []:
            if ln.startswith("snapd"):
                return ln.split()[-1]
        return None

    def _state(self) -> tuple[list[dict], list[dict], datetime | None]:
        now = datetime.now(timezone.utc)
        installed = parse_table(run(["snap", "list", "--unicode=never", "--color=never"],
                                    timeout=30).out)
        pending = parse_table(run(["snap", "refresh", "--list", "--unicode=never",
                                   "--color=never"], timeout=60).out)
        hold = run(["snap", "get", "system", "refresh.hold"], timeout=15)
        return installed, pending, parse_hold(hold.out if hold.ok else "", now)

    def check(self) -> list[Finding]:
        now = datetime.now(timezone.utc)
        installed, pending, hold_until = self._state()
        keys = [f"refresh:{p.get('name')}:{p.get('rev')}" for p in pending]
        keys += [f"held:{r.get('name')}" for r in installed
                 if "held" in r.get("notes", "").split(",")]
        try:
            old = json.loads(self.seen_file.read_text())
            old = old if isinstance(old, dict) else {}
        except (OSError, ValueError):
            old = {}
        seen = update_seen(old, keys, now)
        if is_root() and seen != old:
            try:
                self.seen_file.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.seen_file.with_name(self.seen_file.name + ".tmp")
                tmp.write_text(json.dumps(seen, indent=1) + "\n")
                os.replace(tmp, self.seen_file)
            except OSError:
                pass
        out = findings_for(installed, pending, hold_until, seen, now)
        if installed:
            shown = ", ".join(f"{r['name']} {r.get('version', '?')}" for r in installed[:20])
            more = f" (+{len(installed) - 20})" if len(installed) > 20 else ""
            out.append(Finding(
                service="snap", kind=FindingKind.CONFIG, severity=Severity.INFO,
                title=f"{len(installed)} snap(s) installed, {len(pending)} refresh(es) pending",
                detail=f"{shown}{more}."))
        return out
