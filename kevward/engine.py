# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Runs plugins according to policy and produces an aggregate run result."""

from __future__ import annotations

import json
import os
import platform
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .config import Config
from .model import Finding, FindingKind, ServiceReport, Severity
from .plugin import load
from .util import is_root, reboot_kind, reboot_pending, reboot_pending_pkgs


@dataclass
class RunResult:
    host: str
    generated_at: str
    os: str
    services: list[ServiceReport] = field(default_factory=list)
    attackers: dict[str, Any] = field(default_factory=dict)
    # Host compromise indicators (`kevward audit`). None = not run; [] = run,
    # nothing found; a list = indicators to review. Set by `report --audit`.
    audit: list[Finding] | None = None
    # [audit] allowed_outbound matches: rule -> connections silenced (#155).
    audit_allowed_outbound: dict[str, int] = field(default_factory=dict)
    audit_allowed_forced: dict[str, int] = field(default_factory=dict)
    # How `apt-get update` went before the plan was computed (#171):
    # {"state": "ok" | "failed" | "skipped", "seconds", "error"}; {} if no apt.
    apt_refresh: dict = field(default_factory=dict)
    # The host already asks for a reboot (/run/reboot-required is set), as
    # opposed to "applying the pending updates will need one".
    reboot_pending: bool = False
    # Packages listed in reboot-required.pkgs (why the reboot is pending).
    reboot_packages: list[str] = field(default_factory=list)
    # A shutdown/reboot already scheduled with logind (#114):
    # {"state": "scheduled"|"none"|"unknown", "at": ISO UTC, "mode": ...}.
    reboot_schedule: dict = field(default_factory=lambda: {"state": "unknown"})
    # Which config file was used (None = defaults) and why it was unusable.
    config_source: str | None = None
    config_error: str | None = None
    # Settings in the config file that were ignored (#186).
    config_warnings: list[str] = field(default_factory=list)
    # How many rules the audit exceptions loaded (#186): {"allowed_outbound": n, ...}.
    audit_rules: dict[str, int] = field(default_factory=dict)

    @property
    def reboot_required(self) -> bool:
        return self.reboot_pending or any(s.reboot_required for s in self.services)

    @property
    def reboot_kind(self) -> str:
        """'kernel' | 'userspace' | '' -- see util.reboot_kind."""
        return reboot_kind(self.reboot_packages) if self.reboot_pending else ""

    @property
    def reboot_status(self) -> str:
        """'now' | 'after-updates' | 'no' (for display)."""
        if self.reboot_pending:
            return "now"
        return "after-updates" if self.reboot_required else "no"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kevward_version": __version__,
            "host": self.host,
            "generated_at": self.generated_at,
            "os": self.os,
            "reboot_required": self.reboot_required,
            "reboot_pending": self.reboot_pending,
            "reboot_packages": self.reboot_packages,
            "reboot_kind": self.reboot_kind,
            "reboot_scheduled": (self.reboot_schedule.get("at")
                                 if self.reboot_schedule.get("state") == "scheduled" else None),
            "reboot_schedule_state": self.reboot_schedule.get("state", "unknown"),
            "config_source": self.config_source,
            "config_error": self.config_error,
            "config_warnings": self.config_warnings,
            "services": [s.to_dict() for s in self.services],
            "attackers": self.attackers,
            "audit": None if self.audit is None else [f.to_dict() for f in self.audit],
            "audit_allowed_outbound": self.audit_allowed_outbound,
            "audit_allowed_forced": self.audit_allowed_forced,
            "audit_rules": self.audit_rules,
            "apt_refresh": self.apt_refresh,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def config_warning_report(cfg: Config) -> ServiceReport:
    """A MEDIUM finding when settings in the file were ignored (#186): a rule
    in the wrong table silently changes what kevward detects."""
    n = len(cfg.warnings)
    return ServiceReport(
        service="kevward",
        present=True,
        findings=[
            Finding(
                service="kevward",
                kind=FindingKind.CONFIG,
                severity=Severity.MEDIUM,
                title=f"{n} setting{'s' if n != 1 else ''} in {cfg.source} "
                      f"{'are' if n != 1 else 'is'} ignored",
                detail="; ".join(cfg.warnings) + ". Ignored settings are not in effect "
                       "(e.g. an allowlist rule under the wrong [table]).",
            )
        ],
    )


#: Package lists older than this (hours) make pending updates suspect (#179).
APT_LISTS_STALE_H = 48


def lists_age_hours(refresh: dict, now=None) -> float | None:
    from datetime import datetime, timezone

    at = (refresh or {}).get("lists_updated_at")
    if not at:
        return None
    try:
        when = datetime.fromisoformat(at)
    except ValueError:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - when).total_seconds() / 3600)


def apt_refresh_findings(refresh: dict, now=None) -> list[Finding]:
    """A failed ``apt-get update`` or old lists, as one MEDIUM apt finding
    (#179): the updates listed may be incomplete. Pure."""
    refresh = refresh or {}
    age = lists_age_hours(refresh, now)
    age_txt = f"; lists last updated {age:.0f} h ago" if age is not None else ""
    if refresh.get("state") == "failed":
        err = refresh.get("error") or "unknown error"
        hint = ""
        if "changed its" in err and "value from" in err:
            hint = (" A repository changed its Release information (Label/Origin/Suite). "
                    "If the change is expected, accept it once with "
                    "`apt-get update --allow-releaseinfo-change-label` (or the matching "
                    "--allow-releaseinfo-change-* option); kevward never does this itself.")
        return [Finding(service="apt", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                        title=f"apt lists could not be refreshed: {err}",
                        detail="Pending updates below may be incomplete or out of date"
                               + age_txt + "." + hint)]
    if age is not None and age > APT_LISTS_STALE_H:
        return [Finding(service="apt", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                        title=f"apt lists are stale: last updated {age:.0f} h ago",
                        detail="Security updates published since then are missing from this "
                               "report. Run kevward report as root (it refreshes the lists) "
                               "or `apt-get update`.")]
    return []


#: An sshd surge worth a note (#225): at least this factor and this many more
#: failures in the last 24 h than at the previous report.
SSH_SURGE_FACTOR, SSH_SURGE_MIN = 2.0, 50


def ssh_surge_findings(attackers: dict) -> list[Finding]:
    """INFO when sshd failures in the last 24 h jumped since the previous
    report. Pure."""
    lw = (attackers or {}).get("logwatch") or {}
    prev = (attackers or {}).get("previous") or {}
    cur, before = lw.get("ssh_attempts_24h"), prev.get("ssh_failed_24h")
    if not isinstance(cur, int) or not isinstance(before, int):
        return []
    if cur - before < SSH_SURGE_MIN or cur < SSH_SURGE_FACTOR * max(before, 1):
        return []
    pct = f"+{round(100 * (cur - before) / before)}%" if before else "from 0"
    return [Finding(service="sshd", kind=FindingKind.CONFIG, severity=Severity.INFO,
                    title=f"sshd failed logins rose to {cur} in the last 24 h "
                          f"(previous report: {before}, {pct})",
                    detail=f"Previous report: {prev.get('generated_at') or '?'}. Usually a "
                           "scanner wave; check the top sources below and that fail2ban "
                           "is banning them.")]


SUDOERS_GATE = "/etc/sudoers.d/kevward-ssh-gate"
_GATE_ROLE = re.compile(r'command="(?:sudo -n )?/[\w./-]*/kevward ssh-gate --role (read|operate)')


def report_sandbox(mountinfo: str = "/proc/self/mountinfo") -> dict:
    """Does this run see a hidden /home or a private /tmp (#246)? From this
    process's mount table: systemd's ProtectHome=yes mounts an inaccessible
    directory over /home (``tmpfs`` mounts an empty tmpfs); PrivateTmp binds a
    ``systemd-private-*`` directory over /tmp. Read-only."""
    home_hidden = tmp_private = False
    try:
        with open(mountinfo, errors="replace") as fh:
            for ln in fh:
                pre, _, post = ln.partition(" - ")
                f, g = pre.split(), post.split()
                if len(f) < 5:
                    continue
                root, point, fstype = f[3], f[4], (g[0] if g else "")
                if point == "/home" and ("inaccessible" in root or fstype == "tmpfs"):
                    home_hidden = True
                if point == "/tmp" and "systemd-private-" in root:
                    tmp_private = True
    except OSError:
        pass
    return {"home_hidden": home_hidden, "tmp_private": tmp_private}


def sandbox_findings(sb: dict) -> list[Finding]:
    """MEDIUM when the report cannot see the real /home or /tmp (#246). Pure."""
    hidden = [p for p, k in (("/home", "home_hidden"), ("/tmp", "tmp_private")) if sb.get(k)]
    if not hidden:
        return []
    return [Finding(service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                    title=f"the report runs without the real {' and '.join(hidden)}: "
                          "audit checks there are blind",
                    detail="The report unit has ProtectHome and/or PrivateTmp (from an old "
                           "example unit), so authorized_keys, forced-command and /tmp checks "
                           "see nothing. `sudo kevward schedule install` (or a kevward update) "
                           "writes the drop-in that turns them off.")]


def firewall_missing_findings(state: dict) -> list[Finding]:
    """HIGH when kevward's blocklist should be loaded but is not (#244): the
    boot unit is enabled, or it was applied on this host before. Pure."""
    from .firewall import expected_but_missing

    if not expected_but_missing(state or {}):
        return []
    why = ("its boot unit is enabled" if (state or {}).get("unit") == "enabled"
           else "it was applied on this host before")
    return [Finding(service="firewall", kind=FindingKind.CONFIG, severity=Severity.HIGH,
                    title="kevward firewall not loaded: no IPs are being blocked",
                    detail=f"Table inet kevward is absent although {why}. Run `sudo kevward "
                           "firewall apply --yes`; after a reinstall, `sudo kevward setup "
                           "--restore` puts it back with the console's address allowed. "
                           "To stop using the blocklist, remove /var/lib/kevward/firewall.json.")]


def gate_access(homes: list[str], sudoers: str = SUDOERS_GATE) -> dict:
    """Which ssh-gate keys exist in the given home directories and whether the
    operate role's sudoers drop-in is there (#237). ``checked``: authorized_keys
    files read (#246). Read-only."""
    roles = {"read": 0, "operate": 0}
    checked = 0
    for home in homes:
        try:
            with open(os.path.join(home, ".ssh", "authorized_keys"), errors="replace") as fh:
                checked += 1
                for ln in fh:
                    m = _GATE_ROLE.search(ln)
                    if m:
                        roles[m.group(1)] += 1
        except OSError:
            continue
    return {**roles, "sudoers": os.path.exists(sudoers), "checked": checked}


def gate_access_findings(enabled: bool, access: dict, snapshot_exists: bool,
                         home_hidden: bool = False) -> list[Finding]:
    """MEDIUM when ssh-gate is on but a console could not get in (#237):
    no gate key at all, or operate keys without their sudoers drop-in. Pure."""
    if not enabled:
        return []
    fix = ("Put it back with `sudo kevward setup --restore` (from the snapshot "
           "`kevward uninstall` saved)" if snapshot_exists else
           "Run `sudo kevward setup --console-user … --read-key … --operate-key …`")
    if not access.get("read") and not access.get("operate"):
        if home_hidden:
            # Could not look: never claim the keys are missing (#246).
            return [Finding(service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
                            title="ssh-gate keys could not be checked: /home is hidden "
                                  "from the report",
                            detail="This run cannot see /home (ProtectHome in the report "
                                   f"unit); {access.get('checked', 0)} authorized_keys "
                                   "file(s) were read elsewhere.")]
        return [Finding(service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                        title="ssh-gate is enabled but no authorized_keys entry uses it",
                        detail="The console cannot connect to this host. Checked "
                               f"{access.get('checked', 0)} authorized_keys file(s) under the "
                               "users' home directories. " + fix + ".")]
    if access.get("operate") and not access.get("sudoers"):
        return [Finding(service="kevward", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                        title=f"ssh-gate operate key without {SUDOERS_GATE}",
                        detail="The operate role runs through `sudo -n` and fails without "
                               "this file, so updates, apply and reboots from the console "
                               "do not work. " + fix + ".")]
    return []


def _from(rec: dict) -> str:
    """'from 203.0.113.5', with the key's name when recorded (#223)."""
    key = f"(key {rec['key']}) " if rec.get("key") else ""
    return f"{key}from {rec.get('client') or 'unknown'}"


def gate_change_findings(records: list[dict]) -> list[Finding]:
    """Config changes made through `kevward ssh-gate` in the last days (#185),
    so a change made with a stolen console key stays visible on the host."""
    out = []
    finished = {r.get("job_id") for r in records if r.get("kind") == "apply.finish"}
    for rec in records:
        if rec.get("kind") == "setup":
            acts = rec.get("actions") or []
            out.append(Finding(
                service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
                title=f"kevward setup changed {len(acts)} item(s) at {rec.get('time', '?')}",
                detail="; ".join(f"{a.get('action')} {a.get('kind')} {a.get('path')}"
                                 for a in acts if isinstance(a, dict))
                + ". Shown for 7 days (/var/lib/kevward/ssh-gate-changes.jsonl)."))
            continue
        if rec.get("kind") == "self.update":
            out.append(Finding(
                service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
                title=f"kevward updated {rec.get('old', '?')} → {rec.get('new', '?')} via "
                      f"ssh-gate at {rec.get('time', '?')} {_from(rec)}",
                detail=("Downgrade (rollback). " if rec.get("downgrade") else "")
                + "Shown for 7 days (/var/lib/kevward/ssh-gate-changes.jsonl); if you "
                  "did not request this, revoke the console's operate key."))
            continue
        kind = rec.get("kind")
        if kind == "apply.start" and rec.get("job_id") in finished:
            continue
        if kind in ("apply.start", "apply.finish"):
            who = f"at {rec.get('time', '?')} {_from(rec)}"
            res = rec.get("result") or {}
            if kind == "apply.start":
                title = f"apply job {rec.get('job_id')} started via ssh-gate {who}"
                pk = rec.get("packages") or []
            else:
                title = (f"packages applied via ssh-gate (job {rec.get('job_id')}) {who}"
                         if rec.get("state") == "succeeded" else
                         f"apply via ssh-gate failed (job {rec.get('job_id')}) {who}")
                pk = res.get("installed") or []
            detail = (f"Installed: {', '.join(pk)}. " if pk and kind == "apply.finish" else
                      f"Plan: {', '.join(pk) or 'nothing'}. " if kind == "apply.start" else "")
            if rec.get("error"):
                detail += f"Error: {rec['error']}. "
            out.append(Finding(
                service="kevward", kind=FindingKind.CONFIG,
                severity=Severity.INFO if rec.get("state") != "failed" else Severity.MEDIUM,
                title=title,
                detail=detail + "Shown for 7 days (/var/lib/kevward/ssh-gate-changes.jsonl); "
                "if you did not request this, revoke the console's operate key."))
            continue
        if kind == "report.refresh":
            continue  # rebuilding the report changes nothing on the host
        if kind in ("reboot.schedule", "reboot.cancel", "schedule.install"):
            who = f"via ssh-gate at {rec.get('time', '?')} {_from(rec)}"
            if kind == "reboot.schedule":
                title = f"reboot scheduled for {rec.get('at', '?')} {who}"
                extra = (f"Reason: {rec['reason']}. " if rec.get("reason") else "")
            elif kind == "reboot.cancel":
                title = f"scheduled reboot cancelled {who}"
                extra = f"Was: {(rec.get('was') or {}).get('at', '?')}. "
            else:
                title = f"report timer (re)installed {who}"
                extra = ""
            out.append(Finding(
                service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
                title=title,
                detail=extra + "Shown for 7 days (/var/lib/kevward/ssh-gate-changes.jsonl); "
                "if you did not request this, revoke the console's operate key."))
            continue
        changes = rec.get("changes") or {}
        diff = ", ".join(f"{k}: {v.get('old')!r} → {v.get('new')!r}"
                         for k, v in changes.items() if isinstance(v, dict))
        out.append(Finding(
            service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
            title=f"config changed via ssh-gate at {rec.get('time', '?')} {_from(rec)}",
            detail=f"{diff}. Backup: {rec.get('backup') or 'none'}. Shown for 7 days "
                   "(/var/lib/kevward/ssh-gate-changes.jsonl); if you did not make "
                   "this change, revoke the console key."))
    return out


def config_error_report(cfg: Config) -> ServiceReport:
    """A HIGH finding so an unreadable config is visible in every report."""
    return ServiceReport(
        service="kevward",
        present=True,
        findings=[
            Finding(
                service="kevward",
                kind=FindingKind.CONFIG,
                severity=Severity.HIGH,
                title=f"config file could not be used; running with defaults: {cfg.source}",
                detail=f"{cfg.load_error}. Settings in this file (allowlists, budgets, "
                "policy overrides) are NOT in effect. Fix the file; side-effecting "
                "commands (apply --yes, firewall apply/flush, schedule-reboot) refuse "
                "to run until then.",
            )
        ],
    )


def _reboot_schedule() -> dict:
    try:
        from .scheduler import scheduled_reboot
        return scheduled_reboot()
    except Exception:
        return {"state": "unknown"}


def _configure_apt(cfg: Config) -> None:
    from .plugins import _apt

    _apt.reset_simulation()
    _apt.configure(_apt.AptSettings(
        security_origins=list(cfg.apt.security_origins),
        php_release_check=cfg.apt.php_release_check,
        install_timeout_s=cfg.apt.install_timeout_s,
    ))


def run(cfg: Config, do_apply: bool = False, dry_run: bool = True,
        fresh: bool = True) -> RunResult:
    """``fresh=False`` reuses the apt plan computed by the previous run in this
    process, so an apply installs exactly the plan a dry run just showed (#197)."""
    only = cfg.policy.services or None
    if fresh:
        _configure_apt(cfg)
    plugins = load(only)
    result = RunResult(
        host=socket.gethostname(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        os=f"{platform.system()} {platform.release()}",
        reboot_pending=reboot_pending(),
        reboot_packages=reboot_pending_pkgs(),
        reboot_schedule=_reboot_schedule(),
        config_source=str(cfg.source) if cfg.source else None,
        config_error=cfg.load_error,
        config_warnings=list(cfg.warnings),
    )
    if cfg.load_error:
        result.services.append(config_error_report(cfg))
    elif cfg.warnings:
        result.services.append(config_warning_report(cfg))
    try:
        from .ssh_gate import recent_changes

        gate = gate_change_findings(recent_changes())
    except Exception:
        gate = []
    try:
        if cfg.ssh_gate.enabled and is_root():
            import pwd

            homes = sorted({pw.pw_dir for pw in pwd.getpwall() if pw.pw_dir})
            gate += gate_access_findings(
                True, gate_access(homes),
                os.path.exists("/var/lib/kevward/setup-snapshot.json"),
                home_hidden=report_sandbox()["home_hidden"])
    except Exception:
        pass
    try:
        if is_root():
            gate += sandbox_findings(report_sandbox())
    except Exception:
        pass
    updaters: list[Finding] = []
    try:
        if is_root() and not do_apply:
            from .updaters import host_findings

            updaters = host_findings(cfg)   # #229 #247
            gate += [f for f in updaters if f.service == "kevward"]
    except Exception:
        pass
    if gate:
        result.services.append(ServiceReport(service="kevward", present=True,
                                             findings=gate))
    claimed: set[str] = set()  # package refs already handed to apply() this run
    for p in plugins:
        sp = cfg.policy.for_service(p.name)
        # Respect per-service apply gating by temporarily narrowing intent.
        apply_this = do_apply and (sp.apply_security or sp.apply_minor)
        result.services.append(
            p.report(
                do_apply=apply_this,
                dry_run=dry_run,
                apply_security=sp.apply_security,
                apply_minor=sp.apply_minor,
                claimed=claimed if apply_this else None,
            )
        )
    from .plugins import _apt

    result.apt_refresh = dict(_apt.REFRESH or {})
    stale = apt_refresh_findings(result.apt_refresh) + [
        f for f in updaters if f.service == "apt"]
    if stale:
        apt_svc = next((s for s in result.services if s.service == "apt"), None)
        if apt_svc is not None:
            apt_svc.findings[:0] = stale
        else:
            result.services.append(ServiceReport(service="apt", present=True, findings=stale))
    return result
