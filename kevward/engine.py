# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Runs plugins according to policy and produces an aggregate run result."""

from __future__ import annotations

import json
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .config import Config
from .model import Finding, FindingKind, ServiceReport, Severity
from .plugin import load
from .util import reboot_kind, reboot_pending, reboot_pending_pkgs


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


def gate_change_findings(records: list[dict]) -> list[Finding]:
    """Config changes made through `kevward ssh-gate` in the last days (#185),
    so a change made with a stolen console key stays visible on the host."""
    out = []
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
                      f"ssh-gate at {rec.get('time', '?')} from "
                      f"{rec.get('client') or 'unknown'}",
                detail=("Downgrade (rollback). " if rec.get("downgrade") else "")
                + "Shown for 7 days (/var/lib/kevward/ssh-gate-changes.jsonl); if you "
                  "did not request this, revoke the console's operate key."))
            continue
        changes = rec.get("changes") or {}
        diff = ", ".join(f"{k}: {v.get('old')!r} → {v.get('new')!r}"
                         for k, v in changes.items() if isinstance(v, dict))
        out.append(Finding(
            service="kevward", kind=FindingKind.CONFIG, severity=Severity.INFO,
            title=f"config changed via ssh-gate at {rec.get('time', '?')} "
                  f"from {rec.get('client') or 'unknown'}",
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


def run(cfg: Config, do_apply: bool = False, dry_run: bool = True) -> RunResult:
    only = cfg.policy.services or None
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
    return result
