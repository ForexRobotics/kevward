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
from .util import reboot_pending


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
    # The host already asks for a reboot (/run/reboot-required is set), as
    # opposed to "applying the pending updates will need one".
    reboot_pending: bool = False
    # Which config file was used (None = defaults) and why it was unusable.
    config_source: str | None = None
    config_error: str | None = None

    @property
    def reboot_required(self) -> bool:
        return self.reboot_pending or any(s.reboot_required for s in self.services)

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
            "config_source": self.config_source,
            "config_error": self.config_error,
            "services": [s.to_dict() for s in self.services],
            "attackers": self.attackers,
            "audit": None if self.audit is None else [f.to_dict() for f in self.audit],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


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


def run(cfg: Config, do_apply: bool = False, dry_run: bool = True) -> RunResult:
    only = cfg.policy.services or None
    plugins = load(only)
    result = RunResult(
        host=socket.gethostname(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        os=f"{platform.system()} {platform.release()}",
        reboot_pending=reboot_pending(),
        config_source=str(cfg.source) if cfg.source else None,
        config_error=cfg.load_error,
    )
    if cfg.load_error:
        result.services.append(config_error_report(cfg))
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
    return result
