"""Runs plugins according to policy and produces an aggregate run result."""

from __future__ import annotations

import json
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .model import ServiceReport
from .plugin import load


@dataclass
class RunResult:
    host: str
    generated_at: str
    os: str
    services: list[ServiceReport] = field(default_factory=list)
    attackers: dict[str, Any] = field(default_factory=dict)

    @property
    def reboot_required(self) -> bool:
        return any(s.reboot_required for s in self.services)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "generated_at": self.generated_at,
            "os": self.os,
            "reboot_required": self.reboot_required,
            "services": [s.to_dict() for s in self.services],
            "attackers": self.attackers,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def run(cfg: Config, do_apply: bool = False, dry_run: bool = True) -> RunResult:
    only = cfg.policy.services or None
    plugins = load(only)
    result = RunResult(
        host=socket.gethostname(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        os=f"{platform.system()} {platform.release()}",
    )
    for p in plugins:
        sp = cfg.policy.for_service(p.name)
        # Respect per-service apply gating by temporarily narrowing intent.
        apply_this = do_apply and (sp.apply_security or sp.apply_minor)
        result.services.append(p.report(do_apply=apply_this, dry_run=dry_run))
    return result
