"""Shared data types used across plugins, reporting and the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class _StrEnum(str, Enum):
    """A str-valued enum that stringifies to its value.

    Equivalent to ``enum.StrEnum`` (3.11+) for our needs, but works on
    Python 3.10 too, which patchward supports (Ubuntu 22.04 ships 3.10).
    """

    def __str__(self) -> str:
        return self.value


class Severity(_StrEnum):
    """Severity of a finding, roughly aligned to CVSS buckets."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


class FindingKind(_StrEnum):
    VULNERABILITY = "vulnerability"       # a known CVE / advisory
    SECURITY_UPDATE = "security_update"   # a pending security package update
    MINOR_UPGRADE = "minor_upgrade"       # a non-security minor version bump
    CONFIG = "config"                     # a hardening / misconfiguration issue


@dataclass
class Finding:
    """A single thing worth a human's attention for one service."""

    service: str
    kind: FindingKind
    severity: Severity
    title: str
    detail: str = ""
    current_version: str | None = None
    fixed_version: str | None = None
    cve: str | None = None
    # Set by the plugin when applying this fix would require a reboot.
    reboot_required: bool = False
    # An opaque, plugin-specific handle used by apply() to action this finding
    # (e.g. a package name). Not shown to users.
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ActionResult:
    """Outcome of applying (or planning to apply) a change."""

    service: str
    description: str
    changed: bool = False
    dry_run: bool = False
    ok: bool = True
    output: str = ""
    reboot_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceReport:
    """Everything one plugin produced during a run."""

    service: str
    present: bool
    version: str | None = None
    findings: list[Finding] = field(default_factory=list)
    actions: list[ActionResult] = field(default_factory=list)
    error: str | None = None

    @property
    def reboot_required(self) -> bool:
        return any(f.reboot_required for f in self.findings) or any(
            a.reboot_required for a in self.actions
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "present": self.present,
            "version": self.version,
            "findings": [f.to_dict() for f in self.findings],
            "actions": [a.to_dict() for a in self.actions],
            "error": self.error,
            "reboot_required": self.reboot_required,
        }
