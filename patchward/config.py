"""Configuration loading and the safety policy.

Config is optional; sane, *safe* defaults apply when no file is present.
Format is TOML (stdlib ``tomllib`` on 3.11+).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    tomllib = None  # type: ignore

DEFAULT_PATHS = [
    Path("/etc/patchward/config.toml"),
    Path.home() / ".config" / "patchward" / "config.toml",
    Path("patchward.toml"),
]


@dataclass
class Policy:
    """What patchward is permitted to do. Defaults are conservative."""

    # Apply security updates when running `apply`.
    apply_security: bool = True
    # Apply non-security minor version upgrades. Off by default.
    apply_minor: bool = False
    # Allow patchward to reboot the host itself. Off by default: by default it
    # only *reports* that a reboot is required, or schedules one in a window.
    allow_reboot: bool = False
    # Maintenance window for scheduled reboots, local time "HH:MM".
    reboot_window_start: str = "04:00"
    # Services to manage. Empty = all discovered plugins.
    services: list[str] = field(default_factory=list)
    # Per-service overrides, e.g. {"nginx": {"apply_minor": true}}.
    overrides: dict[str, dict] = field(default_factory=dict)

    def for_service(self, name: str) -> "Policy":
        ov = self.overrides.get(name)
        if not ov:
            return self
        merged = {**self.__dict__, **ov}
        merged.pop("overrides", None)
        return Policy(**{k: v for k, v in merged.items() if k in Policy.__annotations__})


@dataclass
class Config:
    policy: Policy = field(default_factory=Policy)
    report_dir: Path = Path("/var/log/patchward")

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        candidates = [Path(path)] if path else DEFAULT_PATHS
        for p in candidates:
            if p.is_file():
                return cls._from_file(p)
        return cls()

    @classmethod
    def _from_file(cls, p: Path) -> "Config":
        if tomllib is None:  # pragma: no cover
            raise RuntimeError("Python 3.11+ required to read a config file")
        data = tomllib.loads(p.read_text())
        pol = data.get("policy", {})
        policy = Policy(
            **{k: v for k, v in pol.items() if k in Policy.__annotations__}
        )
        cfg = cls(policy=policy)
        if "report_dir" in data:
            cfg.report_dir = Path(data["report_dir"])
        return cfg
