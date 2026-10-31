"""Configuration loading and the safety policy.

Config is optional; sane, *safe* defaults apply when no file is present.
Format is TOML (stdlib ``tomllib`` on 3.11+, ``tomli`` backport on 3.10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10: pip install tomli
    import tomli as tomllib

DEFAULT_PATHS = [
    Path("/etc/kevward/config.toml"),
    Path.home() / ".config" / "kevward" / "config.toml",
    Path("kevward.toml"),
]


@dataclass
class Policy:
    """What kevward is permitted to do. Defaults are conservative."""

    # Apply security updates when running `apply`.
    apply_security: bool = True
    # Apply non-security minor version upgrades. Off by default.
    apply_minor: bool = False
    # Allow kevward to reboot the host itself. Off by default: by default it
    # only *reports* that a reboot is required, or schedules one in a window.
    allow_reboot: bool = False
    # Maintenance window for scheduled reboots, local time "HH:MM".
    reboot_window_start: str = "04:00"
    # Services to manage. Empty = all discovered plugins.
    services: list[str] = field(default_factory=list)
    # Per-service overrides, e.g. {"nginx": {"apply_minor": true}}.
    overrides: dict[str, dict] = field(default_factory=dict)

    def for_service(self, name: str) -> Policy:
        ov = self.overrides.get(name)
        if not ov:
            return self
        merged = {**self.__dict__, **ov}
        merged.pop("overrides", None)
        return Policy(**{k: v for k, v in merged.items() if k in Policy.__annotations__})


@dataclass
class FirewallConfig:
    """Active-defense blocklist settings (see `kevward firewall`)."""

    # TTL for blocklist elements; they age out automatically.
    ttl_days: float = 14.0
    # Minimum sshd auth failures for an IP to qualify (fail2ban bans always do).
    min_sshd_failures: int = 20
    # Extra CIDRs/IPs that must never be blocked (added to the built-in floor).
    allow: list[str] = field(default_factory=list)
    # Optional DNSBL cross-check (off by default -> no network call).
    check_dnsbl: bool = False
    # DNSBL zone to query (e.g. a Spamhaus DQS zone "<key>.zen.dq.spamhaus.net").
    dnsbl_zone: str = "zen.spamhaus.org"
    # Resolver to query directly (DNSBLs rate-limit per resolver; public ones are
    # blocked by Spamhaus). None = system resolver from /etc/resolv.conf.
    dnsbl_resolver: str | None = None
    # Only look up the top-N block candidates; cache results this many days.
    dnsbl_top_n: int = 10
    dnsbl_cache_days: float = 7.0


@dataclass
class Config:
    policy: Policy = field(default_factory=Policy)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    report_dir: Path = Path("/var/log/kevward")

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        candidates = [Path(path)] if path else DEFAULT_PATHS
        for p in candidates:
            if p.is_file():
                return cls._from_file(p)
        return cls()

    @classmethod
    def _from_file(cls, p: Path) -> Config:
        data = tomllib.loads(p.read_text())
        pol = data.get("policy", {})
        policy = Policy(**{k: v for k, v in pol.items() if k in Policy.__annotations__})
        cfg = cls(policy=policy)
        fw = data.get("firewall", {})
        cfg.firewall = FirewallConfig(
            **{k: v for k, v in fw.items() if k in FirewallConfig.__annotations__}
        )
        if "report_dir" in data:
            cfg.report_dir = Path(data["report_dir"])
        return cfg
