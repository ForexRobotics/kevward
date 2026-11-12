# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

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
    # Permanent operator-configured blocks (CIDR or IP, no TTL). The mirror of
    # `allow`; the allowlist still always wins over these.
    block: list[str] = field(default_factory=list)
    # Install a systemd unit so the blocklist is re-applied on boot.
    persist: bool = True
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
class AuditConfig:
    """`kevward audit` settings."""

    # Glob patterns for authorized_keys `command="..."` values that are known
    # and expected (e.g. your own report-collection key). Matching keys are not
    # reported; any other forced-command key still is.
    allowed_forced_commands: list[str] = field(default_factory=list)


@dataclass
class UpdateConfig:
    """Newer-release notice in reports (read-only; never upgrades)."""

    # Look up the latest kevward on PyPI (cached 24h). False for air-gapped hosts.
    check: bool = True


@dataclass
class TrendsConfig:
    """CISA KEV matching (`trends`, `report --trends`)."""

    # Wall-clock budget (seconds) for the version-aware pass that looks CVEs up
    # in Ubuntu's security data. Cached CVEs cost nothing; uncached kernel CVEs
    # take ~5s each, so a cold host resolves only a handful per run at 45s.
    version_budget_s: float = 45.0
    # Upper bound on network lookups per run (cached CVEs are not counted).
    max_version_checks: int = 80
    # Lookups run this many at a time (#66). 1 restores the old sequential pass.
    fetch_workers: int = 4

    def __post_init__(self) -> None:
        # Keep a typo from hanging the daily report or disabling the pass.
        self.version_budget_s = min(max(float(self.version_budget_s), 0.0), 600.0)
        self.max_version_checks = min(max(int(self.max_version_checks), 0), 1000)
        self.fetch_workers = min(max(int(self.fetch_workers), 1), 16)


@dataclass
class Config:
    policy: Policy = field(default_factory=Policy)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    update: UpdateConfig = field(default_factory=UpdateConfig)
    trends: TrendsConfig = field(default_factory=TrendsConfig)
    report_dir: Path = Path("/var/log/kevward")
    # The file actually loaded (None = built-in defaults), for display (#105).
    source: Path | None = None
    # Why that file could not be used; the config is then all defaults (#104).
    load_error: str | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load the first config file found, or defaults.

        Never raises on a bad file: a daily report must not silently stop
        because of a typo (#104). On any read/parse/type error the result is
        the built-in defaults with ``source`` set and ``load_error`` describing
        the problem (line/column only, never file contents). Callers decide
        what to do: read-only commands warn and continue, side-effecting
        commands refuse.
        """
        candidates = [Path(path)] if path else DEFAULT_PATHS
        for p in candidates:
            if p.is_file():
                try:
                    cfg = cls._from_file(p)
                except tomllib.TOMLDecodeError as exc:
                    cfg = cls(load_error=f"not valid TOML: {exc}")
                except (TypeError, ValueError) as exc:
                    cfg = cls(load_error=f"invalid value: {type(exc).__name__}")
                except OSError as exc:
                    cfg = cls(load_error=f"cannot read: {exc.strerror or type(exc).__name__}")
                cfg.source = p
                return cfg
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
        au = data.get("audit", {})
        cfg.audit = AuditConfig(
            **{k: v for k, v in au.items() if k in AuditConfig.__annotations__}
        )
        up = data.get("update", {})
        cfg.update = UpdateConfig(
            **{k: v for k, v in up.items() if k in UpdateConfig.__annotations__}
        )
        tr = data.get("trends", {})
        cfg.trends = TrendsConfig(
            **{k: v for k, v in tr.items() if k in TrendsConfig.__annotations__}
        )
        if "report_dir" in data:
            cfg.report_dir = Path(data["report_dir"])
        return cfg
