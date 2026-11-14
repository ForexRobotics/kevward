# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Config-conditional applicability for actively-exploited CVEs (#86).

Some KEV entries only apply under a specific host configuration, which
name + version matching cannot express. Example: OpenSSH "SSHole"
(CVE-2026-123158) affects only musl-libc builds with PAM disabled; glibc
distributions (all Ubuntu/Debian) and PAM-based setups are not affected.
Without this layer it would be listed against every host running openssh.

Each rule is a small predicate over cheap, read-only local facts. A rule
returns a one-line reason when the CVE is *not applicable* on this host, or
None when it cannot rule the CVE out (the existing status then stands).
Fail-soft throughout: a fact that cannot be read is ``None`` and never makes a
CVE disappear.
"""

from __future__ import annotations

import glob
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from ..util import run

#: Status shown for a CVE ruled out by host configuration.
NOT_APPLICABLE = "not_applicable"


@dataclass
class HostFacts:
    """Lazily-read local facts. ``None`` = unknown (could not be read)."""

    _cache: dict[str, str | None] = field(default_factory=dict)

    def libc(self) -> str | None:
        """'glibc' | 'musl' | None."""
        if "libc" not in self._cache:
            self._cache["libc"] = _detect_libc()
        return self._cache["libc"]

    def os_family(self) -> str:
        """'linux' | 'windows' | other ``sys.platform`` prefix. Always known."""
        if sys.platform.startswith("win"):
            return "windows"
        if sys.platform.startswith("linux"):
            return "linux"
        return sys.platform

    def php_branches(self) -> list[tuple[int, int]] | None:
        """Installed PHP branches from dpkg source names (php8.1 -> (8, 1)).

        Ubuntu ships PHP as versioned source packages (php7.4, php8.1, ...), so
        a CVE that Ubuntu tracks under php7.x never matches a php8.x host by
        name (#62). None when dpkg cannot be read; [] when no PHP is installed.
        """
        if "_php" not in self._cache:
            try:
                from .usn import installed_source_versions
                srcs = installed_source_versions()
            except Exception:
                srcs = None
            self._cache["_php"] = None if srcs is None else ",".join(
                f"{a}.{b}" for a, b in parse_php_branches(srcs))
        raw = self._cache["_php"]
        if raw is None:
            return None
        return [tuple(int(x) for x in s.split(".")) for s in raw.split(",") if s]

    def sshd(self, key: str) -> str | None:
        """Effective ``sshd -T`` value (lower-cased), or None if unreadable."""
        if "_sshd_read" not in self._cache:
            self._cache["_sshd_read"] = "1"
            for k, v in _read_sshd_t().items():
                self._cache[f"sshd:{k}"] = v
        return self._cache.get(f"sshd:{key.lower()}")


def parse_php_branches(sources) -> list[tuple[int, int]]:
    """(major, minor) for each ``phpX.Y`` / ``php5`` source package. Pure."""
    out = set()
    for name in sources:
        m = re.match(r"^php(\d)(?:\.(\d+))?$", name)
        if m:
            out.add((int(m.group(1)), int(m.group(2) or 0)))
    return sorted(out)


def _detect_libc() -> str | None:
    try:
        ver = os.confstr("CS_GNU_LIBC_VERSION")  # e.g. "glibc 2.35"
    except (AttributeError, ValueError, OSError):
        ver = None
    if ver and ver.lower().startswith("glibc"):
        return "glibc"
    if glob.glob("/lib/ld-musl-*.so*"):
        return "musl"
    return None


def _read_sshd_t() -> dict[str, str]:
    """Parse ``sshd -T`` (usually needs root). Empty dict on any failure."""
    try:
        res = run(["sshd", "-T"], timeout=20)
    except Exception:
        return {}
    if not res.ok:
        return {}
    cfg: dict[str, str] = {}
    for line in res.out.splitlines():
        k, sep, v = line.partition(" ")
        if sep:
            cfg[k.lower()] = v.strip().lower()
    return cfg


# --- rules --------------------------------------------------------------------

Rule = Callable[[HostFacts], "str | None"]


def _sshole(f: HostFacts) -> str | None:
    """CVE-2026-123158: musl libc + PAM disabled only."""
    if f.libc() == "glibc":
        return "glibc host; SSHole affects only musl-libc OpenSSH builds"
    if f.sshd("usepam") == "yes":
        return "sshd UsePAM yes; SSHole affects only PAM-disabled sshd"
    return None


def _windows_only(f: HostFacts) -> str | None:
    """CVEs that can only be exploited on Windows hosts."""
    if f.os_family() != "windows":
        return f"Windows-only vulnerability; host is {f.os_family()}"
    return None


def _php_all_at_least(branch: tuple[int, int], fixed_in: str) -> Rule:
    """n/a when every installed PHP branch is ``branch`` or newer."""
    def rule(f: HostFacts) -> str | None:
        have_ = f.php_branches()
        if not have_ or min(have_) < branch:
            return None
        shown = ", ".join(f"{a}.{b}" for a, b in have_)
        return (f"installed PHP {shown}; fixed upstream in {fixed_in}, "
                f"PHP {branch[0]}.{branch[1]}+ never affected")
    return rule


RULES: dict[str, Rule] = {
    "CVE-2026-123158": _sshole,
    # PHP-CGI argument injection via Windows "Best-Fit" charset mapping.
    "CVE-2024-4577": _windows_only,
    # PHP-FPM env_path_info underflow: fixed in 7.1.33 / 7.2.24 / 7.3.11,
    # 7.4.0 shipped with the fix.
    "CVE-2019-11043": _php_all_at_least((7, 4), "7.1.33 / 7.2.24 / 7.3.11"),
    # PHP-CGI query-string argument injection: fixed in 5.3.12 / 5.4.2.
    "CVE-2012-1823": _php_all_at_least((5, 5), "5.3.12 / 5.4.2"),
}


def evaluate(cves: list[str], facts: HostFacts | None = None) -> dict[str, str]:
    """Map CVE -> reason for each CVE a rule rules out on this host."""
    facts = facts or HostFacts()
    out: dict[str, str] = {}
    for cve in cves:
        rule = RULES.get(cve)
        if rule is None:
            continue
        try:
            reason = rule(facts)
        except Exception:
            reason = None  # fail-soft: keep the existing status
        if reason:
            out[cve] = reason
    return out
