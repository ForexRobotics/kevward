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

    def sshd(self, key: str) -> str | None:
        """Effective ``sshd -T`` value (lower-cased), or None if unreadable."""
        if "_sshd_read" not in self._cache:
            self._cache["_sshd_read"] = "1"
            for k, v in _read_sshd_t().items():
                self._cache[f"sshd:{k}"] = v
        return self._cache.get(f"sshd:{key.lower()}")


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


RULES: dict[str, Rule] = {
    "CVE-2026-123158": _sshole,
    # PHP-CGI argument injection via Windows "Best-Fit" charset mapping.
    "CVE-2024-4577": _windows_only,
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
