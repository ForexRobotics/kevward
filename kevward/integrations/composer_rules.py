# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Decide Composer-ecosystem KEV rows from the host's composer.lock files (#62).

Ubuntu's security tracker does not cover Composer packages, so KEV entries for
Laravel, Livewire or Ignition stay ``possible`` forever under the USN layer.
The answer is on disk: every deployed PHP app pins its dependencies in
``composer.lock``. For each rule below kevward reads every lock file it finds
and labels the CVE

* ``not_applicable`` - the package is in none of them,
* ``fixed``          - every copy is at or past the fix,
* ``applicable``     - at least one copy is in the vulnerable range.

Read-only and fail-soft: no lock files, or one that cannot be parsed, decides
nothing and the existing label stands. Versions are compared numerically
(``v11.57.0`` -> (11, 57, 0)); a version that cannot be parsed is treated as
vulnerable rather than guessed safe.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

#: Same roots and limits as the laravel plugin's app search.
DEFAULT_ROOTS = ["/var/www", "/srv", "/home", str(Path.home() / "website")]
_MAX_DEPTH = 5
_SKIP_DIRS = {"vendor", "node_modules"}


@dataclass(frozen=True)
class ComposerRule:
    package: str
    #: Vulnerable ranges as (low inclusive, high exclusive) version strings;
    #: ``None`` for an open end.
    vulnerable: tuple[tuple[str | None, str | None], ...]
    note: str


#: Sources: NVD descriptions / vendor advisories for each CVE.
RULES: dict[str, ComposerRule] = {
    # Laravel Framework through 5.5.40 and 5.6.x through 5.6.29 (APP_KEY
    # unserialize RCE).
    "CVE-2018-15133": ComposerRule(
        "laravel/framework", ((None, "5.5.41"), ("5.6.0", "5.6.30")),
        "fixed in 5.5.41 / 5.6.30"),
    # Ignition before 2.5.2 (facade/ignition). Laravel 9+ ships
    # spatie/laravel-ignition instead, which is not affected.
    "CVE-2021-3129": ComposerRule(
        "facade/ignition", ((None, "2.5.2"),), "fixed in facade/ignition 2.5.2"),
    # Livewire v3 up to 3.6.3 (hydration RCE); v1/v2 are not affected.
    "CVE-2025-54068": ComposerRule(
        "livewire/livewire", (("3.0.0", "3.6.4"),), "fixed in livewire 3.6.4"),
}


def _ver(v: str) -> tuple[int, ...] | None:
    m = re.match(r"^[vV]?(\d+(?:\.\d+)*)", (v or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def is_vulnerable(version: str, rule: ComposerRule) -> bool:
    """True when ``version`` is in a vulnerable range (or cannot be parsed)."""
    v = _ver(version)
    if v is None:
        return True
    for lo, hi in rule.vulnerable:
        lo_v = _ver(lo) if lo else None
        hi_v = _ver(hi) if hi else None
        if (lo_v is None or not _lt(v, lo_v)) and (hi_v is None or _lt(v, hi_v)):
            return True
    return False


def find_lock_files(roots: list[str] | None = None, max_depth: int = _MAX_DEPTH) -> list[Path]:
    """composer.lock files under ``roots`` (depth-bounded; skips vendor/, hidden)."""
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots or DEFAULT_ROOTS:
        r = Path(root)
        if not r.is_dir():
            continue
        base = len(r.parts)
        for dirpath, dirnames, filenames in os.walk(r):
            p = Path(dirpath)
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
            if len(p.parts) - base >= max_depth:
                dirnames[:] = []
            if "composer.lock" in filenames:
                lf = (p / "composer.lock")
                real = lf.resolve()
                if real not in seen:
                    seen.add(real)
                    found.append(lf)
                dirnames[:] = []  # a project's own subdirs are not separate apps
    return found


def lock_packages(text: str) -> dict[str, str] | None:
    """name -> version from a composer.lock (runtime and dev). None if unreadable."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, str] = {}
    for key in ("packages", "packages-dev"):
        for p in data.get(key) or []:
            if isinstance(p, dict) and p.get("name"):
                out[str(p["name"]).lower()] = str(p.get("version") or "")
    return out


def decide(
    cve: str, locks: dict[str, dict[str, str]]
) -> tuple[str, str] | None:
    """(label, reason) for ``cve`` given {lock path: packages}, or None. Pure."""
    rule = RULES.get(cve)
    if rule is None or not locks:
        return None
    hits = [(path, pkgs[rule.package]) for path, pkgs in sorted(locks.items())
            if rule.package in pkgs]
    if not hits:
        return ("not_applicable",
                f"{rule.package} is not in any composer.lock on this host "
                f"({len(locks)} checked)")
    bad = [(p, v) for p, v in hits if is_vulnerable(v, rule)]
    where = "; ".join(f"{Path(p).parent}: {v}" for p, v in (bad or hits))
    if bad:
        return ("applicable", f"{rule.package} in vulnerable range ({rule.note}): {where}")
    return ("fixed", f"{rule.package} past the fix ({rule.note}): {where}")


def evaluate(cves: list[str], roots: list[str] | None = None) -> dict[str, tuple[str, str]]:
    """Map CVE -> (label, reason) for the CVEs a rule can decide on this host."""
    wanted = [c for c in cves if c in RULES]
    if not wanted:
        return {}
    locks: dict[str, dict[str, str]] = {}
    for lf in find_lock_files(roots):
        try:
            pkgs = lock_packages(lf.read_text())
        except OSError:
            pkgs = None
        if pkgs is None:
            return {}  # one unreadable lock file: decide nothing, never guess "absent"
        locks[str(lf)] = pkgs
    out: dict[str, tuple[str, str]] = {}
    for c in wanted:
        d = decide(c, locks)
        if d:
            out[c] = d
    return out
