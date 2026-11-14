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
    #: Directory names whose presence means a copy may be bundled outside any
    #: lock file (e.g. WordPress ships PHPMailer in wp-includes/). When one is
    #: found, "absent from every lock file" no longer means not applicable.
    bundled_in: tuple[str, ...] = ()
    #: "composer" (composer.lock) or "npm" (package-lock.json).
    ecosystem: str = "composer"


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
    # PHPMailer before 5.2.18 (mail() sender injection). WordPress bundled its
    # own copy (fixed in WordPress 4.7.1), so wp-includes/ blocks an "absent".
    "CVE-2016-10033": ComposerRule(
        "phpmailer/phpmailer", ((None, "5.2.18"),), "fixed in PHPMailer 5.2.18",
        bundled_in=("wp-includes",)),
    # systeminformation (npm) before 5.3.1: command injection.
    "CVE-2021-21315": ComposerRule(
        "systeminformation", ((None, "5.3.1"),), "fixed in systeminformation 5.3.1",
        ecosystem="npm"),
}

#: Global npm module directories (a package there has no lock file).
NPM_GLOBAL = ["/usr/lib/node_modules", "/usr/local/lib/node_modules"]


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


def find_lock_files(roots: list[str] | None = None, max_depth: int = _MAX_DEPTH,
                    name: str = "composer.lock") -> list[Path]:
    """Lock files called ``name`` under ``roots`` (depth-bounded; skips
    vendor/, node_modules/ and hidden directories)."""
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
            if name in filenames:
                lf = (p / name)
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


def npm_lock_packages(text: str) -> dict[str, str] | None:
    """name -> version from a package-lock.json (v1 or v2/v3). None if unreadable."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, str] = {}
    for key, meta in (data.get("packages") or {}).items():
        if isinstance(meta, dict) and "node_modules/" in key:
            out[key.rsplit("node_modules/", 1)[1].lower()] = str(meta.get("version") or "")
    def walk(deps):
        for n, meta in (deps or {}).items():
            if isinstance(meta, dict):
                out.setdefault(n.lower(), str(meta.get("version") or ""))
                walk(meta.get("dependencies"))
    walk(data.get("dependencies"))
    return out


def find_dirs(names: tuple[str, ...], roots: list[str] | None = None,
              max_depth: int = _MAX_DEPTH) -> list[Path]:
    """Directories called one of ``names`` under ``roots`` (depth-bounded)."""
    found: list[Path] = []
    for root in roots or DEFAULT_ROOTS:
        r = Path(root)
        if not r.is_dir():
            continue
        base = len(r.parts)
        for dirpath, dirnames, _f in os.walk(r):
            p = Path(dirpath)
            found.extend(p / d for d in dirnames if d in names)
            dirnames[:] = [d for d in dirnames if d not in names and d not in _SKIP_DIRS
                           and not d.startswith(".")]
            if len(p.parts) - base >= max_depth:
                dirnames[:] = []
    return found


def decide(
    cve: str, locks: dict[str, dict[str, str]], bundled: list[str] | None = None,
) -> tuple[str, str] | None:
    """(label, reason) for ``cve`` given {lock path: packages}, or None. Pure.

    ``bundled`` lists directories where the package may sit outside any lock
    file (see ``ComposerRule.bundled_in``); they block a "not applicable".
    """
    rule = RULES.get(cve)
    if rule is None or not locks:
        return None
    hits = [(path, pkgs[rule.package]) for path, pkgs in sorted(locks.items())
            if rule.package in pkgs]
    if not hits:
        if bundled:
            return None
        lock = "composer.lock" if rule.ecosystem == "composer" else "package-lock.json"
        return ("not_applicable",
                f"{rule.package} is not in any {lock} on this host "
                f"({len(locks)} checked)")
    bad = [(p, v) for p, v in hits if is_vulnerable(v, rule)]
    where = "; ".join(f"{Path(p).parent}: {v}" for p, v in (bad or hits))
    if bad:
        return ("applicable", f"{rule.package} in vulnerable range ({rule.note}): {where}")
    return ("fixed", f"{rule.package} past the fix ({rule.note}): {where}")


def _read_locks(roots, name, parse) -> dict[str, dict[str, str]] | None:
    locks: dict[str, dict[str, str]] = {}
    for lf in find_lock_files(roots, name=name):
        try:
            pkgs = parse(lf.read_text())
        except OSError:
            pkgs = None
        if pkgs is None:
            return None  # one unreadable lock file: never guess "absent"
        locks[str(lf)] = pkgs
    return locks


def _npm_globals(dirs: list[str]) -> dict[str, dict[str, str]]:
    """Globally installed npm packages, as pseudo lock entries."""
    out: dict[str, dict[str, str]] = {}
    for d in dirs:
        base = Path(d)
        if not base.is_dir():
            continue
        pkgs: dict[str, str] = {}
        try:
            for pj in base.glob("*/package.json"):
                try:
                    meta = json.loads(pj.read_text())
                    pkgs[str(meta.get("name") or pj.parent.name).lower()] = str(
                        meta.get("version") or "")
                except (OSError, ValueError):
                    continue
        except OSError:
            continue
        out[str(base / "package.json")] = pkgs
    return out


def evaluate(cves: list[str], roots: list[str] | None = None,
             npm_global: list[str] | None = None) -> dict[str, tuple[str, str]]:
    """Map CVE -> (label, reason) for the CVEs a rule can decide on this host."""
    wanted = [c for c in cves if c in RULES]
    if not wanted:
        return {}
    by_eco: dict[str, dict[str, dict[str, str]] | None] = {}
    out: dict[str, tuple[str, str]] = {}
    for c in wanted:
        rule = RULES[c]
        if rule.ecosystem not in by_eco:
            if rule.ecosystem == "npm":
                locks = _read_locks(roots, "package-lock.json", npm_lock_packages)
                if locks is not None:
                    locks.update(_npm_globals(NPM_GLOBAL if npm_global is None else npm_global))
            else:
                locks = _read_locks(roots, "composer.lock", lock_packages)
            by_eco[rule.ecosystem] = locks
        locks = by_eco[rule.ecosystem]
        if not locks:
            continue
        bundled = [str(d) for d in find_dirs(rule.bundled_in, roots)] if rule.bundled_in else []
        if rule.ecosystem == "npm":
            # node_modules/ with no package-lock.json next to it: an install
            # we cannot read, so "absent" is not proven.
            bundled += [str(d) for d in find_dirs(("node_modules",), roots)
                        if not (d.parent / "package-lock.json").is_file()]
        d = decide(c, locks, bundled)
        if d:
            out[c] = d
    return out
