# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Laravel projects: composer advisory audit (report-only), version + EOL note.

Scans configured project paths for a Laravel app (artisan + composer.lock) and
reports dependency advisories, the framework version, and whether that major
release is past (or near) the end of Laravel's security-fix window. Does NOT
run composer update — see _composer.py.

The default roots include /home so a stale per-user checkout (e.g. a
colleague's old copy of the same app) is not silently missed. The walk is
depth-bounded and skips hidden directories, vendor/ and node_modules/.

Configure paths via policy override, e.g.:

    [policy.overrides.laravel]
    paths = ["/var/www/hokaku_server", "/srv/app"]
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import ServicePlugin, register
from ._composer import composer_audit
from ._eol import eol_phase

# Default scan roots; override via config.
_DEFAULT_ROOTS = ["/var/www", "/srv", "/home", str(Path.home() / "website")]

#: How many directory levels below a root to search. /var/www/html/<user>/
#: develop/<app> is 4 deep; 5 leaves headroom without walking whole trees.
_MAX_DEPTH = 5

_SKIP_DIRS = {"vendor", "node_modules"}

#: End of security fixes per Laravel major (YYYY-MM), from
#: https://laravel.com/docs/releases. Majors not listed get no EOL finding.
_LARAVEL_SECURITY_EOL = {
    "9": "2024-02",
    "10": "2025-02",
    "11": "2026-03",
    "12": "2027-02",
}


def _find_laravel_apps(roots: list[str], max_depth: int = _MAX_DEPTH) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        base_depth = len(r.parts)
        for dirpath, dirnames, _filenames in os.walk(r):
            p = Path(dirpath)
            # Don't descend into dependencies, VCS or other hidden dirs.
            dirnames[:] = [
                d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
            ]
            if len(p.parts) - base_depth >= max_depth:
                dirnames[:] = []
            if (p / "artisan").is_file() and (p / "composer.lock").is_file():
                real = p.resolve()
                if real not in seen:  # roots may overlap (e.g. ~/website under /home)
                    seen.add(real)
                    found.append(p)
                dirnames[:] = []  # don't recurse inside an app
    return found


def _major(version: str) -> str | None:
    """'v11.57.0' -> '11'; None for dev branches or unparsable strings."""
    v = version.lstrip("vV")
    head = v.split(".", 1)[0]
    return head if head.isdigit() else None


@register
class LaravelPlugin(ServicePlugin):
    name = "laravel"
    supports_apply = False  # report-only by design
    kev_terms = ["laravel"]

    #: Overridable at runtime by the engine via config (see module docstring).
    roots: list[str] = _DEFAULT_ROOTS

    def detect(self) -> bool:
        return bool(_find_laravel_apps(self.roots))

    def version(self) -> str | None:
        apps = _find_laravel_apps(self.roots)
        if not apps:
            return None
        return f"{len(apps)} app(s): " + ", ".join(str(a) for a in apps)

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        for app in _find_laravel_apps(self.roots):
            findings.extend(composer_audit(app))
            findings.extend(self._framework_version(app))
        return findings

    def _framework_version(self, app: Path) -> list[Finding]:
        lock = app / "composer.lock"
        try:
            data = json.loads(lock.read_text())
        except Exception:
            return []
        for pkg in data.get("packages", []):
            if pkg.get("name") == "laravel/framework":
                return framework_findings(self.name, app, pkg.get("version", "?"))
        return []


def framework_findings(service: str, app: Path, ver: str, today=None) -> list[Finding]:
    """Version note plus, when applicable, an end-of-security-support finding.

    Pure (no I/O) so it can be unit-tested. ``app`` is shown as a full path
    because the same app name often exists in several places on one host.
    """
    out = [
        Finding(
            service=service,
            kind=FindingKind.CONFIG,
            severity=Severity.INFO,
            title=f"{app.name}: laravel/framework {ver}",
            detail=f"{app} · see https://laravel.com/docs/releases for the "
            "support status of this release.",
            current_version=ver,
        )
    ]
    major = _major(ver)
    eol = _LARAVEL_SECURITY_EOL.get(major or "")
    phase = eol_phase(eol, today=today) if eol else None
    if phase:
        after = phase == "after"
        out.append(
            Finding(
                service=service,
                kind=FindingKind.CONFIG,
                severity=Severity.MEDIUM if after else Severity.LOW,
                title=(
                    f"{app.name}: Laravel {major} "
                    + ("past end of security fixes" if after else "nearing end of security fixes")
                    + f" ({eol})"
                ),
                detail=f"{app} · laravel/framework {ver}. "
                + (
                    "Newly disclosed framework vulnerabilities will not be "
                    "fixed in this major; plan an upgrade to a supported release."
                    if after
                    else "Plan an upgrade to a supported major before this date."
                ),
                current_version=ver,
            )
        )
    return out
