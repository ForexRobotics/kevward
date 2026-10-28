"""Laravel projects: composer advisory audit (report-only) + version note.

Scans configured project paths for a Laravel app (artisan + composer.lock) and
reports dependency advisories. Does NOT run composer update — see _composer.py.

Configure paths via policy override, e.g.:

    [policy.overrides.laravel]
    paths = ["/var/www/hokaku_server", "/srv/app"]
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ._composer import composer_audit
from ..model import Finding, FindingKind, Severity
from ..plugin import register, ServicePlugin
from ..util import run

# Default scan roots; override via config.
_DEFAULT_ROOTS = ["/var/www", "/srv", str(Path.home() / "website")]


def _find_laravel_apps(roots: list[str]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(r):
            # Don't descend into vendor/node_modules.
            dirnames[:] = [d for d in dirnames if d not in {"vendor", "node_modules", ".git"}]
            p = Path(dirpath)
            if (p / "artisan").is_file() and (p / "composer.lock").is_file():
                found.append(p)
                dirnames[:] = []  # don't recurse inside an app
    return found


@register
class LaravelPlugin(ServicePlugin):
    name = "laravel"
    supports_apply = False  # report-only by design

    #: Overridable at runtime by the engine via config (see module docstring).
    roots: list[str] = _DEFAULT_ROOTS

    def detect(self) -> bool:
        return bool(_find_laravel_apps(self.roots))

    def version(self) -> str | None:
        apps = _find_laravel_apps(self.roots)
        if not apps:
            return None
        return f"{len(apps)} app(s): " + ", ".join(a.name for a in apps)

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
                ver = pkg.get("version", "?")
                return [
                    Finding(
                        service=self.name,
                        kind=FindingKind.CONFIG,
                        severity=Severity.INFO,
                        title=f"{app.name}: laravel/framework {ver}",
                        detail="Check https://laravel.com/docs/releases for the "
                        "support status of this release.",
                        current_version=ver,
                    )
                ]
        return []
