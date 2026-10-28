"""Generic composer projects (any PHP app, not just Laravel).

Scans configured roots for composer.lock files and runs `composer audit`.
Report-only, like the Laravel plugin.
"""

from __future__ import annotations

import os
from pathlib import Path

from ._composer import composer_audit
from ..model import Finding
from ..plugin import register, ServicePlugin

_DEFAULT_ROOTS = ["/var/www", "/srv", str(Path.home() / "website")]


def _find_composer_projects(roots: list[str]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if d not in {"vendor", "node_modules", ".git"}]
            p = Path(dirpath)
            if (p / "composer.lock").is_file() and not (p / "artisan").is_file():
                found.append(p)
                dirnames[:] = []
    return found


@register
class ComposerPlugin(ServicePlugin):
    name = "composer"
    supports_apply = False
    roots: list[str] = _DEFAULT_ROOTS

    def detect(self) -> bool:
        return bool(_find_composer_projects(self.roots))

    def version(self) -> str | None:
        n = len(_find_composer_projects(self.roots))
        return f"{n} project(s)" if n else None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        for proj in _find_composer_projects(self.roots):
            findings.extend(composer_audit(proj))
        return findings
