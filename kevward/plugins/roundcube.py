# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Roundcube webmail (#138): installed versions + apt updates. Report-only.

Roundcube is one of the most attacked web applications in CISA KEV. It is
installed from apt (``roundcube`` / ``roundcube-core``, code under
/usr/share/roundcube) or from a release tarball under a web root, so apt
alone misses many installs. Every install found (a depth-bounded walk like
the laravel plugin) is reported as INFO with the ``RCMAIL_VERSION`` read from
``program/include/iniset.php``; ``kev_terms`` then lets KEV matching cover
it. Pending apt updates are reported when the package is installed.

Configure install paths via policy override:

    [policy.overrides.roundcube]
    paths = ["/var/www/webmail"]
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin, _pkg_version

_DEFAULT_ROOTS = ["/var/www", "/srv", "/usr/share/roundcube", "/var/lib/roundcube"]
_MAX_DEPTH = 4
_SKIP_DIRS = {"vendor", "node_modules"}
VERSION_FILE = Path("program/include/iniset.php")


def parse_version(iniset: str) -> str | None:
    """``define('RCMAIL_VERSION', '1.6.9');`` -> '1.6.9'. Pure."""
    m = re.search(r"""define\(\s*['"]RCMAIL_VERSION['"]\s*,\s*['"]([^'"]+)['"]""", iniset or "")
    return m.group(1) if m else None


def find_installs(roots: list[str], max_depth: int = _MAX_DEPTH) -> list[Path]:
    """Directories holding a Roundcube ``program/include/iniset.php``."""
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        base = len(r.parts)
        for dirpath, dirnames, _files in os.walk(r):
            p = Path(dirpath)
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
            if len(p.parts) - base >= max_depth:
                dirnames[:] = []
            if (p / VERSION_FILE).is_file():
                real = p.resolve()
                if real not in seen:
                    seen.add(real)
                    found.append(p)
                dirnames[:] = []
    return found


def _read_version(install: Path) -> str | None:
    try:
        return parse_version((install / VERSION_FILE).read_text(errors="replace"))
    except OSError:
        return None


@register
class RoundcubePlugin(AptServicePlugin):
    name = "roundcube"
    packages = ["roundcube", "roundcube-core"]
    service_unit = ""
    supports_apply = False  # report-only
    kev_terms = ["roundcube"]
    roots: list[str] = _DEFAULT_ROOTS

    def _apt_installed(self) -> bool:
        return any(_pkg_version(p) for p in self.packages)

    def detect(self) -> bool:
        return self._apt_installed() or bool(find_installs(self.roots))

    def version(self) -> str | None:
        for install in find_installs(self.roots):
            v = _read_version(install)
            if v:
                return v
        return super().version()

    def check(self) -> list[Finding]:
        findings = super().check() if self._apt_installed() else []
        for install in find_installs(self.roots):
            v = _read_version(install)
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.INFO,
                    title=f"Roundcube {v or '(version unknown)'} at {install}",
                    detail="Roundcube is frequently in CISA KEV; keep it on the latest "
                    "release (https://roundcube.net/download/).",
                    current_version=v,
                )
            )
        return findings
