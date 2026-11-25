# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""phpMyAdmin (#139): installed versions, apt updates, web exposure. Report-only.

phpMyAdmin is a frequent CISA KEV entry and is often installed once and
forgotten. The ``php`` KEV term deliberately does not match it (whole-word
matching), hence this plugin. Installs come from apt (``phpmyadmin``, code in
/usr/share/phpmyadmin, aliased at /phpmyadmin by
/etc/apache2/conf-enabled/phpmyadmin.conf) or from a tarball under a web
root. Each install is reported (INFO) with its version, read from
``libraries/classes/Version.php`` (5.x), ``src/Version.php`` (6.x) or
``libraries/Config.php`` (4.x).

A LOW finding asks the operator to confirm access is restricted when an
install sits under a web root, or when the apache/nginx config aliases it.

Configure install paths via policy override:

    [policy.overrides.phpmyadmin]
    paths = ["/var/www/pma"]
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin, _pkg_version

_DEFAULT_ROOTS = ["/var/www", "/srv"]
APT_DIR = Path("/usr/share/phpmyadmin")
_MAX_DEPTH = 4
_SKIP_DIRS = {"vendor", "node_modules"}
VERSION_FILES = [Path("libraries/classes/Version.php"), Path("src/Version.php"),
                 Path("libraries/Config.php")]
WEB_CONFIG_DIRS = [Path("/etc/apache2/conf-enabled"), Path("/etc/apache2/sites-enabled"),
                   Path("/etc/nginx/sites-enabled"), Path("/etc/nginx/conf.d")]


def parse_version(text: str) -> str | None:
    """Version.php (``VERSION = '5.2.1'``) or 4.x Config.php
    (``'PMA_VERSION', '4.9.5'``) -> the version. Pure."""
    for pat in (r"""\bVERSION\s*=\s*['"]([0-9][^'"]*)['"]""",
                r"""['"]PMA_VERSION['"]\s*,\s*['"]([0-9][^'"]*)['"]"""):
        m = re.search(pat, text or "")
        if m:
            return m.group(1)
    return None


def web_aliases(config: str) -> list[str]:
    """Uncommented apache ``Alias`` / nginx ``location``/``alias``/``root``
    lines that point at phpMyAdmin. Pure."""
    out = []
    for raw in (config or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if re.match(r"(Alias|AliasMatch|location|alias|root)\b.*phpmyadmin", line, re.I):
            out.append(line)
    return out


def _is_install(p: Path) -> bool:
    return any((p / v).is_file() for v in VERSION_FILES)


def find_installs(roots: list[str], max_depth: int = _MAX_DEPTH) -> list[Path]:
    """phpMyAdmin directories under ``roots`` (depth-bounded)."""
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
            if _is_install(p):
                real = p.resolve()
                if real not in seen:
                    seen.add(real)
                    found.append(p)
                dirnames[:] = []
    return found


def read_version(install: Path) -> str | None:
    for v in VERSION_FILES:
        try:
            found = parse_version((install / v).read_text(errors="replace"))
        except OSError:
            continue
        if found:
            return found
    return None


def read_web_config(dirs: list[Path] | None = None) -> str:
    parts = []
    for d in WEB_CONFIG_DIRS if dirs is None else dirs:
        try:
            files = sorted(f for f in d.iterdir() if f.is_file())
        except OSError:
            continue
        for f in files:
            try:
                parts.append(f.read_text(errors="replace"))
            except OSError:
                continue
    return "\n".join(parts)


@register
class PhpMyAdminPlugin(AptServicePlugin):
    name = "phpmyadmin"
    packages = ["phpmyadmin"]
    service_unit = ""
    supports_apply = False  # report-only
    kev_terms = ["phpmyadmin"]
    roots: list[str] = _DEFAULT_ROOTS
    apt_dir: Path = APT_DIR

    def _apt_installed(self) -> bool:
        return any(_pkg_version(p) for p in self.packages)

    def _installs(self) -> list[tuple[Path, bool]]:
        """(path, under a web root) for every install."""
        out = [(p, True) for p in find_installs(self.roots)]
        if _is_install(self.apt_dir) and all(p.resolve() != self.apt_dir.resolve()
                                             for p, _ in out):
            out.append((self.apt_dir, False))
        return out

    def detect(self) -> bool:
        return self._apt_installed() or bool(self._installs())

    def version(self) -> str | None:
        for p, _ in self._installs():
            v = read_version(p)
            if v:
                return v
        return super().version()

    def check(self) -> list[Finding]:
        findings = super().check() if self._apt_installed() else []
        installs = self._installs()
        for p, _ in installs:
            v = read_version(p)
            findings.append(Finding(
                service=self.name, kind=FindingKind.CONFIG, severity=Severity.INFO,
                title=f"phpMyAdmin {v or '(version unknown)'} at {p}",
                detail="phpMyAdmin is frequently in CISA KEV; keep it on the latest "
                "release or remove it if unused.",
                current_version=v,
            ))
        exposed = [str(p) for p, web in installs if web]
        aliases = web_aliases(read_web_config())
        if exposed or aliases:
            where = "; ".join(exposed + [f"web config: {a}" for a in aliases[:3]])
            findings.append(Finding(
                service=self.name, kind=FindingKind.CONFIG, severity=Severity.LOW,
                title="phpMyAdmin is reachable through the web server",
                detail=f"{where}. Confirm it is access-restricted (IP allowlist, "
                "HTTP auth or VPN only), or remove it if unused.",
            ))
        return findings
