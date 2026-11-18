# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""php-fpm / php-cli: apt packages, EOL branches, and which FPM is in use.

Besides the apt layer this plugin answers, read-only (#85):
  * which PHP branches are on the host (CLI and every running phpX.Y-fpm),
    and whether any is past or near the end of security support, with the
    package origin (Ubuntu archive vs. a PPA);
  * which running FPM versions no nginx/Apache config references;
  * whether ``apt autoremove`` would remove an FPM that the web server uses.
"""

from __future__ import annotations

import re

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import have, run
from . import _webserve as ws
from ._apt import AptServicePlugin
from ._eol import eol_phase

# Approximate PHP security-support end dates (YYYY-MM). Update as upstream moves.
_PHP_EOL = {
    "7.4": "2022-11",
    "8.0": "2023-11",
    "8.1": "2025-12",
    "8.2": "2026-12",
    "8.3": "2027-12",
    "8.4": "2028-12",
    "8.5": "2029-12",
}


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def php_findings(
    service: str,
    cli: str | None,
    running: list[str] | None,
    referenced: set[str] | None,
    autoremove: list[str] | None,
    origins: dict[str, str | None],
    today=None,
) -> list[Finding]:
    """EOL / unused-FPM / autoremove findings. Pure (all host data passed in)."""
    out: list[Finding] = []
    running = running or []
    versions = sorted(set(running) | ({cli} if cli else set()), key=_vkey)
    for v in versions:
        eol = _PHP_EOL.get(v)
        phase = eol_phase(eol, today=today) if eol else None
        if not phase:
            continue
        after = phase == "after"
        where = []
        if v in running:
            use = ("in use by the web server" if referenced and v in referenced
                   else "not referenced by the web server" if referenced is not None
                   else "running")
            where.append(f"php{v}-fpm ({use})")
        if v == cli:
            where.append("CLI")
        origin = origins.get(v)
        out.append(Finding(
            service=service,
            kind=FindingKind.CONFIG,
            severity=Severity.MEDIUM if after else Severity.LOW,
            title=f"PHP {v} {'past' if after else 'nearing'} end of security support ({eol})",
            detail=(f"{'; '.join(where)}. "
                    + (f"Package origin: {origin}. " if origin else "")
                    + "Upstream security fixes end " + eol + "; a PPA or distro may "
                    "backport longer, check the origin. Plan a move to a supported branch."),
            current_version=v,
        ))
    if referenced is not None and running:
        unused = [v for v in running if v not in referenced]
        if unused:
            shown = ", ".join(sorted(referenced, key=_vkey)) or "none"
            out.append(Finding(
                service=service,
                kind=FindingKind.CONFIG,
                severity=Severity.INFO,
                title="PHP-FPM running but not used by the web server: "
                      + ", ".join(unused),
                detail=f"nginx/Apache reference PHP {shown}. If nothing else uses "
                       "them, `systemctl disable --now php"
                       + "-fpm php".join(unused) + "-fpm` reduces attack surface.",
            ))
    if referenced and autoremove is not None:
        doomed = set(autoremove)
        for v in sorted(referenced, key=_vkey):
            if f"php{v}-fpm" in doomed:
                pkgs = sorted(p for p in doomed if p.startswith(f"php{v}"))
                out.append(Finding(
                    service=service,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title=f"php{v}-fpm serves the web server but `apt autoremove` "
                          "would remove it",
                    detail="Marked as automatically installed. Keep it with "
                           f"`sudo apt-mark manual {' '.join(pkgs)}`.",
                ))
    return out


@register
class PhpPlugin(AptServicePlugin):
    name = "php"
    packages = ["php", "php-fpm", "php-cli", "php-common"]
    service_unit = "php-fpm.service"
    kev_terms = ["php"]

    def check(self) -> list[Finding]:
        findings = super().check()
        running = ws.running_fpm()
        cli = self._php_minor()
        nginx_present = have("nginx")
        apache_text = ws.apache_conf_text()
        referenced = ws.referenced_versions(
            ws.nginx_dump() if nginx_present else None, apache_text,
            nginx_present, apache_text is not None)
        need_origin = [v for v in sorted(set(running or []) | ({cli} if cli else set()))
                       if v in _PHP_EOL and eol_phase(_PHP_EOL[v])]
        origins = {v: ws.package_origin(f"php{v}-fpm" if v in (running or [])
                                        else f"php{v}-cli") for v in need_origin}
        autorm = ws.autoremovable() if referenced else None
        findings.extend(php_findings(self.name, cli, running, referenced, autorm, origins))
        return findings

    @staticmethod
    def _php_minor() -> str | None:
        res = run(["php", "-v"], timeout=15)
        if not res.ok:
            return None
        m = re.search(r"PHP (\d+\.\d+)", res.out)
        return m.group(1) if m else None
