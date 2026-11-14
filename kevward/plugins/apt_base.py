# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The apt subsystem itself: the full set of pending updates host-wide.

Complements the per-service plugins by catching everything else (kernel,
libraries, base system) so nothing security-relevant is missed.
"""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import format_pkgs, have, reboot_kind, reboot_pending, reboot_pending_pkgs
from ._apt import AptServicePlugin, _simulate_upgrade, change_findings


@register
class AptPlugin(AptServicePlugin):
    name = "apt"
    packages: list[str] = []  # special-cased: this plugin owns the host

    def detect(self) -> bool:
        return have("apt-get")

    def version(self) -> str | None:
        return None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(change_findings(self.name, _simulate_upgrade()))
        if reboot_pending():
            findings.append(reboot_finding(self.name, reboot_pending_pkgs()))
        return findings


def reboot_finding(service: str, pkgs: list[str]) -> Finding:
    """The "Reboot required" finding, saying which packages asked for it.

    Kernel/firmware/microcode (or unknown) -> medium: nothing changes until the
    reboot. Userspace only (e.g. libc6) -> low: needrestart has already
    restarted the services; the reboot replaces the remaining processes."""
    kind = reboot_kind(pkgs)
    title = "Reboot required"
    detail = ("/run/reboot-required is set; a reboot is needed to finish "
              "applying prior updates.")
    if pkgs:
        title += f" ({format_pkgs(pkgs)})"
        detail += " Requested by: " + ", ".join(pkgs) + "."
    if kind == "userspace":
        detail += (" Only userspace packages: services were restarted by "
                   "needrestart; reboot to replace the remaining processes.")
    return Finding(
        service=service,
        kind=FindingKind.CONFIG,
        severity=Severity.LOW if kind == "userspace" else Severity.MEDIUM,
        title=title,
        detail=detail,
        reboot_required=True,
    )

