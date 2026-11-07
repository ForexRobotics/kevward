# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The apt subsystem itself: the full set of pending updates host-wide.

Complements the per-service plugins by catching everything else (kernel,
libraries, base system) so nothing security-relevant is missed.
"""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import have, reboot_pending
from ._apt import AptServicePlugin, _simulate_upgrade, change_finding


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
        for change in _simulate_upgrade():
            findings.append(change_finding(self.name, change))
        if reboot_pending():
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title="Reboot required",
                    detail="/run/reboot-required is set; a reboot is needed to "
                    "finish applying prior updates.",
                    reboot_required=True,
                )
            )
        return findings
