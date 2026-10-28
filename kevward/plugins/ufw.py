"""ufw: apt package + "is the firewall actually active?" check."""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import is_root, run
from ._apt import AptServicePlugin


@register
class UfwPlugin(AptServicePlugin):
    name = "ufw"
    packages = ["ufw"]
    service_unit = "ufw.service"

    def check(self) -> list[Finding]:
        findings = super().check()
        # `ufw status` needs root; skip the active-check silently otherwise.
        if is_root():
            res = run(["ufw", "status"], timeout=15)
            if res.ok and "Status: inactive" in res.out:
                findings.append(
                    Finding(
                        service=self.name,
                        kind=FindingKind.CONFIG,
                        severity=Severity.HIGH,
                        title="Firewall is inactive",
                        detail="ufw is installed but not enabled. Enable with "
                        "`ufw enable` after confirming your SSH rule.",
                    )
                )
        return findings
