"""php-fpm / php-cli: apt packages plus an EOL-version warning."""

from __future__ import annotations

import re

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin

# Approximate PHP security-support end dates (YYYY-MM). Update as upstream moves.
_PHP_EOL = {
    "7.4": "2022-11",
    "8.0": "2023-11",
    "8.1": "2025-12",
    "8.2": "2026-12",
    "8.3": "2027-12",
    "8.4": "2028-12",
}


@register
class PhpPlugin(AptServicePlugin):
    name = "php"
    packages = ["php", "php-fpm", "php-cli", "php-common"]
    service_unit = "php-fpm.service"

    def check(self) -> list[Finding]:
        findings = super().check()
        ver = self._php_minor()
        if ver and ver in _PHP_EOL:
            # Rough "is it past security support" heuristic; detail is explicit.
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title=f"PHP {ver} nearing/after end of security support",
                    detail=f"PHP {ver} security support ends ~{_PHP_EOL[ver]}. "
                    "Plan a migration to a supported branch.",
                    current_version=ver,
                )
            )
        return findings

    @staticmethod
    def _php_minor() -> str | None:
        res = run(["php", "-v"], timeout=15)
        if not res.ok:
            return None
        m = re.search(r"PHP (\d+\.\d+)", res.out)
        return m.group(1) if m else None
