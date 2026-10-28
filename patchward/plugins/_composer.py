"""Shared helper for composer-based projects.

Runs ``composer audit`` (which queries the packagist/OSV advisory database) in
a project directory and turns advisories into findings. Report-only: patchward
never runs ``composer update`` for you, because a dependency bump can break an
application in ways only its maintainer can judge.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..util import have, run

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def composer_audit(project_dir: str | Path) -> list[Finding]:
    project_dir = Path(project_dir)
    if not have("composer") or not (project_dir / "composer.lock").is_file():
        return []
    res = run(
        ["composer", "audit", "--format=json", "--no-interaction"],
        timeout=120,
    )
    # composer exits non-zero when advisories are found; parse stdout anyway.
    text = res.out.strip() or res.err.strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    findings: list[Finding] = []
    advisories = data.get("advisories", {})
    for pkg, items in advisories.items():
        for adv in items:
            sev = _SEV_MAP.get((adv.get("severity") or "").lower(), Severity.MEDIUM)
            findings.append(
                Finding(
                    service=f"composer:{project_dir.name}",
                    kind=FindingKind.VULNERABILITY,
                    severity=sev,
                    title=f"{pkg}: {adv.get('title', 'advisory')}",
                    detail=(adv.get("link") or ""),
                    cve=adv.get("cve"),
                    current_version=adv.get("affectedVersions"),
                )
            )
    return findings
