"""Node.js: runtime EOL check + `npm audit` on configured projects.

Two layers:
  * the Node.js runtime itself (is this major line still in LTS/supported?)
  * each project's dependencies via `npm audit --json` (OSV-backed).
Report-only: patchward does not run `npm audit fix` for you.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import ServicePlugin, register
from ..util import have, run

_DEFAULT_ROOTS = ["/var/www", "/srv", str(Path.home() / "website")]

# Node major line -> end-of-life (YYYY-MM). Even majors are LTS.
_NODE_EOL = {
    "16": "2023-09",
    "18": "2025-04",
    "20": "2026-04",
    "22": "2027-04",
    "24": "2028-04",
}

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _find_node_projects(roots: list[str]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        for dirpath, dirnames, _filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if d not in {"node_modules", "vendor", ".git"}]
            p = Path(dirpath)
            if (p / "package.json").is_file():
                found.append(p)
                dirnames[:] = []
    return found


@register
class NodejsPlugin(ServicePlugin):
    name = "nodejs"
    supports_apply = False
    roots: list[str] = _DEFAULT_ROOTS

    def detect(self) -> bool:
        return have("node")

    def version(self) -> str | None:
        res = run(["node", "-v"], timeout=15)
        return res.out.strip() if res.ok else None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._runtime_check())
        for proj in _find_node_projects(self.roots):
            findings.extend(self._npm_audit(proj))
        return findings

    def _runtime_check(self) -> list[Finding]:
        v = self.version() or ""
        m = re.match(r"v?(\d+)\.", v)
        if not m:
            return []
        major = m.group(1)
        if major in _NODE_EOL:
            return [
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title=f"Node.js {v} end-of-life ~{_NODE_EOL[major]}",
                    detail="Move to a current LTS line (even-numbered major) that "
                    "still receives security updates.",
                    current_version=v,
                )
            ]
        return []

    def _npm_audit(self, proj: Path) -> list[Finding]:
        if not have("npm") or not (proj / "package-lock.json").is_file():
            return []
        res = run(["npm", "audit", "--json"], timeout=120)
        try:
            data = json.loads(res.out or res.err)
        except (json.JSONDecodeError, ValueError):
            return []
        out: list[Finding] = []
        for name, vuln in (data.get("vulnerabilities") or {}).items():
            sev = _SEV_MAP.get((vuln.get("severity") or "").lower(), Severity.MEDIUM)
            out.append(
                Finding(
                    service=f"npm:{proj.name}",
                    kind=FindingKind.VULNERABILITY,
                    severity=sev,
                    title=f"{name}: {vuln.get('severity')} severity advisory",
                    detail=f"range: {vuln.get('range', '?')} (in {proj})",
                )
            )
        return out
