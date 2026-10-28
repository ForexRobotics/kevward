"""WordPress: core/plugin/theme version + update inventory via wp-cli.

If wp-cli (`wp`) is available, reports available core, plugin and theme updates
(plugins/themes are the dominant WordPress attack surface). Report-only.

Configure install paths via policy override:

    [policy.overrides.wordpress]
    paths = ["/var/www/blog"]
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import ServicePlugin, register
from ..util import have, run

_DEFAULT_ROOTS = ["/var/www", "/srv"]


def _find_wp_installs(roots: list[str]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        r = Path(root)
        if not r.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if d not in {"node_modules", "vendor", ".git"}]
            if "wp-config.php" in filenames or "wp-load.php" in filenames:
                found.append(Path(dirpath))
                dirnames[:] = []
    return found


def _wp(path: Path, *args: str) -> list | dict | None:
    # --allow-root so it works under the systemd unit; wp-cli refuses root otherwise.
    res = run(["wp", *args, f"--path={path}", "--allow-root", "--format=json"], timeout=90)
    if not res.ok:
        return None
    try:
        return json.loads(res.out or "[]")
    except (json.JSONDecodeError, ValueError):
        return None


@register
class WordPressPlugin(ServicePlugin):
    name = "wordpress"
    supports_apply = False
    kev_terms = ["wordpress"]
    roots: list[str] = _DEFAULT_ROOTS

    def detect(self) -> bool:
        return have("wp") and bool(_find_wp_installs(self.roots))

    def version(self) -> str | None:
        installs = _find_wp_installs(self.roots)
        return f"{len(installs)} install(s)" if installs else None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        for site in _find_wp_installs(self.roots):
            findings.extend(self._core(site))
            findings.extend(self._components(site, "plugin"))
            findings.extend(self._components(site, "theme"))
        return findings

    def _core(self, site: Path) -> list[Finding]:
        data = _wp(site, "core", "check-update")
        out: list[Finding] = []
        for upd in data or []:
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.SECURITY_UPDATE,
                    severity=Severity.HIGH,
                    title=f"{site.name}: WordPress core {upd.get('version')} available",
                    detail=f"type: {upd.get('update_type', 'update')}",
                    fixed_version=upd.get("version"),
                )
            )
        return out

    def _components(self, site: Path, kind: str) -> list[Finding]:
        data = _wp(site, kind, "list", "--update=available")
        out: list[Finding] = []
        for item in data or []:
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.SECURITY_UPDATE,
                    severity=Severity.MEDIUM,
                    title=f"{site.name}: {kind} '{item.get('name')}' "
                    f"{item.get('version')} → {item.get('update_version')}",
                    detail=f"status: {item.get('status', '?')}",
                    current_version=item.get("version"),
                    fixed_version=item.get("update_version"),
                )
            )
        return out
