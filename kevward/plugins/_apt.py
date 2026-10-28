"""Reusable base for apt-managed services.

Most Ubuntu services (nginx, php, openssh, ufw, ...) are just a set of apt
packages. This base turns "which packages" into check/apply behaviour:

* ``check`` surfaces pending security updates and (separately) minor upgrades
  for the managed packages, using ``apt-get -s`` (simulate) so it never
  changes anything.
* ``apply`` installs the selected packages, honouring dry-run.

Concrete plugins typically only declare ``name``, ``packages`` and
``service_unit``.
"""

from __future__ import annotations

import re

from ..model import ActionResult, Finding, FindingKind, Severity
from ..plugin import ServicePlugin
from ..util import have, is_root, run

# Lines from `apt-get -s upgrade` look like:
#   Inst nginx [1.24.0-1] (1.24.0-2ubuntu1 Ubuntu:24.04/noble-security [amd64])
_INST = re.compile(
    r"^Inst\s+(?P<pkg>\S+)\s+\[(?P<cur>[^\]]+)\]\s+\((?P<new>\S+)\s+(?P<origin>[^)]*)\)"
)


def _pkg_version(pkg: str) -> str | None:
    res = run(["dpkg-query", "-W", "-f=${Version}", pkg])
    return res.out.strip() or None if res.ok else None


def _simulate_upgrade() -> list[dict]:
    """Return planned package changes from a simulated full upgrade."""
    # Refresh lists quietly; tolerate failure (e.g. offline / no root).
    run(["apt-get", "update", "-qq"], timeout=180)
    res = run(["apt-get", "-s", "upgrade"], timeout=180)
    out: list[dict] = []
    for line in res.out.splitlines():
        m = _INST.match(line.strip())
        if m:
            d = m.groupdict()
            d["security"] = "security" in d["origin"].lower()
            out.append(d)
    return out


class AptServicePlugin(ServicePlugin):
    #: apt package names this plugin owns.
    packages: list[str] = []
    #: systemd unit to flag for restart (informational).
    service_unit: str | None = None

    def detect(self) -> bool:
        return any(_pkg_version(p) for p in self.packages)

    def version(self) -> str | None:
        for p in self.packages:
            v = _pkg_version(p)
            if v:
                return f"{p} {v}"
        return None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        owned = set(self.packages)
        for change in _simulate_upgrade():
            if change["pkg"] not in owned:
                continue
            security = change["security"]
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.SECURITY_UPDATE
                    if security
                    else FindingKind.MINOR_UPGRADE,
                    severity=Severity.HIGH if security else Severity.LOW,
                    title=f"{change['pkg']} {change['cur']} → {change['new']}",
                    detail=f"origin: {change['origin'].strip()}",
                    current_version=change["cur"],
                    fixed_version=change["new"],
                    # Kernel/libc class packages imply a reboot; approximate.
                    reboot_required=change["pkg"].startswith(("linux-", "libc")),
                    ref=change["pkg"],
                )
            )
        return findings

    def apply(self, findings: list[Finding], dry_run: bool) -> list[ActionResult]:
        pkgs = sorted({f.ref for f in findings if f.ref})
        if not pkgs:
            return []
        desc = "install: " + ", ".join(pkgs)
        if dry_run:
            return [ActionResult(self.name, desc, changed=False, dry_run=True)]
        if not is_root():
            return [
                ActionResult(
                    self.name, desc, changed=False, ok=False,
                    output="requires root",
                )
            ]
        if not have("apt-get"):
            return [ActionResult(self.name, desc, ok=False, output="apt-get missing")]
        env_args = ["apt-get", "install", "-y", "--only-upgrade", *pkgs]
        res = run(env_args, timeout=600)
        reboot = any(f.reboot_required for f in findings)
        return [
            ActionResult(
                self.name,
                desc,
                changed=res.ok,
                ok=res.ok,
                output=(res.out[-2000:] if res.ok else res.err[-2000:]),
                reboot_required=reboot,
            )
        ]
