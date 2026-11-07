# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

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
from ..util import have, is_root, pkg_needs_reboot, run

# Lines from `apt-get -s upgrade` look like:
#   Inst nginx [1.24.0-1] (1.24.0-2ubuntu1 Ubuntu:24.04/noble-security [amd64])
_INST = re.compile(
    r"^Inst\s+(?P<pkg>\S+)\s+\[(?P<cur>[^\]]+)\]\s+\((?P<new>\S+)\s+(?P<origin>[^)]*)\)"
)


def _pkg_version(pkg: str) -> str | None:
    res = run(["dpkg-query", "-W", "-f=${Version}", pkg])
    return res.out.strip() or None if res.ok else None


def parse_inst(text: str) -> list[dict]:
    """Planned upgrades of *installed* packages from ``apt-get -s`` output.

    Only ``Inst`` lines with a ``[current]`` version are returned: packages
    that would be newly installed (e.g. a new ``linux-image-X.Y.Z``) have no
    current version and are represented by the metapackage that pulls them in.
    """
    out: list[dict] = []
    for line in text.splitlines():
        m = _INST.match(line.strip())
        if m:
            d = m.groupdict()
            d["security"] = "security" in d["origin"].lower()
            d["kept_back"] = False
            out.append(d)
    return out


def merge_kept_back(upgrade: list[dict], full: list[dict]) -> list[dict]:
    """Add upgrades that ``apt-get upgrade`` keeps back but a full upgrade does.

    ``apt-get upgrade`` never installs new packages, so a kernel update (the
    ``linux-generic`` / ``linux-image-generic`` metapackages pulling in a new
    ``linux-image-*``) is silently "kept back" and never shows up as ``Inst``.
    Diffing against ``apt-get -s dist-upgrade`` recovers those, flagged
    ``kept_back`` (locale-independent: no parsing of translated headers).
    Phased-update deferrals are honoured by both commands, so they stay out.
    """
    seen = {c["pkg"] for c in upgrade}
    extra = []
    for c in full:
        if c["pkg"] not in seen:
            c = dict(c, kept_back=True)
            extra.append(c)
    return upgrade + extra


def _simulate_upgrade() -> list[dict]:
    """Planned changes from a simulated upgrade, including kept-back ones."""
    # Refresh lists quietly; tolerate failure (e.g. offline / no root).
    run(["apt-get", "update", "-qq"], timeout=180)
    upgrade = parse_inst(run(["apt-get", "-s", "upgrade"], timeout=180).out)
    full = parse_inst(run(["apt-get", "-s", "dist-upgrade"], timeout=180).out)
    return merge_kept_back(upgrade, full)


# Kernel metapackages: upgrading them installs a new kernel image.
_KERNEL_META = re.compile(r"^linux-(generic|virtual|image|signed-image)(-|$)")


def change_needs_reboot(pkg: str) -> bool:
    return pkg_needs_reboot(pkg) or bool(_KERNEL_META.match(pkg))


def change_finding(service: str, change: dict) -> Finding:
    """One Finding for one planned package change (shared by apt plugins)."""
    security = change["security"]
    kept = change.get("kept_back", False)
    title = f"{change['pkg']} {change['cur']} → {change['new']}"
    detail = f"origin: {change['origin'].strip()}"
    if kept:
        title += " (kept back)"
        detail += (
            "; `apt-get upgrade` keeps this back because it needs new packages "
            "(typically a new kernel). Apply with "
            f"`sudo apt-get install {change['pkg']}` or `sudo apt full-upgrade`."
        )
    return Finding(
        service=service,
        kind=FindingKind.SECURITY_UPDATE if security else FindingKind.MINOR_UPGRADE,
        severity=Severity.HIGH if security else Severity.LOW,
        title=title,
        detail=detail,
        current_version=change["cur"],
        fixed_version=change["new"],
        # Only the kernel image (incl. its metapackages) and glibc imply a reboot.
        reboot_required=change_needs_reboot(change["pkg"]),
        ref=change["pkg"],
    )


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
            findings.append(change_finding(self.name, change))
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
                    output="requires root -- re-run with sudo",
                )
            ]
        if not have("apt-get"):
            return [ActionResult(self.name, desc, ok=False, output="apt-get missing")]
        # --only-upgrade never installs the *named* packages afresh, but still
        # pulls in new dependencies (e.g. the new kernel for a kept-back
        # linux-generic).
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
