# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The apt subsystem itself: the full set of pending updates host-wide.

Complements the per-service plugins by catching everything else (kernel,
libraries, base system) so nothing security-relevant is missed.
"""

from __future__ import annotations

import os

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..stale_libs import StaleUnit, StaleVM, scan, scan_vms
from ..util import (
    format_pkgs,
    have,
    is_root,
    reboot_kind,
    reboot_pending,
    reboot_pending_pkgs,
)
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
        stale = stale_code_finding(self.name, scan(), complete=is_root())
        if stale:
            findings.append(stale)
        vms = stale_vm_finding(self.name, scan_vms())
        if vms:
            findings.append(vms)
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



def _unit_label(u: StaleUnit) -> str:
    if u.unit.endswith(".service"):
        return u.unit[: -len(".service")]
    if u.unit == "unknown" and u.comms:
        return u.comms[0]  # no systemd cgroup: name the process instead
    return u.unit


def stale_code_finding(
    service: str, units: list[StaleUnit], complete: bool = True
) -> Finding | None:
    """"Processes still run replaced code": a restart is pending even when
    /run/reboot-required is not set (e.g. sshd still on the pre-update libssl).

    Medium when a service still maps an old TLS library (it keeps serving with
    it), low otherwise. ``complete`` is False as non-root (only the caller's
    own processes are visible); then nothing found is not reported at all."""
    if not units:
        return None
    labels = [_unit_label(u) for u in units]
    n = len(units)
    title = (f"{n} unit{' still runs' if n == 1 else 's still run'} replaced "
             f"code ({format_pkgs(labels)})")
    lines = []
    for u in units:
        libs = ", ".join(sorted({f.rsplit("/", 1)[-1] for f in u.files}))
        pids = ", ".join(str(p) for p in u.pids[:5])
        if len(u.pids) > 5:
            pids += f" +{len(u.pids) - 5} more"
        lines.append(f"{u.unit} [{', '.join(u.comms[:3])}; pid {pids}]: "
                     f"{libs} -> {u.hint()}")
    detail = ("These processes started before an update replaced the files "
              "below and still execute the old copies, so the fix is not live "
              "for them yet. " + "; ".join(lines) + ".")
    if not complete:
        detail += " Only this user's processes were checked; run as root to see all."
    tls = any(u.tls and u.unit.endswith(".service") for u in units)
    return Finding(
        service=service,
        kind=FindingKind.CONFIG,
        severity=Severity.MEDIUM if tls else Severity.LOW,
        title=title,
        detail=detail,
    )


def stale_vm_finding(service: str, vms: list[StaleVM]) -> Finding | None:
    """MEDIUM: qemu (or virtiofsd / swtpm) was updated but VMs still run the
    old binary until each VM is restarted (#254)."""
    if not vms:
        return None
    names = sorted({v.name for v in vms})
    hints = []
    if any(v.snap == "multipass" for v in vms):
        hints.append("multipass restart <name>")
    if any(not v.snap for v in vms):
        hints.append("virsh reboot <name> (or restart the VM)")
    if any(v.snap and v.snap != "multipass" for v in vms):
        hints.append("restart the VM")
    lines = [f"{v.name} (pid {v.pid}, {os.path.basename(v.exe)}: {v.reason})" for v in vms]
    return Finding(
        service=service,
        kind=FindingKind.CONFIG,
        severity=Severity.MEDIUM,
        title=f"qemu was updated but {len(names)} VM(s) still run the old binary "
              f"({format_pkgs(names)})",
        detail="A running VM keeps executing the qemu it started with; the update is "
               "not in effect for it until the VM is restarted. " + "; ".join(lines)
               + ". Restart them: " + ", ".join(hints) + ".",
    )
